from __future__ import annotations

import json
import time
import tracemalloc
from dataclasses import asdict, replace
from pathlib import Path
from typing import Iterable

import pandas as pd

from .architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from .config import ResearchConfig
from .crypto import KeyRegistry
from .domain import ArchitectureRunResult, EvidenceCase
from .metrics import decision_metrics
from .robustness import inject_compromised_rsu_evidence
from .sumo.density import build_density_scenario
from .sumo.runner import run_sumo_trace
from .trace import build_trace_bundle, read_events_jsonl
from .trust_cache import simulate_topology_v2v_trust_cache


VARIANT_DISTRIBUTED_HONEST = "distributed_density_honest"


def _label_result(result: ArchitectureRunResult, label: str) -> ArchitectureRunResult:
    return replace(
        result,
        architecture=label,
        decisions=[replace(decision, architecture=label) for decision in result.decisions],
    )


def _run_measured(architecture, cases: list[EvidenceCase], seed: int, label: str):
    tracemalloc.start()
    cpu_start = time.process_time()
    result = architecture.run(cases, seed)
    cpu_seconds = time.process_time() - cpu_start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return _label_result(result, label), cpu_seconds, peak_bytes / 1024.0


def _completed_trace(trace_dir: Path, seed: int, vehicle_count: int) -> bool:
    required = (
        "run_summary.json",
        "scenario_manifest.json",
        "shared_detection_trace.jsonl",
        "mobility_trace.csv",
    )
    if any(not (trace_dir / name).exists() for name in required):
        return False
    try:
        summary = json.loads((trace_dir / "run_summary.json").read_text(encoding="utf-8"))
        manifest = json.loads((trace_dir / "scenario_manifest.json").read_text(encoding="utf-8"))
        return (
            bool(summary.get("completed"))
            and int(summary.get("seed")) == seed
            and int(manifest["counts"]["unique_vehicles_observed"]) == vehicle_count
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False


def _message_rows(result: ArchitectureRunResult, context: dict) -> list[dict]:
    if not result.messages:
        return []
    frame = pd.DataFrame(asdict(message) for message in result.messages)
    grouped = frame.groupby("message_type", as_index=False).agg(
        messages=("message_id", "count"),
        delivered=("dropped", lambda values: int((~values.astype(bool)).sum())),
        dropped=("dropped", "sum"),
        bytes_total=("size_bytes", "sum"),
        retransmissions=("retransmission", lambda values: int((values.astype(int) > 0).sum())),
        mean_queue_delay_ms=("queue_delay_ms", "mean"),
    )
    return [{**context, **row} for row in grouped.to_dict("records")]


def _decision_rows(result: ArchitectureRunResult, cases: list[EvidenceCase], context: dict) -> list[dict]:
    by_case = {case.case_id: case for case in cases}
    rows = []
    for decision in result.decisions:
        case = by_case[decision.case_id]
        rows.append(
            {
                **context,
                "case_id": decision.case_id,
                "vehicle_id": decision.vehicle_id,
                "attack_type": case.attack_type.value,
                "ground_truth_malicious": int(case.ground_truth_malicious),
                "predicted_revoked": int(
                    decision.committed and decision.new_state.value == "revoked"
                ),
                "committed": int(decision.committed),
                "new_state": decision.new_state.value,
                "reason": decision.reason,
                "detected_at": decision.detected_at,
                "qualified_at": decision.qualified_at,
                "finalized_at": decision.finalized_at,
                "ledger_available_at": decision.ledger_available_at,
                "decision_margin": decision.decision_margin,
                "metadata_json": json.dumps(dict(decision.metadata), sort_keys=True),
            }
        )
    return rows


def _consensus_rows(result: ArchitectureRunResult, context: dict) -> list[dict]:
    return [{**context, **asdict(outcome)} for outcome in result.consensus]


def _write_cell_frames(cell_dir: Path, frames: dict[str, pd.DataFrame]) -> None:
    cell_dir.mkdir(parents=True, exist_ok=True)
    for filename, frame in frames.items():
        frame.to_csv(cell_dir / filename, index=False)
    (cell_dir / "cell_complete.json").write_text(
        json.dumps({"completed": True, "files": sorted(frames)}, indent=2),
        encoding="utf-8",
    )


def _read_completed_cell(cell_dir: Path) -> dict[str, pd.DataFrame] | None:
    marker = cell_dir / "cell_complete.json"
    if not marker.exists():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        frames = {}
        for filename in data["files"]:
            path = cell_dir / filename
            if not path.exists():
                return None
            try:
                frames[filename] = pd.read_csv(path)
            except pd.errors.EmptyDataError:
                frames[filename] = pd.DataFrame()
        return frames
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def _append_frame(target: list[pd.DataFrame], frame: pd.DataFrame | None) -> None:
    if frame is not None and not frame.empty:
        target.append(frame)


def run_density_campaign(
    config: ResearchConfig,
    *,
    scenario_directories: Iterable[str | Path],
    output_directory: str | Path,
    seeds: Iterable[int] | None = None,
    resume: bool = False,
) -> dict:
    """Run a paired topology x density architecture campaign.

    A SUMO trace is generated once for each topology, vehicle count and seed.
    That exact trace is then replayed through the distributed architecture and
    every Centralized Remote backhaul level. Optional distributed robustness
    variants use the same evidence cases as well.
    """

    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)
    seed_values = tuple(dict.fromkeys(int(seed) for seed in (seeds or config.simulation.seeds)))
    if not seed_values:
        raise ValueError("At least one density-campaign seed is required")
    scenarios = [Path(path).resolve() for path in scenario_directories]
    if not scenarios:
        raise ValueError("At least one topology is required")

    keys = KeyRegistry(config.security.deterministic_master_seed)
    all_metrics: list[pd.DataFrame] = []
    all_decisions: list[pd.DataFrame] = []
    all_messages: list[pd.DataFrame] = []
    all_consensus: list[pd.DataFrame] = []
    all_cache: list[pd.DataFrame] = []
    trace_rows: list[dict] = []
    resumed_cells = executed_cells = 0

    for scenario in scenarios:
        topology = scenario.name
        for vehicle_count in config.density_campaign.vehicle_counts:
            generated_scenario = output / "generated_scenarios" / topology / f"vehicles_{vehicle_count}"
            density_manifest = build_density_scenario(
                scenario,
                generated_scenario,
                vehicle_count=vehicle_count,
                attack_vehicle_ratio=config.density_campaign.attack_vehicle_ratio,
                departure_window_seconds=config.density_campaign.departure_window_seconds,
                end_time_seconds=config.sumo.end_time_seconds,
            )
            rsus = json.loads((generated_scenario / "rsus.json").read_text(encoding="utf-8"))

            for seed in seed_values:
                print(
                    f"[density] topology={topology} vehicles={vehicle_count} seed={seed}",
                    flush=True,
                )
                trace_dir = output / "traces" / topology / f"vehicles_{vehicle_count}" / f"seed_{seed}"
                if resume and _completed_trace(trace_dir, seed, vehicle_count):
                    print("[resume] shared SUMO trace", flush=True)
                else:
                    run_sumo_trace(
                        config,
                        scenario_directory=generated_scenario,
                        output_directory=trace_dir,
                        seed=seed,
                    )
                trace_manifest = json.loads(
                    (trace_dir / "scenario_manifest.json").read_text(encoding="utf-8")
                )
                observed_count = int(trace_manifest["counts"]["unique_vehicles_observed"])
                if observed_count != vehicle_count:
                    raise RuntimeError(
                        f"Invalid density trace for {topology}/{vehicle_count}/{seed}: "
                        f"observed {observed_count} unique vehicles"
                    )
                trace_rows.append(
                    {
                        "topology": topology,
                        "vehicle_count": vehicle_count,
                        "seed": seed,
                        "observed_vehicle_count": observed_count,
                        "peak_concurrent_vehicles": trace_manifest["counts"]["peak_concurrent_vehicles"],
                        "cases": trace_manifest["counts"]["cases"],
                        "v2x_messages": trace_manifest["counts"]["v2x_messages"],
                        "detection_events": trace_manifest["counts"]["detection_events"],
                        "attack_vehicle_count": density_manifest.attack_vehicle_count,
                        "attack_vehicle_ratio": density_manifest.attack_vehicle_ratio,
                        "trace_path": str(trace_dir / "shared_detection_trace.jsonl"),
                    }
                )

                cell_dir = output / "cells" / topology / f"vehicles_{vehicle_count}" / f"seed_{seed}"
                cached_frames = _read_completed_cell(cell_dir) if resume else None
                if cached_frames is not None:
                    resumed_cells += 1
                    _append_frame(all_metrics, cached_frames.get("metrics.csv"))
                    _append_frame(all_decisions, cached_frames.get("decisions.csv"))
                    _append_frame(all_messages, cached_frames.get("message_summary.csv"))
                    _append_frame(all_consensus, cached_frames.get("consensus_outcomes.csv"))
                    _append_frame(all_cache, cached_frames.get("topology_v2v_cache.csv"))
                    print("[resume] architecture/cache cell", flush=True)
                    continue

                events = read_events_jsonl(trace_dir / "shared_detection_trace.jsonl")
                bundle = build_trace_bundle(
                    events,
                    keys,
                    window_seconds=config.detector.case_window_seconds,
                    namespace=f"{topology}-vehicles-{vehicle_count}",
                )
                cases = bundle.rsu_cases
                truth = {case.case_id: case.ground_truth_malicious for case in cases}
                opened = {case.case_id: case.opened_at for case in cases}
                base_context = {
                    "topology": topology,
                    "vehicle_count": vehicle_count,
                    "seed": seed,
                }
                metric_rows: list[dict] = []
                decision_rows: list[dict] = []
                message_rows: list[dict] = []
                consensus_rows: list[dict] = []
                cache_rows: list[dict] = []

                distributed_config = replace(
                    config,
                    network=replace(config.network, central_backhaul_extra_latency_ms=0.0),
                )
                distributed_result, cpu_seconds, peak_kb = _run_measured(
                    DistributedRSUExtendedVPUFT(distributed_config, keys),
                    cases,
                    seed,
                    VARIANT_DISTRIBUTED_HONEST,
                )

                runs: list[tuple[ArchitectureRunResult, float, float, float | None, list[EvidenceCase]]] = [
                    (distributed_result, cpu_seconds, peak_kb, None, cases)
                ]
                for delay in config.density_campaign.backhaul_extra_latency_ms:
                    remote_config = replace(
                        config,
                        network=replace(
                            config.network,
                            central_backhaul_extra_latency_ms=float(delay),
                        ),
                    )
                    suffix = f"{float(delay):g}ms"
                    if float(delay) == 0.0:
                        suffix += "_control"
                    result, cpu, peak = _run_measured(
                        CentralizedVPUFT(remote_config, keys),
                        cases,
                        seed,
                        f"centralized_remote_{suffix}",
                    )
                    runs.append((result, cpu, peak, float(delay), cases))

                if config.density_campaign.include_robustness_variants:
                    accusation_cases, _ = inject_compromised_rsu_evidence(
                        cases,
                        keys=keys,
                        compromised_rsu=config.robustness.compromised_evidence_rsu,
                        correlated_copies=config.robustness.correlated_forgery_copies,
                        mode="false_accusation",
                    )
                    concealment_cases, _ = inject_compromised_rsu_evidence(
                        cases,
                        keys=keys,
                        compromised_rsu=config.robustness.compromised_evidence_rsu,
                        correlated_copies=config.robustness.correlated_forgery_copies,
                        mode="concealment",
                    )
                    malicious_pbft = replace(
                        config.pbft,
                        validator_behaviors={
                            **config.pbft.validator_behaviors,
                            config.robustness.malicious_validator:
                                config.robustness.malicious_validator_behavior,
                        },
                    )
                    malicious_config = replace(distributed_config, pbft=malicious_pbft)
                    guard_config = replace(
                        distributed_config,
                        distributed_extension=replace(
                            config.distributed_extension,
                            leave_one_source_out_guard=True,
                            evidence_source_fault_budget=1,
                            guard_on_directional_conflict_only=False,
                        ),
                    )
                    robustness_specs = (
                        (
                            "distributed_density_false_accusation_rsu",
                            distributed_config,
                            accusation_cases,
                        ),
                        (
                            "distributed_density_concealment_rsu",
                            distributed_config,
                            concealment_cases,
                        ),
                        (
                            "distributed_density_malicious_validator",
                            malicious_config,
                            cases,
                        ),
                        (
                            "distributed_density_guard_honest",
                            guard_config,
                            cases,
                        ),
                        (
                            "distributed_density_guard_false_accusation_rsu",
                            guard_config,
                            accusation_cases,
                        ),
                    )
                    for label, variant_config, variant_cases in robustness_specs:
                        result, cpu, peak = _run_measured(
                            DistributedRSUExtendedVPUFT(variant_config, keys),
                            variant_cases,
                            seed,
                            label,
                        )
                        runs.append((result, cpu, peak, None, variant_cases))

                for result, cpu, peak, delay, result_cases in runs:
                    metrics = decision_metrics(result, truth, opened)
                    metrics.update(
                        {
                            **base_context,
                            "backhaul_extra_latency_ms": delay,
                            "cpu_time_seconds": cpu,
                            "peak_memory_kb": peak,
                            "fault_activated_count": sum(
                                outcome.fault_activated for outcome in result.consensus
                            ),
                            "invalid_proposal_attempt_count": sum(
                                outcome.invalid_proposal_attempted for outcome in result.consensus
                            ),
                        }
                    )
                    metric_rows.append(metrics)
                    context = {
                        **base_context,
                        "architecture": result.architecture,
                        "backhaul_extra_latency_ms": delay,
                    }
                    decision_rows.extend(_decision_rows(result, result_cases, context))
                    message_rows.extend(_message_rows(result, context))
                    consensus_rows.extend(_consensus_rows(result, context))

                if config.density_campaign.include_topology_cache:
                    mobility_rows = pd.read_csv(trace_dir / "mobility_trace.csv").to_dict("records")
                    for ttl in config.trust_cache.ttl_seconds:
                        cache_rows.append(
                            simulate_topology_v2v_trust_cache(
                                distributed_config,
                                seed=seed,
                                topology=topology,
                                requested_vehicle_count=vehicle_count,
                                ttl_seconds=float(ttl),
                                mobility_rows=mobility_rows,
                                decisions=distributed_result.decisions,
                                rsus=rsus,
                            )
                        )

                frames = {
                    "metrics.csv": pd.DataFrame(metric_rows),
                    "decisions.csv": pd.DataFrame(decision_rows),
                    "message_summary.csv": pd.DataFrame(message_rows),
                    "consensus_outcomes.csv": pd.DataFrame(consensus_rows),
                    "topology_v2v_cache.csv": pd.DataFrame(cache_rows),
                }
                _write_cell_frames(cell_dir, frames)
                executed_cells += 1
                _append_frame(all_metrics, frames["metrics.csv"])
                _append_frame(all_decisions, frames["decisions.csv"])
                _append_frame(all_messages, frames["message_summary.csv"])
                _append_frame(all_consensus, frames["consensus_outcomes.csv"])
                _append_frame(all_cache, frames["topology_v2v_cache.csv"])

    combined = output / "combined"
    combined.mkdir(parents=True, exist_ok=True)
    metrics_frame = pd.concat(all_metrics, ignore_index=True) if all_metrics else pd.DataFrame()
    decisions_frame = pd.concat(all_decisions, ignore_index=True) if all_decisions else pd.DataFrame()
    messages_frame = pd.concat(all_messages, ignore_index=True) if all_messages else pd.DataFrame()
    consensus_frame = pd.concat(all_consensus, ignore_index=True) if all_consensus else pd.DataFrame()
    cache_frame = pd.concat(all_cache, ignore_index=True) if all_cache else pd.DataFrame()
    trace_frame = pd.DataFrame(trace_rows)
    metrics_frame.to_csv(combined / "density_metrics_by_seed.csv", index=False)
    decisions_frame.to_csv(combined / "density_decisions.csv", index=False)
    messages_frame.to_csv(combined / "density_message_type_summary.csv", index=False)
    consensus_frame.to_csv(combined / "density_consensus_outcomes.csv", index=False)
    cache_frame.to_csv(combined / "density_topology_v2v_cache.csv", index=False)
    trace_frame.to_csv(combined / "density_trace_audit.csv", index=False)

    manifest = {
        "campaign": "controlled_topology_vehicle_density_extension",
        "frozen_v7_modified": False,
        "shared_trace_pairing": True,
        "topologies": [scenario.name for scenario in scenarios],
        "vehicle_counts": list(config.density_campaign.vehicle_counts),
        "seeds": list(seed_values),
        "backhaul_extra_latency_ms": list(
            config.density_campaign.backhaul_extra_latency_ms
        ),
        "weights": asdict(config.weights),
        "attack_vehicle_ratio": config.density_campaign.attack_vehicle_ratio,
        "include_robustness_variants": config.density_campaign.include_robustness_variants,
        "include_topology_cache": config.density_campaign.include_topology_cache,
        "expected_shared_traces": len(scenarios)
        * len(config.density_campaign.vehicle_counts)
        * len(seed_values),
        "architecture_evaluations_per_trace": (
            1
            + len(config.density_campaign.backhaul_extra_latency_ms)
            + (5 if config.density_campaign.include_robustness_variants else 0)
        ),
        "resume": {
            "enabled": resume,
            "resumed_cells": resumed_cells,
            "executed_cells": executed_cells,
        },
        "claim_boundary": (
            "Vehicle density is a controlled SUMO demand factor. Timing, loss, cache and "
            "resource measurements remain simulation/model outputs, not field measurements."
        ),
    }
    (combined / "density_campaign_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
