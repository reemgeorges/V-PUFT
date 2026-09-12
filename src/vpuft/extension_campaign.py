from __future__ import annotations

import json
import time
import tracemalloc
from collections import defaultdict
from dataclasses import asdict, replace
from pathlib import Path

import pandas as pd

from .architectures import DistributedRSUExtendedVPUFT
from .config import ResearchConfig
from .crypto import KeyRegistry
from .domain import ArchitectureRunResult
from .metrics import decision_metrics
from .robustness import inject_compromised_rsu_evidence
from .simulation import generate_scenario
from .trust_cache import simulate_v2v_trust_cache
from .trace import build_trace_bundle, read_events_jsonl


def _label_result(result: ArchitectureRunResult, label: str) -> ArchitectureRunResult:
    return replace(
        result,
        architecture=label,
        decisions=[replace(decision, architecture=label) for decision in result.decisions],
    )


def _run_measured(architecture, cases, seed: int, label: str) -> tuple[ArchitectureRunResult, float, float]:
    tracemalloc.start()
    cpu_start = time.process_time()
    result = architecture.run(cases, seed)
    cpu_seconds = time.process_time() - cpu_start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return _label_result(result, label), cpu_seconds, peak_bytes / 1024.0


def run_extension_campaign(
    config: ResearchConfig,
    output_dir: str | Path,
    trace_paths: list[str | Path] | None = None,
) -> dict:
    """Run post-freeze experiments without re-running Centralized Near-Edge."""

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    keys = KeyRegistry(config.security.deterministic_master_seed)
    metric_rows: list[dict] = []
    decision_rows: list[dict] = []
    message_rows: list[dict] = []
    consensus_rows: list[dict] = []
    evidence_attack_rows: list[dict] = []

    bundle_specs = []
    if trace_paths:
        for trace_path in trace_paths:
            path = Path(trace_path)
            topology = path.parent.name
            grouped = defaultdict(list)
            for event in read_events_jsonl(path):
                grouped[event.seed].append(event)
            bundle_specs.extend(
                (
                    topology,
                    build_trace_bundle(
                        events,
                        keys,
                        window_seconds=config.detector.case_window_seconds,
                        namespace=topology,
                    ),
                )
                for _, events in sorted(grouped.items())
            )
    else:
        bundle_specs = [
            ("synthetic", generate_scenario(config, keys, seed))
            for seed in config.simulation.seeds
        ]

    for topology, bundle in bundle_specs:
        seed = bundle.seed
        truth = {case.case_id: case.ground_truth_malicious for case in bundle.rsu_cases}
        opened = {case.case_id: case.opened_at for case in bundle.rsu_cases}

        accusation_cases, accusation_audit = inject_compromised_rsu_evidence(
            bundle.rsu_cases,
            keys=keys,
            compromised_rsu=config.robustness.compromised_evidence_rsu,
            correlated_copies=config.robustness.correlated_forgery_copies,
            mode="false_accusation",
        )
        concealment_cases, concealment_audit = inject_compromised_rsu_evidence(
            bundle.rsu_cases,
            keys=keys,
            compromised_rsu=config.robustness.compromised_evidence_rsu,
            correlated_copies=config.robustness.correlated_forgery_copies,
            mode="concealment",
        )
        evidence_attack_rows.extend({"topology": topology, "seed": seed, **row} for row in [*accusation_audit, *concealment_audit])

        malicious_pbft = replace(
            config.pbft,
            validator_behaviors={
                **config.pbft.validator_behaviors,
                config.robustness.malicious_validator: config.robustness.malicious_validator_behavior,
            },
        )
        validator_attack_config = replace(config, pbft=malicious_pbft)
        guard_config = replace(
            config,
            distributed_extension=replace(
                config.distributed_extension,
                leave_one_source_out_guard=True,
                evidence_source_fault_budget=1,
                guard_on_directional_conflict_only=False,
            ),
        )

        variants = [
            (
                "distributed_extension_honest",
                DistributedRSUExtendedVPUFT(config, keys),
                bundle.rsu_cases,
            ),
            (
                "distributed_extension_false_accusation_rsu",
                DistributedRSUExtendedVPUFT(config, keys),
                accusation_cases,
            ),
            (
                "distributed_extension_concealment_rsu",
                DistributedRSUExtendedVPUFT(config, keys),
                concealment_cases,
            ),
            (
                "distributed_extension_malicious_validator",
                DistributedRSUExtendedVPUFT(validator_attack_config, keys),
                bundle.rsu_cases,
            ),
            (
                "distributed_extension_guard_honest",
                DistributedRSUExtendedVPUFT(guard_config, keys),
                bundle.rsu_cases,
            ),
            (
                "distributed_extension_guard_false_accusation_rsu",
                DistributedRSUExtendedVPUFT(guard_config, keys),
                accusation_cases,
            ),
        ]

        for label, architecture, cases in variants:
            result, cpu_seconds, peak_kb = _run_measured(architecture, cases, seed, label)
            metrics = decision_metrics(result, truth, opened)
            metrics.update({
                "seed": seed,
                "topology": topology,
                "cpu_time_seconds": cpu_seconds,
                "peak_memory_kb": peak_kb,
                "fault_activated_count": sum(outcome.fault_activated for outcome in result.consensus),
                "semantic_invalid_proposals": sum(outcome.invalid_proposal_attempted for outcome in result.consensus),
                "validator_recheck_failures": sum(outcome.validator_recheck_failures for outcome in result.consensus),
                "evidence_guard_checks": int(result.extension_metrics.get("evidence_guard_checks", 0)),
                "evidence_guard_rejections": int(result.extension_metrics.get("evidence_guard_rejections", 0)),
            })
            metric_rows.append(metrics)
            for decision in result.decisions:
                decision_rows.append({
                    "seed": seed,
                    "topology": topology,
                    "architecture": label,
                    "case_id": decision.case_id,
                    "vehicle_id": decision.vehicle_id,
                    "ground_truth_malicious": int(truth[decision.case_id]),
                    "predicted_revoked": int(decision.committed and decision.new_state.value == "revoked"),
                    "new_state": decision.new_state.value,
                    "committed": int(decision.committed),
                    "reason": decision.reason,
                    **dict(decision.metadata),
                })
            message_rows.extend({"topology": topology, "seed": seed, "architecture": label, **asdict(message)} for message in result.messages)
            consensus_rows.extend({"topology": topology, "seed": seed, "architecture": label, **asdict(outcome)} for outcome in result.consensus)

    metrics = pd.DataFrame(metric_rows)
    decisions = pd.DataFrame(decision_rows)
    messages = pd.DataFrame(message_rows)
    consensus = pd.DataFrame(consensus_rows)
    attack_audit = pd.DataFrame(evidence_attack_rows)
    metrics.to_csv(output / "extension_metrics_by_seed.csv", index=False)
    decisions.to_csv(output / "extension_decisions.csv", index=False)
    messages.to_csv(output / "extension_network_messages.csv", index=False)
    consensus.to_csv(output / "extension_consensus_outcomes.csv", index=False)
    attack_audit.to_csv(output / "compromised_evidence_injection_audit.csv", index=False)

    if not decisions.empty:
        pivot = decisions.pivot_table(
            index=["topology", "seed", "case_id", "ground_truth_malicious"],
            columns="architecture",
            values="predicted_revoked",
            aggfunc="first",
        ).reset_index()
        honest = "distributed_extension_honest"
        for candidate in [
            "distributed_extension_false_accusation_rsu",
            "distributed_extension_concealment_rsu",
            "distributed_extension_malicious_validator",
            "distributed_extension_guard_honest",
            "distributed_extension_guard_false_accusation_rsu",
        ]:
            if honest in pivot and candidate in pivot:
                pivot[f"classification_changed__{candidate}"] = (pivot[honest] != pivot[candidate]).astype(int)
        pivot.to_csv(output / "extension_case_agreement.csv", index=False)

    v2v_rows = []
    extension_seeds = sorted({bundle.seed for _, bundle in bundle_specs})
    for seed in extension_seeds:
        for vehicle_count in config.trust_cache.vehicle_counts:
            for ttl_seconds in config.trust_cache.ttl_seconds:
                v2v_rows.append(simulate_v2v_trust_cache(
                    config,
                    seed=seed,
                    vehicle_count=vehicle_count,
                    ttl_seconds=ttl_seconds,
                ))
    pd.DataFrame(v2v_rows).to_csv(output / "v2v_trust_cache_sensitivity.csv", index=False)

    summary = metrics.groupby("architecture", as_index=False).mean(numeric_only=True) if not metrics.empty else pd.DataFrame()
    summary.to_csv(output / "extension_summary.csv", index=False)
    topology_summary = (
        metrics.groupby(["topology", "architecture"], as_index=False).mean(numeric_only=True)
        if not metrics.empty else pd.DataFrame()
    )
    topology_summary.to_csv(output / "extension_summary_by_topology.csv", index=False)
    manifest = {
        "campaign": "post_freeze_extension",
        "centralized_near_edge_rerun": False,
        "centralized_near_edge_role": "frozen_v7_reference_and_0ms_backhaul_control_only",
        "seeds": extension_seeds,
        "topologies": sorted({topology for topology, _ in bundle_specs}),
        "trace_replay": bool(trace_paths),
        "weights": asdict(config.weights),
        "variants": sorted(metrics["architecture"].unique().tolist()) if not metrics.empty else [],
        "v2v_ttl_seconds": list(config.trust_cache.ttl_seconds),
        "v2v_vehicle_counts": list(config.trust_cache.vehicle_counts),
        "files": [
            "extension_metrics_by_seed.csv",
            "extension_summary.csv",
            "extension_summary_by_topology.csv",
            "extension_decisions.csv",
            "extension_case_agreement.csv",
            "extension_network_messages.csv",
            "extension_consensus_outcomes.csv",
            "compromised_evidence_injection_audit.csv",
            "v2v_trust_cache_sensitivity.csv",
        ],
        "claim_boundary": (
            "Results apply only to the modeled evidence-forgery, validator-fault, and light-cache stimuli; "
            "they do not prove production PBFT Byzantine safety or field-radio performance."
        ),
    }
    (output / "extension_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
