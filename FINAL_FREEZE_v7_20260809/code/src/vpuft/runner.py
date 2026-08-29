from __future__ import annotations

import json
import time
import tracemalloc
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from .architectures import AhmedInspiredWitnessVPUFT, CentralizedVPUFT, DistributedRSUVPUFT
from .config import ResearchConfig
from .crypto import KeyRegistry
from .domain import ArchitectureRunResult
from .metrics import confusion_metrics, decision_metrics, decisions_frame
from .reporting import plot_architecture_summary
from .simulation import generate_scenario
from .trace import TraceBundle, build_trace_bundle, calibration_rows, read_events_jsonl


def _run_architectures(config: ResearchConfig, bundle: TraceBundle, keys: KeyRegistry) -> list[ArchitectureRunResult]:
    architectures = [
        (CentralizedVPUFT(config, keys), bundle.rsu_cases),
        (DistributedRSUVPUFT(config, keys), bundle.rsu_cases),
        (AhmedInspiredWitnessVPUFT(config, keys), bundle.witness_cases),
    ]
    results: list[ArchitectureRunResult] = []
    for architecture, cases in architectures:
        result = architecture.run(cases, bundle.seed)
        results.append(result)
    return results


def _write_campaign_outputs(config: ResearchConfig, bundles: list[TraceBundle], output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    keys = KeyRegistry(config.security.deterministic_master_seed)
    all_metrics: list[dict] = []
    all_decisions: list[pd.DataFrame] = []
    all_architecture_evidence: list[dict] = []
    all_unified_evidence: list[dict] = []
    all_messages: list[dict] = []
    all_consensus: list[dict] = []
    all_events: list[dict] = []

    for bundle in bundles:
        truth_cases = {case.case_id: case for case in [*bundle.rsu_cases, *bundle.witness_cases]}
        truth = {case_id: case.ground_truth_malicious for case_id, case in truth_cases.items()}
        opened = {case_id: case.opened_at for case_id, case in truth_cases.items()}
        inferred_attacks = {case_id: case.attack_type.value for case_id, case in truth_cases.items()}
        ground_truth_attacks: dict[str, str] = {}
        for event in bundle.events:
            ground_truth_attacks[event.case_id] = str(
                event.payload.get("ground_truth_case_attack_type", event.attack_type.value)
            )
        results: list[ArchitectureRunResult] = []
        for architecture, cases in [
            (CentralizedVPUFT(config, keys), bundle.rsu_cases),
            (DistributedRSUVPUFT(config, keys), bundle.rsu_cases),
            (AhmedInspiredWitnessVPUFT(config, keys), bundle.witness_cases),
        ]:
            tracemalloc.start()
            cpu_start = time.process_time()
            result = architecture.run(cases, bundle.seed)
            cpu_time = time.process_time() - cpu_start
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            results.append(result)
            metrics = decision_metrics(result, truth, opened)
            metrics["cpu_time_seconds"] = cpu_time
            metrics["peak_memory_kb"] = peak_bytes / 1024.0
            metrics["seed"] = bundle.seed
            all_metrics.append(metrics)
            all_architecture_evidence.extend(result.evidence_rows)
            all_messages.extend({"architecture": result.architecture, "seed": bundle.seed, **asdict(msg)} for msg in result.messages)
            all_consensus.extend({"architecture": result.architecture, "seed": bundle.seed, **asdict(outcome)} for outcome in result.consensus)
        frame = decisions_frame(results, truth, ground_truth_attacks)
        if not frame.empty:
            frame["inferred_attack_type"] = frame["case_id"].map(inferred_attacks).fillna("unknown")
        frame["seed"] = bundle.seed
        all_decisions.append(frame)
        all_unified_evidence.extend(calibration_rows(bundle.events))
        all_events.extend({
            "seed": event.seed,
            "event_id": event.event_id,
            "case_id": event.case_id,
            "source_kind": event.source_kind.value,
            "attack_type": event.attack_type.value,
            "ground_truth_attack_type": str(event.payload.get("ground_truth_case_attack_type", "unknown")),
            "direction": int(event.direction),
            "ground_truth_malicious": int(event.ground_truth_malicious),
        } for event in bundle.events)

    metrics_df = pd.DataFrame(all_metrics)
    decisions_df = pd.concat(all_decisions, ignore_index=True) if all_decisions else pd.DataFrame()
    architecture_evidence_df = pd.DataFrame(all_architecture_evidence)
    unified_evidence_df = pd.DataFrame(all_unified_evidence)
    messages_df = pd.DataFrame(all_messages)
    consensus_df = pd.DataFrame(all_consensus)
    events_df = pd.DataFrame(all_events)

    metrics_df.to_csv(output / "metrics_by_seed.csv", index=False)
    if not metrics_df.empty:
        summary = metrics_df.groupby("architecture", dropna=False).agg(
            mean_mcc=("mcc", "mean"),
            mean_recall=("malicious_revocation_recall", "mean"),
            mean_frr=("false_revocation_rate", "mean"),
            mean_latency_p95_ms=("latency_p95_ms", "mean"),
            mean_bytes_per_decision=("bytes_per_decision", "mean"),
            mean_pdr=("packet_delivery_ratio", "mean"),
            mean_consensus_success=("consensus_success_rate", "mean"),
            mean_cpu_time_seconds=("cpu_time_seconds", "mean"),
            mean_peak_memory_kb=("peak_memory_kb", "mean"),
            ledger_consistency_rate=("ledger_consistent", "mean"),
        ).reset_index()
    else:
        summary = pd.DataFrame()
    summary.to_csv(output / "architecture_summary.csv", index=False)
    if not summary.empty:
        plot_architecture_summary(output / "architecture_summary.csv", output / "architecture_summary.png")

    decisions_df.to_csv(output / "decisions.csv", index=False)
    architecture_evidence_df.to_csv(output / "architecture_evidence.csv", index=False)
    unified_evidence_df.to_csv(output / "evidence_campaign.csv", index=False)
    messages_df.to_csv(output / "network_messages.csv", index=False)
    consensus_df.to_csv(output / "consensus_outcomes.csv", index=False)
    events_df.to_csv(output / "trace_event_index.csv", index=False)

    per_attack_rows = []
    if not decisions_df.empty:
        for (architecture, attack), group in decisions_df.groupby(["architecture", "attack_type"], dropna=False):
            per_attack_rows.append({"architecture": architecture, "attack_type": attack, **confusion_metrics(group)})
    pd.DataFrame(per_attack_rows).to_csv(output / "metrics_by_attack.csv", index=False)

    # Explicitly audit attack-type inference separately from the trust decision.
    if not decisions_df.empty and {"attack_type", "inferred_attack_type", "case_id"}.issubset(decisions_df.columns):
        inference_cases = (
            decisions_df[["case_id", "seed", "attack_type", "inferred_attack_type", "ground_truth_malicious"]]
            .drop_duplicates()
            .sort_values(["seed", "case_id"])
        )
        inference_cases["attack_type_correct"] = (
            inference_cases["attack_type"].astype(str) == inference_cases["inferred_attack_type"].astype(str)
        ).astype(int)
    else:
        inference_cases = pd.DataFrame()
    inference_cases.to_csv(output / "attack_inference_cases.csv", index=False)

    article_rows = []
    if not decisions_df.empty:
        article = decisions_df[decisions_df["architecture"] == "ahmed_inspired_witness_vpuft"].copy()
        if not article.empty:
            native = article["article_native_reference_qualified"].astype(int)
            actual = article["predicted_revoked"].astype(int)
            truth_values = article["ground_truth_malicious"].astype(int)
            native_frame = pd.DataFrame({"ground_truth_malicious": truth_values, "predicted_revoked": native})
            actual_frame = pd.DataFrame({"ground_truth_malicious": truth_values, "predicted_revoked": actual})
            article_rows = [
                {"configuration": "article_native_threshold_reference", **confusion_metrics(native_frame)},
                {"configuration": "ahmed_inspired_with_vpuft", **confusion_metrics(actual_frame)},
            ]
    pd.DataFrame(article_rows).to_csv(output / "article_reference_ablation.csv", index=False)

    if not messages_df.empty:
        message_summary = messages_df.groupby(["architecture", "message_type"], as_index=False).agg(
            sent=("message_id", "count"),
            delivered=("dropped", lambda s: int((~s.astype(bool)).sum())),
            dropped=("dropped", "sum"),
            bytes_total=("size_bytes", "sum"),
            mean_retransmission=("retransmission", "mean"),
            mean_queue_delay_ms=("queue_delay_ms", "mean"),
        )
    else:
        message_summary = pd.DataFrame()
    message_summary.to_csv(output / "message_summary.csv", index=False)

    inflation_rows = []
    if not unified_evidence_df.empty:
        for (seed, case_id, source_kind), group in unified_evidence_df.groupby(["seed", "case_id", "source_kind"]):
            attestations = len(group)
            roots = group["observation_root_id"].nunique()
            inflation_rows.append({
                "seed": seed,
                "case_id": case_id,
                "source_kind": source_kind,
                "attestations": attestations,
                "independent_roots": roots,
                "correlated_reports_suppressed": max(0, attestations - roots),
                "suppression_rate": (attestations - roots) / attestations if attestations else 0.0,
            })
    pd.DataFrame(inflation_rows).to_csv(output / "evidence_correlation_metrics.csv", index=False)

    manifest = {
        "version": "1.0.0",
        "seeds": [bundle.seed for bundle in bundles],
        "architectures": sorted(metrics_df["architecture"].unique().tolist()) if not metrics_df.empty else [],
        "weights": asdict(config.weights),
        "comparison_rule": "One shared V-PUFT engine; architecture/finalization/evidence-source differ.",
        "files": [
            "metrics_by_seed.csv",
            "architecture_summary.csv",
            "metrics_by_attack.csv",
            "attack_inference_cases.csv",
            "decisions.csv",
            "evidence_campaign.csv",
            "architecture_evidence.csv",
            "network_messages.csv",
            "message_summary.csv",
            "consensus_outcomes.csv",
            "article_reference_ablation.csv",
            "evidence_correlation_metrics.csv",
            "trace_event_index.csv",
            "architecture_summary.png",
        ],
    }
    (output / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def run_campaign(config: ResearchConfig, output_dir: str | Path) -> dict:
    keys = KeyRegistry(config.security.deterministic_master_seed)
    bundles = [generate_scenario(config, keys, seed) for seed in config.simulation.seeds]
    return _write_campaign_outputs(config, bundles, Path(output_dir))


def run_trace_campaign(config: ResearchConfig, trace_path: str | Path, output_dir: str | Path) -> dict:
    events = read_events_jsonl(trace_path)
    grouped = defaultdict(list)
    for event in events:
        grouped[event.seed].append(event)
    keys = KeyRegistry(config.security.deterministic_master_seed)
    bundles = [
        build_trace_bundle(
            group,
            keys,
            window_seconds=config.detector.case_window_seconds,
        )
        for _seed, group in sorted(grouped.items())
    ]
    return _write_campaign_outputs(config, bundles, Path(output_dir))
