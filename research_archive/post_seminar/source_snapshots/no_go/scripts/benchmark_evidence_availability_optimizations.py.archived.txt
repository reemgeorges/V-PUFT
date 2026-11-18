"""Bounded replay benchmarks for opt-in evidence-availability optimizations.

This script consumes an existing immutable C3 shared-detection trace. It does
not run SUMO or create new mobility/attack inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from dataclasses import replace
from pathlib import Path

import pandas as pd

from replay_evidence_availability_v5 import (
    CELLS, completed_trace, decision_frame, metric_row, opportunity_metrics, sha256_file,
)
from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.trace import build_trace_bundle, read_events_jsonl


def variants(base):
    validators = ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5")
    epoch = base.distributed_extension.membership_epoch.strip()
    pbft = replace(base.pbft, validators=validators, max_byzantine=1, quorum_size=4,
                   membership_epoch=epoch)
    common_ext = replace(
        base.distributed_extension,
        coordinator_strategy="canonical_case_epoch_hash",
        coordinator_pool=validators,
        membership_epoch=epoch,
        sensing_only_rsu_ids=("rsu-6", "rsu-7", "rsu-8"),
        evidence_availability_enabled=False,
        evidence_announcement_batching=False,
        evidence_receipt_dissemination="all_to_all",
        evidence_verification_cache_enabled=False,
        coordinator_omit_opposing_evidence=False,
        coordinator_equivocate_evidence_bundle=False,
        duplicate_evidence_announcements=False,
    )
    common = replace(base, pbft=pbft, simulation=replace(base.simulation, rsu_count=8),
                     distributed_extension=common_ext)

    def config(name, *, enabled=True, batching=False, receipts="all_to_all", cache=False):
        ext = replace(
            common_ext,
            evidence_availability_enabled=enabled,
            evidence_announcement_batching=batching,
            evidence_receipt_dissemination=receipts,
            evidence_verification_cache_enabled=cache,
        )
        result = replace(common, distributed_extension=ext)
        result.validate()
        return name, result

    return (
        config("C1_deterministic_V5_baseline", enabled=False),
        config("reference_full_evidence_availability"),
        config("C_receipts_to_coordinator", receipts="coordinator_only"),
        config("D_validator_local_verification_cache", cache=True),
        config("A_full_payload_case_batches", batching=True),
        config("A_C_D_batches_coordinator_receipts_cache", batching=True,
               receipts="coordinator_only", cache=True),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--trace-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cell", default="20:2101", help="One saved density:seed cell")
    parser.add_argument("--repeats", type=int, default=3,
                        help="Repeated runs for each candidate; reference is run once")
    parser.add_argument("--variants", nargs="*", default=None,
                        help="Optional subset of variant names from the manifest")
    args = parser.parse_args()
    density_text, sep, seed_text = args.cell.partition(":")
    if not sep or (int(density_text), int(seed_text)) not in CELLS:
        raise ValueError(f"--cell must be one of the saved cells: {CELLS}")
    density, seed = int(density_text), int(seed_text)
    if args.repeats < 1:
        raise ValueError("--repeats must be at least one")
    if args.output.exists() and any(args.output.iterdir()):
        raise FileExistsError(f"Refusing to overwrite nonempty output directory: {args.output}")

    base = load_config(args.config)
    available_variants = variants(base)
    if args.variants is None:
        variant_list = available_variants
    else:
        requested = set(args.variants)
        known = {name for name, _ in available_variants}
        if not requested or not requested <= known:
            raise ValueError(f"--variants must be a nonempty subset of {sorted(known)}")
        requested.add("C1_deterministic_V5_baseline")
        variant_list = [(name, config) for name, config in available_variants if name in requested]
    trace = completed_trace(args.trace_root, density, seed)
    trace_hash = sha256_file(trace)
    events = read_events_jsonl(trace)
    bundle = build_trace_bundle(
        events, KeyRegistry(base.security.deterministic_master_seed),
        window_seconds=base.detector.case_window_seconds,
        namespace=f"urban_roundabout-vehicles-{density}",
    )
    cases = bundle.rsu_cases
    generated_messages = pd.read_csv(trace.parent / "generated_messages.csv")
    rows = []
    baseline_frame = None
    baseline_case_ids = None
    baseline_opportunities = None
    baseline_row = None
    runs_manifest = []

    for name, config in variant_list:
        repeats = 1 if name == "reference_full_evidence_availability" else args.repeats
        cpu_samples = []
        first_identity = None
        result = None
        frame = None
        for repetition in range(repeats):
            started = time.process_time()
            current = DistributedRSUExtendedVPUFT(
                config, KeyRegistry(config.security.deterministic_master_seed)
            ).run(cases, seed)
            cpu_samples.append(time.process_time() - started)
            current_frame = decision_frame(current, cases, density=density, seed=seed, variant=name)
            identity = current_frame[["case_id", "new_state", "committed", "reason"]].sort_values(
                "case_id").reset_index(drop=True)
            if first_identity is None:
                first_identity = identity
            else:
                pd.testing.assert_frame_equal(first_identity, identity, check_dtype=False)
            result, frame = current, current_frame
        assert result is not None and frame is not None
        row = metric_row(
            result, cases, frame, density=density, seed=seed, variant=name,
            cpu=statistics.median(cpu_samples), wall=float("nan"), peak=float("nan"), acquisition={},
        )
        opp = opportunity_metrics(generated_messages, trace, frame)
        opportunity_ids = opp.pop("opportunity_ids")
        row.update(opp)
        messages = result.messages
        types = [message.message_type for message in messages]
        evidence_types = {
            "RSU_EVIDENCE_EXCHANGE", "VPUFT_EVIDENCE_BUNDLE", "WITNESS_EVIDENCE_UPLINK",
            "EVIDENCE_ANNOUNCEMENT", "EVIDENCE_ANNOUNCEMENT_RECEIPT",
            "EVIDENCE_RETRIEVAL_REQUEST", "EVIDENCE_RETRIEVAL_RESPONSE",
            "EVIDENCE_ANNOUNCEMENT_BATCH", "EVIDENCE_ANNOUNCEMENT_BATCH_RECEIPT",
            "EVIDENCE_ANNOUNCEMENT_BATCH_RETRIEVAL_REQUEST",
            "EVIDENCE_ANNOUNCEMENT_BATCH_RETRIEVAL_RESPONSE",
            "EVIDENCE_ANNOUNCEMENT_BATCH_UPLINK",
        }
        row.update({
            "case_count": len(cases), "trace_sha256": trace_hash,
            "cpu_samples_seconds": json.dumps(cpu_samples),
            "cpu_mean_seconds": statistics.mean(cpu_samples),
            "cpu_stdev_seconds": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0.0,
            "cpu_min_seconds": min(cpu_samples), "cpu_max_seconds": max(cpu_samples),
            "total_transmission_attempts": len(messages),
            "messages_per_input_case": len(messages) / max(1, len(cases)),
            "evidence_protocol_messages": sum(kind in evidence_types for kind in types),
            "announcement_messages": sum(kind in {"EVIDENCE_ANNOUNCEMENT", "EVIDENCE_ANNOUNCEMENT_BATCH"}
                                          for kind in types),
            "receipt_messages": sum(kind in {"EVIDENCE_ANNOUNCEMENT_RECEIPT",
                                             "EVIDENCE_ANNOUNCEMENT_BATCH_RECEIPT"} for kind in types),
            "retrieval_messages": sum("RETRIEVAL" in kind for kind in types),
            "total_transmitted_bytes": sum(message.size_bytes for message in messages),
            "successful_finalizations": sum(outcome.committed for outcome in result.consensus),
            "rejected_or_unqualified_cases": sum(not decision.committed for decision in result.decisions),
            "batch_announcement_messages": sum(kind == "EVIDENCE_ANNOUNCEMENT_BATCH" for kind in types),
            "batch_receipt_messages": sum(kind == "EVIDENCE_ANNOUNCEMENT_BATCH_RECEIPT" for kind in types),
            "batch_availability_certificates": sum(
                int(decision.metadata.get("evidence_batch_certificate_count", 0)) for decision in result.decisions
            ),
        })
        rows.append(row)
        if name == "C1_deterministic_V5_baseline":
            baseline_row, baseline_frame, baseline_opportunities = row, first_identity, opportunity_ids
            baseline_case_ids = tuple(first_identity.case_id.astype(str))
        elif baseline_frame is not None:
            if baseline_opportunities != opportunity_ids:
                raise AssertionError(f"Attack opportunity universe changed in {name}")
            if tuple(first_identity.case_id.astype(str)) != baseline_case_ids:
                raise AssertionError(f"Case universe changed in {name}")
        runs_manifest.append({
            "variant": name, "repeats": repeats, "cpu_samples_seconds": cpu_samples,
            "case_count": len(cases), "trace_sha256": trace_hash,
            "attack_opportunities": row["attack_opportunities"],
            "opportunity_ids_match_C1": baseline_opportunities == opportunity_ids
                if baseline_opportunities is not None else None,
            "case_universe_matches_C1": baseline_case_ids is not None
                and tuple(first_identity.case_id.astype(str)) == baseline_case_ids,
        })
        print(f"{name}: CPU median={statistics.median(cpu_samples):.4f}s; "
              f"messages/case={row['messages_per_input_case']:.2f}; "
              f"Recall={row['recall']:.4f}; opportunity={row['opportunity_detection_recall_fixed_denominator']:.4f}",
              flush=True)
        args.output.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(args.output / "optimization_variants_in_progress.csv", index=False)

    table = pd.DataFrame(rows)
    table.to_csv(args.output / "optimization_variants.csv", index=False)
    if baseline_row is not None:
        b = baseline_row
        compare_rows = []
        for row in rows:
            compare_rows.append({
                "variant": row["variant"],
                "cpu_delta_percent_vs_C1": 100 * (row["cpu_time_seconds"] / b["cpu_time_seconds"] - 1)
                    if b["cpu_time_seconds"] else float("nan"),
                "messages_per_case_delta_percent_vs_C1": 100 * (
                    row["messages_per_input_case"] / b["messages_per_input_case"] - 1
                ) if b["messages_per_input_case"] else float("nan"),
                "p95_e2e_delta_percent_vs_C1": 100 * (row["p95_e2e_ms"] / b["p95_e2e_ms"] - 1)
                    if b["p95_e2e_ms"] else float("nan"),
                "recall": row["recall"], "opportunity_recall": row["opportunity_detection_recall_fixed_denominator"],
                "TP": row["TP"], "FP": row["FP"], "TN": row["TN"], "FN": row["FN"],
            })
        pd.DataFrame(compare_rows).to_csv(args.output / "optimization_vs_C1.csv", index=False)
    (args.output / "optimization_manifest.json").write_text(json.dumps({
        "config_sha256": sha256_file(args.config), "trace_path": str(trace),
        "trace_sha256": trace_hash, "density": density, "seed": seed,
        "sumo_rerun": False, "saved_trace_only": True,
        "variants": runs_manifest,
        "acceptance_gates": {"cpu_overhead_max_percent": 25,
                             "messages_per_case_overhead_max_percent": 20,
                             "p95_e2e_overhead_max_percent": 5,
                             "new_false_positives": 0},
    }, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
