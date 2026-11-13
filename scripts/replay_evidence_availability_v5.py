from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.opportunity_evaluation import opportunity_frame
from vpuft.trace import build_trace_bundle, read_events_jsonl
from run_phase2_ablation import decision_frame, metric_row


CELLS = ((20, 2101), (20, 2102), (60, 2101), (60, 2102), (100, 2101), (100, 2102))
PBFT_TYPES = {"PRE_PREPARE", "PREPARE", "COMMIT", "STATE_RECOVERY"}
EVIDENCE_TYPES = {
    "RSU_EVIDENCE_EXCHANGE", "VPUFT_EVIDENCE_BUNDLE", "WITNESS_EVIDENCE_UPLINK",
    "EVIDENCE_ANNOUNCEMENT", "EVIDENCE_ANNOUNCEMENT_RECEIPT",
    "EVIDENCE_RETRIEVAL_REQUEST", "EVIDENCE_RETRIEVAL_RESPONSE",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def completed_trace(root: Path, density: int, seed: int) -> Path:
    parent = root / "pilot" / "C3" / f"vehicles_{density}"
    primary = parent / f"seed_{seed}"
    if (primary / "run_summary.json").is_file():
        summary = json.loads((primary / "run_summary.json").read_text(encoding="utf-8"))
        if summary.get("completed") is True:
            return primary / "shared_detection_trace.jsonl"
    retries = []
    for candidate in sorted(parent.glob(f"seed_{seed}_retry*")):
        marker = candidate / "run_summary.json"
        if marker.is_file() and json.loads(marker.read_text(encoding="utf-8")).get("completed") is True:
            retries.append(candidate / "shared_detection_trace.jsonl")
    if len(retries) != 1:
        raise FileNotFoundError(f"expected one completed trace for C3/{density}/{seed}, got {retries}")
    return retries[0]


def paired_configs(base):
    validators = ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5")
    epoch = base.distributed_extension.membership_epoch.strip()
    pbft = replace(base.pbft, validators=validators, max_byzantine=1, quorum_size=4, membership_epoch=epoch)
    ext = replace(
        base.distributed_extension,
        coordinator_strategy="canonical_case_epoch_hash",
        coordinator_pool=validators,
        membership_epoch=epoch,
        sensing_only_rsu_ids=("rsu-6", "rsu-7", "rsu-8"),
        evidence_availability_enabled=False,
        coordinator_omit_opposing_evidence=False,
        coordinator_equivocate_evidence_bundle=False,
        duplicate_evidence_announcements=False,
    )
    common = replace(base, pbft=pbft, simulation=replace(base.simulation, rsu_count=8), distributed_extension=ext)
    candidate = replace(common, distributed_extension=replace(ext, evidence_availability_enabled=True))
    if common.pbft.membership_epoch != candidate.pbft.membership_epoch:
        raise AssertionError("Paired evidence availability variants must share the validated V5 membership epoch")
    common.validate()
    candidate.validate()
    return (("V5_deterministic_baseline", common), ("V5_evidence_availability", candidate))


def opportunity_metrics(messages: pd.DataFrame, trace: Path, decisions: pd.DataFrame) -> dict[str, float | int]:
    observed_ids: set[str] = set()
    with trace.open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("source_kind") == "rsu":
                observed_ids.add(str(event["message_id"]))
    opportunities = opportunity_frame(messages, decisions, observed_ids, window_seconds=15.0)
    total = len(opportunities)
    detected = int(opportunities.detected_opportunity.sum())
    terminal = int(opportunities.terminal_after_revocation.sum())
    return {
        "attack_opportunities": total,
        "observed_attack_opportunities": int(opportunities.observed_opportunity.sum()),
        "unobserved_attack_opportunities": int((~opportunities.observed_opportunity).sum()),
        "successfully_detected_opportunities": detected,
        "opportunity_detection_recall_fixed_denominator": detected / total if total else 0.0,
        "protected_opportunities_including_terminal": detected + terminal,
        "protected_opportunity_fraction_fixed_denominator": (detected + terminal) / total if total else 0.0,
        "terminal_opportunities": terminal,
        "opportunity_ids": tuple(sorted(opportunities.opportunity_id.astype(str))),
    }


def run_repeated(config, cases, seed: int, density: int, variant: str, repeats: int):
    cpu_samples: list[float] = []
    result = None
    first_decisions = None
    for _ in range(repeats):
        started = time.process_time()
        current = DistributedRSUExtendedVPUFT(
            config, KeyRegistry(config.security.deterministic_master_seed)
        ).run(cases, seed)
        cpu_samples.append(time.process_time() - started)
        frame = decision_frame(current, cases, density=density, seed=seed, variant=variant)
        identity = frame[["case_id", "new_state", "committed", "reason"]].sort_values("case_id").reset_index(drop=True)
        if first_decisions is None:
            first_decisions = identity
        else:
            pd.testing.assert_frame_equal(first_decisions, identity, check_dtype=False)
        result = current
    assert result is not None and first_decisions is not None
    return result, first_decisions, cpu_samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--trace-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--cells", nargs="*", default=None, help="Optional density:seed cells; default is all six saved pilot cells")
    args = parser.parse_args()
    if args.repeats < 1:
        raise ValueError("repeats must be at least one")
    if args.output.exists() and any(args.output.iterdir()):
        raise FileExistsError(f"Refusing to overwrite nonempty output directory: {args.output}")

    selected_cells = CELLS
    if args.cells is not None:
        parsed = []
        for value in args.cells:
            density_text, separator, seed_text = value.partition(":")
            if not separator:
                raise ValueError(f"Invalid cell {value!r}; expected density:seed")
            cell = (int(density_text), int(seed_text))
            if cell not in CELLS:
                raise ValueError(f"Cell {cell} is not in the saved paired pilot set {CELLS}")
            parsed.append(cell)
        if not parsed or len(set(parsed)) != len(parsed):
            raise ValueError("--cells must contain unique saved pilot cells")
        selected_cells = tuple(parsed)

    base = load_config(args.config)
    variants = paired_configs(base)
    metric_rows: list[dict] = []
    paired_rows: list[dict] = []
    manifests: list[dict] = []
    for density, seed in selected_cells:
        trace = completed_trace(args.trace_root, density, seed)
        trace_hash = sha256_file(trace)
        events = read_events_jsonl(trace)
        bundle = build_trace_bundle(
            events,
            KeyRegistry(base.security.deterministic_master_seed),
            window_seconds=base.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        cases = bundle.rsu_cases
        if len({case.case_id for case in cases}) != len(cases):
            raise AssertionError(f"duplicate case IDs at density={density}, seed={seed}")
        generated_path = trace.parent / "generated_messages.csv"
        generated_messages = pd.read_csv(generated_path)
        paired_cell: list[tuple[str, dict, pd.DataFrame, dict]] = []
        for name, config in variants:
            result, decision_identity, cpu_samples = run_repeated(config, cases, seed, density, name, args.repeats)
            frame = decision_frame(result, cases, density=density, seed=seed, variant=name)
            row = metric_row(
                result, cases, frame, density=density, seed=seed, variant=name,
                cpu=statistics.median(cpu_samples), wall=float("nan"), peak=float("nan"), acquisition={},
            )
            opp = opportunity_metrics(generated_messages, trace, frame)
            opportunity_ids = opp.pop("opportunity_ids")
            row.update(opp)
            message_types = [message.message_type for message in result.messages]
            row.update({
                "case_count": len(cases),
                "trace_sha256": trace_hash,
                "trace_path": str(trace),
                "cpu_mean_seconds": statistics.mean(cpu_samples),
                "cpu_stdev_seconds": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0.0,
                "cpu_min_seconds": min(cpu_samples),
                "cpu_max_seconds": max(cpu_samples),
                "total_transmission_attempts": len(message_types),
                "messages_per_input_case": len(message_types) / max(1, len(cases)),
                "pbft_messages": sum(kind in PBFT_TYPES for kind in message_types),
                "evidence_protocol_messages": sum(kind in EVIDENCE_TYPES for kind in message_types),
                "announcement_messages": sum(kind == "EVIDENCE_ANNOUNCEMENT" for kind in message_types),
                "receipt_messages": sum(kind == "EVIDENCE_ANNOUNCEMENT_RECEIPT" for kind in message_types),
                "retrieval_messages": sum(kind.startswith("EVIDENCE_RETRIEVAL_") for kind in message_types),
                "total_transmitted_bytes": sum(message.size_bytes for message in result.messages),
                "successful_finalizations": sum(outcome.committed for outcome in result.consensus),
                "rejected_or_unqualified_cases": sum(
                    not decision.committed for decision in result.decisions
                ),
                "evidence_availability_enabled": config.distributed_extension.evidence_availability_enabled,
            })
            metric_rows.append(row)
            paired_cell.append((name, row, decision_identity, {"opportunity_ids": opportunity_ids, "frame": frame}))
        (left_name, left, left_ids, left_opp), (right_name, right, right_ids, right_opp) = paired_cell
        if left["trace_sha256"] != right["trace_sha256"] or left["case_count"] != right["case_count"]:
            raise AssertionError("Paired layouts did not use identical trace and case universe")
        pd.testing.assert_frame_equal(left_ids, right_ids, check_dtype=False)
        if left_opp["opportunity_ids"] != right_opp["opportunity_ids"]:
            raise AssertionError("Fixed attack-opportunity universe differs across V5 variants")
        paired_rows.append({
            "density": density,
            "seed": seed,
            "trace_sha256": trace_hash,
            "case_count": len(cases),
            "attack_opportunities": left["attack_opportunities"],
            "baseline_observed_opportunities": left["observed_attack_opportunities"],
            "candidate_observed_opportunities": right["observed_attack_opportunities"],
            "baseline_opportunity_recall": left["opportunity_detection_recall_fixed_denominator"],
            "candidate_opportunity_recall": right["opportunity_detection_recall_fixed_denominator"],
            "baseline_state_aware_recall": left["recall"],
            "candidate_state_aware_recall": right["recall"],
            "baseline_TP": left["TP"], "candidate_TP": right["TP"],
            "baseline_FP": left["FP"], "candidate_FP": right["FP"],
            "baseline_TN": left["TN"], "candidate_TN": right["TN"],
            "baseline_FN": left["FN"], "candidate_FN": right["FN"],
            "baseline_cpu_seconds": left["cpu_time_seconds"], "candidate_cpu_seconds": right["cpu_time_seconds"],
            "baseline_messages_per_case": left["messages_per_input_case"],
            "candidate_messages_per_case": right["messages_per_input_case"],
            "baseline_p95_e2e_ms": left["p95_e2e_ms"], "candidate_p95_e2e_ms": right["p95_e2e_ms"],
            "baseline_ledger_delay_p95_ms": left["p95_ledger_consistency_ms"],
            "candidate_ledger_delay_p95_ms": right["p95_ledger_consistency_ms"],
            "baseline_pdr": left["pdr"], "candidate_pdr": right["pdr"],
            "baseline_finalizations": left["successful_finalizations"],
            "candidate_finalizations": right["successful_finalizations"],
        })
        manifests.append({
            "density": density,
            "seed": seed,
            "trace_path": str(trace),
            "trace_sha256": trace_hash,
            "case_count": len(cases),
            "attack_opportunity_count": left["attack_opportunities"],
            "paired_case_ids_identical": True,
            "paired_opportunity_ids_identical": True,
            "sumo_rerun": False,
            "repeats_per_variant": args.repeats,
        })
        print(
            f"paired d={density} seed={seed} cases={len(cases)} "
            f"Recall={left['recall']:.4f}->{right['recall']:.4f} "
            f"opportunity={left['opportunity_detection_recall_fixed_denominator']:.4f}->"
            f"{right['opportunity_detection_recall_fixed_denominator']:.4f}",
            flush=True,
        )

    args.output.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(metric_rows).to_csv(args.output / "evidence_availability_metrics.csv", index=False)
    pd.DataFrame(paired_rows).to_csv(args.output / "evidence_availability_paired.csv", index=False)
    (args.output / "evidence_availability_manifest.json").write_text(
        json.dumps({
            "base_config_sha256": sha256_file(args.config),
            "variants": [
                {
                    "name": name,
                    "validators": list(config.pbft.validators),
                    "quorum": config.pbft.resolved_quorum,
                    "max_byzantine": config.pbft.max_byzantine,
                    "membership_epoch": config.distributed_extension.membership_epoch,
                    "coordinator_strategy": config.distributed_extension.coordinator_strategy,
                    "coordinator_pool": list(config.distributed_extension.coordinator_pool),
                    "evidence_availability_enabled": config.distributed_extension.evidence_availability_enabled,
                }
                for name, config in variants
            ],
            "cells": manifests,
            "requested_cells": [list(cell) for cell in selected_cells],
            "all_six_pilot_cells_evaluated": len(selected_cells) == len(CELLS),
        }, indent=2),
        encoding="utf-8",
    )
    print(f"wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
