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
from vpuft.trace import build_trace_bundle, read_events_jsonl
from run_phase2_ablation import decision_frame, metric_row


CELLS = ((20, 2101), (20, 2102), (60, 2101), (60, 2102), (100, 2101), (100, 2102))
PBFT_TYPES = {"PRE_PREPARE", "PREPARE", "COMMIT", "STATE_RECOVERY"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def completed_trace(trace_root: Path, density: int, seed: int) -> Path:
    parent = trace_root / "pilot" / "C3" / f"vehicles_{density}"
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
        raise FileNotFoundError(f"expected exactly one completed trace for C3/{density}/{seed}; got {retries}")
    return retries[0]


def variant_config(base, *, v5: bool):
    if v5:
        validators = ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5")
        q, epoch = 4, "v5-eight-rsu-committee-v1"
        sensing_only = ("rsu-6", "rsu-7", "rsu-8")
        label = "V5_q4"
    else:
        validators = ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
        q, epoch = 3, "v4-eight-rsu-replay-v1"
        sensing_only = ("rsu-5", "rsu-6", "rsu-7", "rsu-8")
        label = "V4_q3"
    pbft = replace(base.pbft, validators=validators, max_byzantine=1, quorum_size=q, membership_epoch=epoch)
    ext = replace(
        base.distributed_extension,
        coordinator_strategy="first_observer_then_hash",
        coordinator_pool=("rsu-1", "rsu-2", "rsu-3", "rsu-4"),
        membership_epoch=epoch,
        sensing_only_rsu_ids=sensing_only,
    )
    config = replace(base, pbft=pbft, distributed_extension=ext, simulation=replace(base.simulation, rsu_count=8))
    config.validate()
    return label, config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--trace-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        raise ValueError("repeats must be at least one")

    base = load_config(args.config)
    variants = [variant_config(base, v5=False), variant_config(base, v5=True)]
    rows = []
    for density, seed in CELLS:
        trace = completed_trace(args.trace_root, density, seed)
        events = read_events_jsonl(trace)
        bundle = build_trace_bundle(
            events,
            KeyRegistry(base.security.deterministic_master_seed),
            window_seconds=base.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        cases = bundle.rsu_cases
        fingerprints = {case.case_id: case.ground_truth_malicious for case in cases}
        if len(fingerprints) != len(cases):
            raise AssertionError(f"duplicate case identity in {density}/{seed}")
        cell_rows = []
        for label, config in variants:
            cpu_samples = []
            result = None
            frame = None
            decision_fingerprint = None
            for _ in range(args.repeats):
                started = time.process_time()
                result = DistributedRSUExtendedVPUFT(
                    config, KeyRegistry(config.security.deterministic_master_seed)
                ).run(cases, seed)
                cpu_samples.append(time.process_time() - started)
                frame = decision_frame(result, cases, density=density, seed=seed, variant=label)
                current = frame[["case_id", "new_state", "committed", "qualified_at", "finalized_at"]].sort_values("case_id").reset_index(drop=True)
                if decision_fingerprint is None:
                    decision_fingerprint = current
                else:
                    pd.testing.assert_frame_equal(decision_fingerprint, current, check_dtype=False, check_exact=False, atol=1e-10)
            assert result is not None and frame is not None
            row = metric_row(
                result, cases, frame, density=density, seed=seed, variant=label,
                cpu=statistics.median(cpu_samples), wall=float("nan"), peak=float("nan"), acquisition={},
            )
            message_types = [message.message_type for message in result.messages]
            row.update({
                "case_count": len(cases),
                "trace_sha256": sha256_file(trace),
                "repeats": args.repeats,
                "cpu_mean_s": statistics.mean(cpu_samples),
                "cpu_median_s": statistics.median(cpu_samples),
                "cpu_stdev_s": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0.0,
                "cpu_min_s": min(cpu_samples),
                "cpu_max_s": max(cpu_samples),
                "pbft_message_count": sum(kind in PBFT_TYPES for kind in message_types),
                "evidence_transport_message_count": sum(kind in {"RSU_EVIDENCE_EXCHANGE", "VPUFT_EVIDENCE_BUNDLE", "WITNESS_EVIDENCE_UPLINK"} for kind in message_types),
                "all_message_count": len(message_types),
                "messages_per_input_case": len(message_types) / max(1, len(cases)),
                "successful_finalizations": sum(outcome.committed for outcome in result.consensus),
                "consensus_progress_failures": sum(not outcome.committed for outcome in result.consensus),
                "ledger_consistent": int(result.ledger_consistent),
                "trace_path_used": str(trace),
            })
            rows.append(row)
            cell_rows.append(row)
            print(f"{label} density={density} seed={seed} cases={len(cases)} finalizations={row['successful_finalizations']} CPU={row['cpu_median_s']:.6f}s", flush=True)
        left, right = cell_rows
        if left["trace_sha256"] != right["trace_sha256"] or left["case_count"] != right["case_count"]:
            raise AssertionError("paired V4/V5 run did not use identical trace input")

    args.output.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(rows)
    frame.to_csv(args.output / "v4_v5_paired_replay.csv", index=False)
    manifest = {
        "baseline_config_sha256": sha256_file(args.config),
        "trace_root": str(args.trace_root),
        "cells": [
            {"density": d, "seed": s, "trace": str(completed_trace(args.trace_root, d, s)), "trace_sha256": sha256_file(completed_trace(args.trace_root, d, s))}
            for d, s in CELLS
        ],
        "variants": [{"name": name, "validators": list(config.pbft.validators), "quorum": config.pbft.resolved_quorum, "membership_epoch": config.pbft.membership_epoch, "coordinator_pool": list(config.distributed_extension.coordinator_pool)} for name, config in variants],
        "repeats": args.repeats,
        "frozen_inputs_only": True,
    }
    (args.output / "paired_replay_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
