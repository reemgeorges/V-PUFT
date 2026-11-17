from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from dataclasses import asdict, replace
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from vpuft.architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.density_campaign import _assert_transport_causality, _run_measured
from vpuft.metrics import decision_metrics
from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics
from vpuft.trace import build_trace_bundle, read_events_jsonl
from scripts.final_scenario5_ablation_adapter import (
    AblationQualificationAdapter,
    VARIANTS,
    effective_variant_record,
)
from scripts.sensitivity_opportunities import (
    build_base_emission_times,
    evaluate_attack_opportunities,
)


DEFAULT_SOURCE = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
    / "VPUFT-Preservation-2026-11-15"
    / "sensitivity_replication_2026-11-16"
)
DEFAULT_OUTPUT = ROOT / "results/final_scenario5_ablation"
BASE_CONFIG = ROOT / "results/urban_roundabout_campaign_corrected_final/effective_config.json"
DENSITIES = (20, 100)
SEEDS = (7003, 7004, 7005, 7006)
PILOT_SEEDS = (7003, 7004)
ABLATIONS = VARIANTS[1:]
WINDOW_SECONDS = 15.0
MAX_WALL_SECONDS = 1800.0
MAX_OUTPUT_BYTES = 500_000_000
MIN_FREE_BYTES = 5_000_000_000


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_value(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "-C", str(ROOT), *args],
        text=True,
    ).strip()


def _atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temp, path)


def _save_frame(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    pd.DataFrame(rows).to_csv(temp, index=False)
    os.replace(temp, path)


def _persist_run_rows(output: Path, rows: dict[str, list[dict]]) -> None:
    """Persist the current row state, including metadata-only resume updates."""
    for key, filename in (
        ("metrics", "ABLATION_METRICS_BY_SEED.csv"),
        ("decisions", "ABLATION_CASE_DECISIONS.csv"),
        ("opportunities", "ABLATION_FIXED_OPPORTUNITIES.csv"),
        ("manifest", "ABLATION_RUN_MANIFEST.csv"),
    ):
        _save_frame(output / filename, rows[key])


def _load_rows(path: Path) -> list[dict]:
    return pd.read_csv(path).to_dict("records") if path.is_file() else []


def _trace_rows(source: Path) -> list[dict]:
    manifest = json.loads((source / "SENSITIVITY_TRACE_MANIFEST.json").read_text(encoding="utf-8"))
    indexed = {(int(row["density"]), int(row["seed"])): row for row in manifest["traces"]}
    selected = []
    required_hashes = {
        "shared_detection_trace.jsonl": "trace_sha256",
        "generated_messages.csv": "generated_messages_sha256",
        "attack_ground_truth.csv": "attack_ground_truth_sha256",
        "mobility_trace.csv": "mobility_trace_sha256",
        "scenario_manifest.json": "scenario_manifest_sha256",
    }
    for density in DENSITIES:
        for seed in SEEDS:
            row = indexed.get((density, seed))
            if row is None:
                raise RuntimeError(f"Missing frozen trace manifest row for density={density}, seed={seed}")
            trace_dir = source / row["trace_relative_directory"]
            verified = {}
            for filename, digest_name in required_hashes.items():
                item = trace_dir / filename
                if not item.is_file():
                    raise FileNotFoundError(item)
                actual = sha(item)
                if actual != row[digest_name]:
                    raise RuntimeError(f"Trace hash mismatch: {item}")
                verified[filename] = actual
            selected.append({
                "density": density,
                "seed": seed,
                "source_trace_directory": str(trace_dir),
                "trace_sha256": row["trace_sha256"],
                "generated_messages_sha256": row["generated_messages_sha256"],
                "attack_ground_truth_sha256": row["attack_ground_truth_sha256"],
                "mobility_trace_sha256": row["mobility_trace_sha256"],
                "scenario_manifest_sha256": row["scenario_manifest_sha256"],
                "unique_vehicles": int(row["unique_vehicles"]),
                "case_count_in_raw_trace": int(row["cases_in_raw_detection_trace"]),
                "v2x_messages": int(row["v2x_messages"]),
                "detection_events": int(row["detection_events"]),
                "verified_file_hashes": verified,
            })
    return selected


def _source_hashes(source: Path) -> dict[str, str]:
    paths = [
        ROOT / "results/urban_roundabout_campaign_corrected_final/effective_config.json",
        ROOT / "sumo/urban_roundabout/attacks.json",
        ROOT / "sumo/urban_roundabout/rsus.json",
        ROOT / "src/vpuft/architectures/base.py",
        ROOT / "src/vpuft/architectures/centralized.py",
        ROOT / "src/vpuft/architectures/distributed_extension.py",
        ROOT / "src/vpuft/config.py",
        ROOT / "src/vpuft/crypto.py",
        ROOT / "src/vpuft/domain.py",
        ROOT / "src/vpuft/evidence.py",
        ROOT / "src/vpuft/qualification.py",
        ROOT / "src/vpuft/weighting.py",
        ROOT / "src/vpuft/trace.py",
        ROOT / "src/vpuft/density_campaign.py",
        ROOT / "src/vpuft/metrics.py",
        ROOT / "src/vpuft/state_aware_evaluation.py",
        ROOT / "scripts/sensitivity_opportunities.py",
        ROOT / "scripts/final_scenario5_ablation_adapter.py",
        ROOT / "scripts/run_final_scenario5_ablation.py",
        ROOT / "scripts/analyze_final_scenario5_ablation.py",
        ROOT / "tests/test_scenario5_ablation_adapter.py",
        ROOT / "tests/test_scenario5_ablation_analysis.py",
        source / "SENSITIVITY_TRACE_MANIFEST.json",
        source / "SENSITIVITY_EFFECTIVE_CONFIGS.json",
        source / "SENSITIVITY_RUN_MANIFEST.csv",
        source / "SENSITIVITY_METRICS_BY_SEED.csv",
        source / "SENSITIVITY_CASE_DECISIONS.csv",
        source / "SENSITIVITY_FIXED_OPPORTUNITIES.csv",
        source / "RUN_CONTEXT.json",
    ]
    return {path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path): sha(path) for path in paths}


def _selected_saved_baseline(source: Path, trace_records: list[dict], base_config) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    source_manifest = pd.read_csv(source / "SENSITIVITY_RUN_MANIFEST.csv")
    source_metrics = pd.read_csv(source / "SENSITIVITY_METRICS_BY_SEED.csv")
    source_decisions = pd.read_csv(source / "SENSITIVITY_CASE_DECISIONS.csv")
    source_opportunities = pd.read_csv(source / "SENSITIVITY_FIXED_OPPORTUNITIES.csv")
    source_context = json.loads((source / "RUN_CONTEXT.json").read_text(encoding="utf-8"))
    baseline_commit = str(source_context["execution_commit"])
    baseline_branch = str(source_context["execution_branch"])
    baseline_runner_hash = str(source_context["source_and_input_sha256"]["scripts/run_final_scenario5_sensitivity_replication.py"])
    wanted = set(SEEDS)
    selection = (source_manifest["variant_id"].eq("baseline")) & source_manifest["seed"].astype(int).isin(wanted)
    manifest = source_manifest.loc[selection].copy()
    if len(manifest) != 16 or not manifest["status"].eq("completed").all():
        raise RuntimeError("Selected saved baseline cells are incomplete")
    expected_hash = {(x["density"], x["seed"]): x["trace_sha256"] for x in trace_records}
    for row in manifest.to_dict("records"):
        key = (int(row["density"]), int(row["seed"]))
        if row["trace_sha256"] != expected_hash[key]:
            raise RuntimeError(f"Saved baseline uses a different trace: {row}")
    keys = {(int(r["density"]), int(r["seed"]), r["architecture"]) for r in manifest.to_dict("records")}
    if len(keys) != 16:
        raise RuntimeError("Saved baseline manifest has duplicate or missing selected cells")
    rows = []
    for frame, output in (
        (source_metrics, "metrics"),
        (source_decisions, "decisions"),
        (source_opportunities, "opportunities"),
    ):
        subset = frame[(frame["variant_id"] == "baseline") & frame["seed"].astype(int).isin(wanted)].copy()
        if len(subset) == 0:
            raise RuntimeError(f"No saved baseline {output} rows for selected seeds")
        rows.append(subset.to_dict("records"))
    metrics, decisions, opportunities = rows
    metric_index = {(int(r["density"]), int(r["seed"]), r["architecture"]): r for r in metrics}
    decision_groups: dict[tuple[int, int, str], list[dict]] = {}
    for row in decisions:
        decision_groups.setdefault((int(row["density"]), int(row["seed"]), row["architecture"]), []).append(row)
    opportunity_index = {(int(r["density"]), int(r["seed"]), r["architecture"]): r for r in opportunities}
    for row in manifest.to_dict("records"):
        key = (int(row["density"]), int(row["seed"]), row["architecture"])
        if key not in metric_index or key not in opportunity_index:
            raise RuntimeError(f"Saved baseline missing metric/opportunity row for {key}")
        if len(decision_groups.get(key, [])) != int(row["case_count"]):
            raise RuntimeError(f"Saved baseline decision count mismatch for {key}")
        if metric_index[key]["trace_sha256"] != row["trace_sha256"] or opportunity_index[key]["trace_sha256"] != row["trace_sha256"]:
            raise RuntimeError(f"Saved baseline artifacts disagree on trace hash for {key}")
        expected_backhaul = 100.0 if row["architecture"] == "C100" else 0.0
        actual_backhaul = float(metric_index[key]["backhaul_extra_latency_ms"])
        if abs(actual_backhaul - expected_backhaul) > 1e-9:
            raise RuntimeError(f"Saved baseline has wrong backhaul for {key}: {actual_backhaul}")
        row["backhaul_extra_latency_ms"] = actual_backhaul
    for row in metrics:
        delay = 100.0 if row["architecture"] == "C100" else 0.0
        arch_config = replace(base_config, network=replace(base_config.network, central_backhaul_extra_latency_ms=delay))
        row["effective_config_sha256"] = effective_variant_record(arch_config, "baseline")["effective_config_sha256"]
        row["execution_commit"] = baseline_commit
        row["execution_branch"] = baseline_branch
        row["runner_script_sha256"] = baseline_runner_hash
    manifest_records = manifest.to_dict("records")
    for row in manifest_records:
        delay = 100.0 if row["architecture"] == "C100" else 0.0
        arch_config = replace(base_config, network=replace(base_config.network, central_backhaul_extra_latency_ms=delay))
        row["effective_config_sha256"] = effective_variant_record(arch_config, "baseline")["effective_config_sha256"]
        row["execution_kind"] = "reused_saved_baseline"
        row["execution_commit"] = baseline_commit
        row["execution_branch"] = baseline_branch
        row["runner_script_sha256"] = baseline_runner_hash
        row["adapter_script_sha256"] = "production_engine_no_adapter"
    return manifest_records, metrics, decisions, opportunities


def _stage_seeds(stage: str) -> tuple[int, ...]:
    return PILOT_SEEDS if stage == "pilot" else tuple(seed for seed in SEEDS if seed not in PILOT_SEEDS)


def _enrich_reused_baseline(metric_rows: list[dict], manifest_rows: list[dict],
                            saved_metrics: list[dict], saved_manifest: list[dict]) -> None:
    metric_index = {
        (int(row["density"]), int(row["seed"]), row["architecture"]): row
        for row in saved_metrics
    }
    manifest_index = {
        (int(row["density"]), int(row["seed"]), row["architecture"]): row
        for row in saved_manifest
    }
    for rows, index in ((metric_rows, metric_index), (manifest_rows, manifest_index)):
        for row in rows:
            if row.get("variant_id") != "baseline":
                continue
            key = (int(row["density"]), int(row["seed"]), row["architecture"])
            if key not in index:
                raise RuntimeError(f"Reused baseline provenance row missing: {key}")
            for field in (
                "effective_config_sha256", "execution_commit", "execution_branch",
                "runner_script_sha256", "adapter_script_sha256",
            ):
                if field in index[key]:
                    row[field] = index[key][field]
            if row.get("architecture") == "C100":
                row["backhaul_extra_latency_ms"] = 100.0
            else:
                row["backhaul_extra_latency_ms"] = 0.0
            row["execution_kind"] = "reused_saved_baseline"


def _resume_reconciliation_hashes(known_paths: set[str], stored_hashes: dict, current_hashes: dict) -> dict:
    """Keep absent pre-run hashes explicit instead of implying they were recorded."""
    return {
        "changed_files": sorted(known_paths),
        "original_source_hashes": {name: stored_hashes.get(name) for name in sorted(known_paths)},
        "current_source_hashes": {name: current_hashes.get(name) for name in sorted(known_paths)},
    }


def _execute_cell(
    *, config, cases, density: int, seed: int, variant_id: str,
    architecture_name: str, trace_record: dict, events, attempt: int, output: Path,
) -> tuple[dict, list[dict], dict, dict]:
    run_config = config
    if architecture_name == "C100":
        run_config = replace(
            config,
            network=replace(config.network, central_backhaul_extra_latency_ms=100.0),
        )
        architecture = CentralizedVPUFT(run_config, KeyRegistry(run_config.security.deterministic_master_seed))
    else:
        run_config = replace(
            config,
            network=replace(config.network, central_backhaul_extra_latency_ms=0.0),
        )
        architecture = DistributedRSUExtendedVPUFT(run_config, KeyRegistry(run_config.security.deterministic_master_seed))
    if variant_id != "baseline":
        architecture.engine = AblationQualificationAdapter(run_config, variant_id)
    wall_started = time.perf_counter()
    result, cpu, peak_kb = _run_measured(architecture, cases, seed, architecture_name)
    wall_seconds = time.perf_counter() - wall_started
    _assert_transport_causality(
        result,
        queue_rate_bytes_per_second=run_config.network.queue_rate_bytes_per_second,
    )
    case_by_id = {case.case_id: case for case in cases}
    truth = {case.case_id: case.ground_truth_malicious for case in cases}
    opened = {case.case_id: case.opened_at for case in cases}
    metric = decision_metrics(result, truth, opened)
    metric.update({
        "variant_id": variant_id,
        "density": density,
        "seed": seed,
        "architecture": architecture_name,
        "attempt": attempt,
        "backhaul_extra_latency_ms": run_config.network.central_backhaul_extra_latency_ms,
        "cpu_time_seconds": cpu,
        "peak_memory_kb": peak_kb,
        "case_count": len(result.decisions),
        "trace_sha256": trace_record["trace_sha256"],
        "effective_config_sha256": effective_variant_record(run_config, variant_id)["effective_config_sha256"],
        "execution_commit": git_value("rev-parse", "HEAD"),
        "execution_branch": git_value("rev-parse", "--abbrev-ref", "HEAD"),
    })
    decision_rows = []
    for decision in result.decisions:
        case = case_by_id[decision.case_id]
        decision_rows.append({
            "variant_id": variant_id,
            "density": density,
            "seed": seed,
            "architecture": architecture_name,
            "attempt": attempt,
            "case_id": decision.case_id,
            "vehicle_id": decision.vehicle_id,
            "attack_type": case.attack_type.value,
            "ground_truth_malicious": int(case.ground_truth_malicious),
            "committed": int(decision.committed),
            "predicted_revoked": int(decision.committed and decision.new_state.value == "revoked"),
            "new_state": decision.new_state.value,
            "reason": decision.reason,
            "opened_at": case.opened_at,
            "detected_at": decision.detected_at,
            "qualified_at": decision.qualified_at,
            "finalized_at": decision.finalized_at,
            "ledger_available_at": decision.ledger_available_at,
            "trace_sha256": trace_record["trace_sha256"],
        })
    frame = pd.DataFrame([{
        "case_id": row["case_id"],
        "vehicle_id": row["vehicle_id"],
        "seed": seed,
        "architecture": architecture_name,
        "ground_truth_malicious": row["ground_truth_malicious"],
        "committed": row["committed"],
        "new_state": row["new_state"],
        "topology": "urban_roundabout",
        "vehicle_count": density,
        "backhaul_extra_latency_ms": metric["backhaul_extra_latency_ms"],
    } for row in decision_rows])
    method_b = state_aware_first_revocation_metrics(frame, window_seconds=WINDOW_SECONDS)
    if len(method_b) != 1:
        raise RuntimeError("Method B evaluator failed to return exactly one row")
    mb = method_b.iloc[0]
    for name in ("TP", "FP", "TN", "FN"):
        if int(metric[name]) != int(mb[name]):
            raise RuntimeError(f"Decision metrics and Method B disagree for {name}")
    if int(metric["excluded_post_revocation_cases"]) != int(mb["excluded_post_revocation_windows"]):
        raise RuntimeError("Decision metrics and Method B disagree on terminal exclusions")

    trace_dir = Path(trace_record["source_trace_directory"])
    raw_messages = pd.read_csv(trace_dir / "generated_messages.csv")
    mobility = pd.read_csv(trace_dir / "mobility_trace.csv")
    attack_messages = raw_messages[
        raw_messages["ground_truth_malicious"].astype(str).str.lower().isin(("true", "1"))
    ]
    emissions = build_base_emission_times(mobility.to_dict("records"), seed=seed)
    observations = [{
        "message_id": event.message_id,
        "case_id": event.case_id,
        "seed": event.seed,
        "vehicle_id": event.vehicle_id,
        "detected_at": event.detected_at,
        "source_kind": event.source_kind.value,
        "observation_root_id": event.observation_root_id,
    } for event in events]
    opportunities = evaluate_attack_opportunities(
        attack_messages.to_dict("records"), observations, decision_rows, emissions,
        seed=seed, window_seconds=WINDOW_SECONDS,
    )
    opportunity_row = {
        "variant_id": variant_id,
        "density": density,
        "seed": seed,
        "architecture": architecture_name,
        "attempt": attempt,
        **opportunities,
        "trace_sha256": trace_record["trace_sha256"],
    }
    manifest_row = {
        "variant_id": variant_id,
        "density": density,
        "seed": seed,
        "architecture": architecture_name,
        "attempt": attempt,
        "status": "completed",
        "execution_kind": "replayed_saved_detection_trace",
        "case_count": len(decision_rows),
        "trace_sha256": trace_record["trace_sha256"],
        "effective_config_sha256": metric["effective_config_sha256"],
        "execution_commit": git_value("rev-parse", "HEAD"),
        "execution_branch": git_value("rev-parse", "--abbrev-ref", "HEAD"),
        "runner_script_sha256": sha(ROOT / "scripts/run_final_scenario5_ablation.py"),
        "adapter_script_sha256": sha(ROOT / "scripts/final_scenario5_ablation_adapter.py"),
        "cpu_time_seconds": cpu,
        "wall_seconds": wall_seconds,
        "messages_total": metric["messages_total"],
        "bytes_total": metric["bytes_total"],
        "pdr": metric["packet_delivery_ratio"],
        "failure": "",
    }
    return metric, decision_rows, opportunity_row, manifest_row


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded Scenario 5 evidence-component ablation replay")
    parser.add_argument("--stage", choices=("pilot", "remaining"), required=True)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    source = args.source_dir.expanduser().resolve()
    output = args.output_dir.expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Existing trace preservation directory not found: {source}")
    if not output.is_relative_to(ROOT):
        raise ValueError("Study output must remain under this research worktree")
    if git_value("rev-parse", "--abbrev-ref", "HEAD") != "research/final-scenario5":
        raise RuntimeError("Ablation is permitted only on research/final-scenario5")
    if git_value("status", "--porcelain", "--untracked-files=all"):
        # Existing raw pilot files and this isolated study's files are preserved.
        allowed = (
            "results/final_scenario5_sensitivity/pilot_2026-11-16/",
            "docs/final_scenario5_ablation/",
            "results/final_scenario5_ablation/",
            "scripts/final_scenario5_ablation_adapter.py",
            "scripts/run_final_scenario5_ablation.py",
            "scripts/analyze_final_scenario5_ablation.py",
            "tests/test_scenario5_ablation_adapter.py",
            "tests/test_scenario5_ablation_analysis.py",
        )
        unexpected = [line for line in git_value("status", "--porcelain", "--untracked-files=all").splitlines()
                      if not line[3:].replace("\\", "/").startswith(allowed)]
        if unexpected:
            raise RuntimeError(f"Unexpected pre-existing worktree changes: {unexpected[:5]}")

    config = load_config(BASE_CONFIG)
    config.validate()
    if config.pbft.validators != ("rsu-1", "rsu-2", "rsu-3", "rsu-4"):
        raise RuntimeError("Unexpected baseline PBFT membership")
    if config.policies["position_offset"].required_sources != 2:
        raise RuntimeError("Unexpected baseline source-diversity policy")
    if any(abs(policy.freshness_window_seconds - 15.0) > 1e-12 for policy in config.policies.values()):
        raise RuntimeError("Unexpected baseline freshness policy")

    source_config = json.loads((source / "SENSITIVITY_EFFECTIVE_CONFIGS.json").read_text(encoding="utf-8"))
    config_hash = hashlib.sha256(
        json.dumps(asdict(config), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if source_config["baseline"]["effective_config_sha256"] != config_hash:
        raise RuntimeError("Existing saved baseline was produced with a different effective base configuration")

    trace_records = _trace_rows(source)
    saved_manifest, baseline_metrics, baseline_decisions, baseline_opportunities = _selected_saved_baseline(source, trace_records, config)
    if output.exists() and any(output.iterdir()) and not args.resume:
        raise RuntimeError(f"Output directory is not empty; refusing to overwrite: {output}")
    output.mkdir(parents=True, exist_ok=True)
    disk = __import__("shutil").disk_usage(output.anchor or str(ROOT.anchor))
    if disk.free < MIN_FREE_BYTES:
        raise RuntimeError(f"Free-space reserve failed: {disk.free} < {MIN_FREE_BYTES}")
    if args.preflight:
        if output.exists() and any(output.iterdir()):
            raise RuntimeError(f"Preflight refuses a non-empty target: {output}")
        baseline_case_bytes = len(pd.DataFrame(baseline_decisions).to_csv(index=False).encode("utf-8"))
        baseline_case_rows = len(baseline_decisions)
        planned_new_case_rows = baseline_case_rows * 2
        estimated_serialized_case_bytes = int(
            baseline_case_bytes + (baseline_case_bytes / max(1, baseline_case_rows)) * planned_new_case_rows * 1.5
        )
        estimated_total_output_bytes = estimated_serialized_case_bytes + 75_000_000
        print(json.dumps({
            "preflight": "passed",
            "branch": git_value("rev-parse", "--abbrev-ref", "HEAD"),
            "commit": git_value("rev-parse", "HEAD"),
            "selected_trace_count": len(trace_records),
            "trace_hash_checks": sum(len(row["verified_file_hashes"]) for row in trace_records),
            "selected_saved_baseline_cells": len(saved_manifest),
            "planned_new_pilot_runs": 16,
            "planned_new_remaining_runs": 16,
            "maximum_new_runs": 32,
            "maximum_comparison_cells": 48,
            "wall_time_cap_seconds": MAX_WALL_SECONDS,
            "output_cap_bytes": MAX_OUTPUT_BYTES,
            "estimated_output_bytes_with_75MB_reserve": estimated_total_output_bytes,
            "minimum_free_bytes": MIN_FREE_BYTES,
            "free_bytes_before_run": disk.free,
            "preserved_trace_bytes_not_copied": sum(
                Path(row["source_trace_directory"], filename).stat().st_size
                for row in trace_records
                for filename in row["verified_file_hashes"]
            ),
            "output_directory": str(output),
            "output_exists_and_empty": output.exists() and not any(output.iterdir()),
            "raw_trace_storage": str(source),
        }, indent=2))
        return

    context = {
        "study": "final_scenario5_bounded_component_ablation_v1",
        "branch": git_value("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": git_value("rev-parse", "HEAD"),
        "baseline_config_sha256": config_hash,
        "source_hashes": _source_hashes(source),
        "density": list(DENSITIES),
        "seeds": list(SEEDS),
        "pilot_seeds": list(PILOT_SEEDS),
        "variants": list(VARIANTS),
        "architectures": ["C100", "Distributed"],
        "max_comparison_cells": 48,
        "max_new_ablation_runs": 32,
        "wall_time_cap_seconds": MAX_WALL_SECONDS,
        "output_cap_bytes": MAX_OUTPUT_BYTES,
        "minimum_free_bytes": MIN_FREE_BYTES,
        "raw_trace_storage": str(source),
        "raw_traces_copied": False,
    }
    context_path = output / "ABLATION_CONTEXT.json"
    if args.resume:
        if not context_path.is_file():
            raise RuntimeError("Resume context/source/config hashes differ")
        stored_context = json.loads(context_path.read_text(encoding="utf-8"))
        if stored_context != context:
            stable_stored = dict(stored_context)
            stable_current = dict(context)
            stored_hashes = dict(stable_stored.pop("source_hashes", {}))
            current_hashes = dict(stable_current.pop("source_hashes", {}))
            changed_hash_paths = {
                name for name in set(stored_hashes) | set(current_hashes)
                if stored_hashes.get(name) != current_hashes.get(name)
            }
            known_paths = {
                "scripts/run_final_scenario5_ablation.py",
                "scripts/analyze_final_scenario5_ablation.py",
                "tests/test_scenario5_ablation_analysis.py",
                str(source / "RUN_CONTEXT.json"),
            }
            if stable_stored != stable_current or changed_hash_paths != known_paths:
                raise RuntimeError("Resume context/source/config hashes differ")
            reconciliation_path = output / "ABLATION_RESUME_CODE_RECONCILIATION.json"
            reconciliation = {
                **_resume_reconciliation_hashes(known_paths, stored_hashes, current_hashes),
                "scope": [
                    "corrected the pilot validator to restrict identity checks to pilot seeds",
                    "normalized tuple/list representation when comparing effective configuration JSON",
                    "added source provenance fields for reused baseline rows",
                    "added pooled fixed-opportunity count aggregation; no experiment inputs or adapter qualification semantics changed",
                    "added the read-only source RUN_CONTEXT manifest hash to provenance",
                ],
                "no_behavioral_or_simulation_logic_changed": True,
                "completed_pilot_outputs_preserved": True,
            }
            if reconciliation_path.exists():
                existing_reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
                old_original = existing_reconciliation.get("original_source_hashes", {})
                if old_original and old_original != reconciliation["original_source_hashes"]:
                    raise RuntimeError("Original pilot source hashes differ from reconciliation record")
                _atomic_json(reconciliation_path, reconciliation)
            else:
                _atomic_json(reconciliation_path, reconciliation)
    elif context_path.exists():
        raise RuntimeError("Output already initialized; use --resume after reviewing it")
    else:
        _atomic_json(context_path, context)

    configs_path = output / "ABLATION_EFFECTIVE_CONFIGS.json"
    effective_configs = {}
    for variant in VARIANTS:
        effective_configs[variant] = {}
        for architecture in ("C100", "Distributed"):
            delay = 100.0 if architecture == "C100" else 0.0
            arch_config = replace(config, network=replace(config.network, central_backhaul_extra_latency_ms=delay))
            effective_configs[variant][architecture] = effective_variant_record(arch_config, variant)
    # Match the JSON representation used by previous writes (dataclass tuples become arrays).
    effective_configs = json.loads(json.dumps(effective_configs))
    if args.resume and configs_path.exists():
        if json.loads(configs_path.read_text(encoding="utf-8")) != effective_configs:
            raise RuntimeError("Effective configuration manifest changed during resume")
    else:
        _atomic_json(configs_path, effective_configs)
    _atomic_json(output / "ABLATION_INPUT_TRACE_MANIFEST.json", {"traces": trace_records})

    metrics_path = output / "ABLATION_METRICS_BY_SEED.csv"
    decisions_path = output / "ABLATION_CASE_DECISIONS.csv"
    opportunities_path = output / "ABLATION_FIXED_OPPORTUNITIES.csv"
    manifest_path = output / "ABLATION_RUN_MANIFEST.csv"
    if args.resume:
        metric_rows = _load_rows(metrics_path)
        decision_rows = _load_rows(decisions_path)
        opportunity_rows = _load_rows(opportunities_path)
        manifest_rows = _load_rows(manifest_path)
        original_runner_hash = json.loads(context_path.read_text(encoding="utf-8"))["source_hashes"]["scripts/run_final_scenario5_ablation.py"]
        for row in manifest_rows:
            if row.get("variant_id") != "baseline":
                row.setdefault("runner_script_sha256", original_runner_hash)
                row.setdefault("adapter_script_sha256", context["source_hashes"]["scripts/final_scenario5_ablation_adapter.py"])
        _enrich_reused_baseline(metric_rows, manifest_rows, baseline_metrics, saved_manifest)
    else:
        metric_rows = [dict(row, execution_kind="reused_saved_baseline") for row in baseline_metrics]
        decision_rows = [dict(row, execution_kind="reused_saved_baseline") for row in baseline_decisions]
        opportunity_rows = [dict(row, execution_kind="reused_saved_baseline") for row in baseline_opportunities]
        manifest_rows = [dict(row, execution_kind="reused_saved_baseline") for row in saved_manifest]
        _save_frame(metrics_path, metric_rows)
        _save_frame(decisions_path, decision_rows)
        _save_frame(opportunities_path, opportunity_rows)
        _save_frame(manifest_path, manifest_rows)

    trace_index = {(row["density"], row["seed"]): row for row in trace_records}
    existing = {
        (r["variant_id"], int(r["density"]), int(r["seed"]), r["architecture"])
        for r in manifest_rows if r.get("status") == "completed"
    }
    expected_variants = {"A_report_mass", "C_no_diversity_gates"}
    expected_seed_scope = set(_stage_seeds(args.stage))
    if args.stage == "remaining":
        pilot_check = output / "ABLATION_PILOT_VALIDATION.json"
        if not pilot_check.is_file() or not json.loads(pilot_check.read_text(encoding="utf-8")).get("passed"):
            raise RuntimeError("Remaining runs require a passed, reviewed pilot validation marker")

    started = time.monotonic()
    executed = 0
    key_registry = KeyRegistry(config.security.deterministic_master_seed)
    for density in DENSITIES:
        for seed in _stage_seeds(args.stage):
            trace_record = trace_index[(density, seed)]
            trace_dir = Path(trace_record["source_trace_directory"])
            events = read_events_jsonl(trace_dir / "shared_detection_trace.jsonl")
            bundle = build_trace_bundle(
                events,
                key_registry,
                window_seconds=WINDOW_SECONDS,
                namespace=f"urban_roundabout-vehicles-{density}",
            )
            cases = bundle.rsu_cases
            if not cases:
                raise RuntimeError(f"No RSU cases at density={density}, seed={seed}")
            for variant_id in sorted(expected_variants):
                for architecture in ("C100", "Distributed"):
                    key = (variant_id, density, seed, architecture)
                    if key in existing:
                        continue
                    if time.monotonic() - started > MAX_WALL_SECONDS:
                        _atomic_json(output / "ABLATION_STATUS.json", {
                            "status": "paused_wall_cap", "stage": args.stage,
                            "completed_total": len(existing), "executed_this_invocation": executed,
                            "expected_total": 48, "active_wall_seconds": time.monotonic() - started,
                        })
                        raise TimeoutError("Ablation wall-time cap reached; resume only after inspecting outputs")
                    free = __import__("shutil").disk_usage(output.anchor or str(ROOT.anchor)).free
                    if free < MIN_FREE_BYTES:
                        raise RuntimeError(f"Free-space reserve reached: {free} < {MIN_FREE_BYTES}")
                    try:
                        previous_attempts = [
                            int(float(row.get("attempt", 1))) for row in manifest_rows
                            if row.get("variant_id") == variant_id
                            and int(float(row.get("density", 0))) == density
                            and int(float(row.get("seed", 0))) == seed
                            and row.get("architecture") == architecture
                        ]
                        attempt = max(previous_attempts, default=0) + 1
                        metric, case_rows, opportunity, manifest_row = _execute_cell(
                            config=config,
                            cases=cases,
                            density=density,
                            seed=seed,
                            variant_id=variant_id,
                            architecture_name=architecture,
                            trace_record=trace_record,
                            events=bundle.events,
                            attempt=attempt,
                            output=output,
                        )
                    except Exception as exc:
                        manifest_rows.append({
                            "variant_id": variant_id, "density": density, "seed": seed,
                            "architecture": architecture, "status": "failed",
                            "execution_kind": "replayed_saved_detection_trace",
                            "trace_sha256": trace_record["trace_sha256"],
                            "failure": repr(exc),
                        })
                        _save_frame(manifest_path, manifest_rows)
                        _atomic_json(output / "ABLATION_STATUS.json", {
                            "status": "failed", "failed_cell": manifest_rows[-1],
                            "completed_total": len(existing),
                        })
                        raise
                    metric_rows.append(metric)
                    decision_rows.extend(case_rows)
                    opportunity_rows.append(opportunity)
                    manifest_rows.append(manifest_row)
                    existing.add(key)
                    executed += 1
                    _save_frame(metrics_path, metric_rows)
                    _save_frame(decisions_path, decision_rows)
                    _save_frame(opportunities_path, opportunity_rows)
                    _save_frame(manifest_path, manifest_rows)
                    size = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
                    if size > MAX_OUTPUT_BYTES:
                        raise RuntimeError(f"Ablation output cap exceeded: {size} > {MAX_OUTPUT_BYTES}")
                    _atomic_json(output / "ABLATION_STATUS.json", {
                        "status": "running", "stage": args.stage,
                        "completed_total": len(existing), "executed_this_invocation": executed,
                        "expected_total": 48, "active_wall_seconds": time.monotonic() - started,
                        "output_bytes": size,
                    })

    _persist_run_rows(output, {
        "metrics": metric_rows,
        "decisions": decision_rows,
        "opportunities": opportunity_rows,
        "manifest": manifest_rows,
    })
    _validate_cells(output, trace_records)
    status = {
        "status": "pilot_cells_completed" if args.stage == "pilot" else "all_cells_completed",
        "stage": args.stage,
        "completed_comparison_cells": 16 if args.stage == "pilot" else 48,
        "reused_baseline_cells": 8 if args.stage == "pilot" else 16,
        "new_ablation_runs_total": 16 if args.stage == "pilot" else 32,
        "executed_this_invocation": executed,
        "active_wall_seconds": time.monotonic() - started,
        "output_bytes": sum(path.stat().st_size for path in output.rglob("*") if path.is_file()),
    }
    _atomic_json(output / "ABLATION_STATUS.json", status)
    if args.stage == "pilot":
        checks = _pilot_checks(output, trace_records, PILOT_SEEDS)
        _atomic_json(output / "ABLATION_PILOT_VALIDATION.json", checks)
        if not checks["passed"]:
            raise RuntimeError("Pilot validation failed; remaining cells were not started")
    print(json.dumps(status, indent=2))


def _validate_cells(output: Path, traces: list[dict]) -> None:
    manifest = pd.read_csv(output / "ABLATION_RUN_MANIFEST.csv")
    metrics = pd.read_csv(output / "ABLATION_METRICS_BY_SEED.csv")
    decisions = pd.read_csv(output / "ABLATION_CASE_DECISIONS.csv")
    opportunities = pd.read_csv(output / "ABLATION_FIXED_OPPORTUNITIES.csv")
    trace_hash = {(int(r["density"]), int(r["seed"])): r["trace_sha256"] for r in traces}
    completed = manifest[manifest.status.eq("completed")]
    if completed.duplicated(["variant_id", "density", "seed", "architecture"]).any():
        raise RuntimeError("Duplicate successful cell in run manifest")
    for row in completed.to_dict("records"):
        key = (int(row["density"]), int(row["seed"]))
        if row["trace_sha256"] != trace_hash[key]:
            raise RuntimeError(f"Manifest trace hash mismatch for {row}")
        mask = (
            metrics.variant_id.eq(row["variant_id"])
            & metrics.density.astype(int).eq(int(row["density"]))
            & metrics.seed.astype(int).eq(int(row["seed"]))
            & metrics.architecture.eq(row["architecture"])
        )
        if int(mask.sum()) != 1:
            raise RuntimeError(f"Expected one metric row for {row}")
        dmask = (
            decisions.variant_id.eq(row["variant_id"])
            & decisions.density.astype(int).eq(int(row["density"]))
            & decisions.seed.astype(int).eq(int(row["seed"]))
            & decisions.architecture.eq(row["architecture"])
        )
        group = decisions.loc[dmask]
        if len(group) != int(row["case_count"]) or group.case_id.duplicated().any():
            raise RuntimeError(f"Decision count/identity mismatch for {row}")
        omask = (
            opportunities.variant_id.eq(row["variant_id"])
            & opportunities.density.astype(int).eq(int(row["density"]))
            & opportunities.seed.astype(int).eq(int(row["seed"]))
            & opportunities.architecture.eq(row["architecture"])
        )
        if int(omask.sum()) != 1:
            raise RuntimeError(f"Expected one opportunity row for {row}")


def _pilot_checks(output: Path, trace_records: list[dict], seeds: tuple[int, ...]) -> dict:
    metrics = pd.read_csv(output / "ABLATION_METRICS_BY_SEED.csv")
    decisions = pd.read_csv(output / "ABLATION_CASE_DECISIONS.csv")
    opportunities = pd.read_csv(output / "ABLATION_FIXED_OPPORTUNITIES.csv")
    checks = {}
    checks["pilot_has_all_24_comparison_cells"] = len(metrics[
        metrics.seed.astype(int).isin(seeds) & metrics.density.astype(int).isin(DENSITIES)
    ]) == 24
    checks["all_expected_variants_architectures_and_seeds_present"] = all(
        len(metrics[(metrics.variant_id == variant) & metrics.seed.astype(int).isin(seeds)
                    & metrics.architecture.isin(("C100", "Distributed"))]) == 8
        for variant in VARIANTS
    )
    checks["each_cell_has_unique_case_ids"] = not decisions.duplicated(
        ["variant_id", "density", "seed", "architecture", "case_id"]
    ).any()
    checks["fixed_opportunity_denominators_match_within_trace"] = True
    for _, group in opportunities.groupby(["density", "seed"]):
        for field in ("attack_message_opportunities", "observed_attack_messages", "unobserved_attack_messages"):
            if group[field].nunique(dropna=False) != 1:
                checks["fixed_opportunity_denominators_match_within_trace"] = False
    checks["all_selected_trace_hashes_match_manifest"] = len(trace_records) == 8
    checks["all_replayed_metrics_reconcile_to_Method_B"] = True
    for row in metrics[metrics.variant_id != "baseline"].to_dict("records"):
        subset = decisions[
            (decisions.variant_id == row["variant_id"])
            & (decisions.density.astype(int) == int(row["density"]))
            & (decisions.seed.astype(int) == int(row["seed"]))
            & (decisions.architecture == row["architecture"])
        ]
        counts = {key: 0 for key in ("TP", "FP", "TN", "FN")}
        terminal = {}
        by_vehicle = {}
        for r in subset.to_dict("records"):
            if int(r["predicted_revoked"]) and int(r["ground_truth_malicious"]):
                label = "TP"
            elif int(r["predicted_revoked"]):
                label = "FP"
            elif int(r["ground_truth_malicious"]):
                label = "FN"
            else:
                label = "TN"
            # Metric rows use Method B's terminal first-revocation exclusions;
            # a later noop decision is identified by its reason.
            if r["reason"] == "already_revoked_terminal_state":
                continue
            counts[label] += 1
        for name, value in counts.items():
            if int(row[name]) != value:
                checks["all_replayed_metrics_reconcile_to_Method_B"] = False
    checks["trace_case_sets_match_baseline"] = True
    pilot_decisions = decisions[decisions.seed.astype(int).isin(seeds)]
    for (density, seed, architecture), group in pilot_decisions.groupby(
        ["density", "seed", "architecture"], dropna=False
    ):
        baseline_group = group[group.variant_id == "baseline"].set_index("case_id")
        for variant in ABLATIONS:
            candidate_group = group[group.variant_id == variant].set_index("case_id")
            if set(candidate_group.index) != set(baseline_group.index):
                checks["trace_case_sets_match_baseline"] = False
                continue
            for column in ("vehicle_id", "attack_type", "ground_truth_malicious", "opened_at"):
                left = baseline_group[column].sort_index()
                right = candidate_group[column].sort_index()
                if column == "opened_at":
                    equal = left.astype(float).equals(right.astype(float))
                else:
                    equal = left.astype(str).equals(right.astype(str))
                if not equal:
                    checks["trace_case_sets_match_baseline"] = False
    checks["passed"] = all(checks.values())
    checks["scope"] = {"densities": list(DENSITIES), "seeds": list(seeds), "architectures": 2, "variants": 3}
    return checks


if __name__ == "__main__":
    main()
