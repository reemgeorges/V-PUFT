from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import os
import sys
import subprocess
import time
from dataclasses import asdict, replace
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

from vpuft.architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.density_campaign import _assert_transport_causality, _run_measured
from vpuft.metrics import decision_metrics
from vpuft.sumo.density import build_density_scenario
from vpuft.sumo.runner import run_sumo_trace
from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics
from vpuft.trace import build_trace_bundle, read_events_jsonl
from scripts.sensitivity_opportunities import build_base_emission_times, evaluate_attack_opportunities


BASE_CONFIG = Path("results/urban_roundabout_campaign_corrected_final/effective_config.json")
DEFAULT_OUT = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "VPUFT-Preservation-2026-11-15" / "sensitivity_replication_2026-11-16"
DENSITIES = (20, 100)
SEEDS = (7003, 7004, 7005, 7006, 7007, 7008)
WINDOW = 15.0
MAX_WALL_SECONDS = 3600.0
MAX_OUTPUT_BYTES = 3_000_000_000
MIN_FREE_BYTES = 5_000_000_000
EXPECTED_RUNS = 120


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git_value(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "-C", str(ROOT), *args],
        text=True,
    ).strip()


def verify_completed_pilot(pilot_dir: Path) -> tuple[dict, int]:
    status_path = pilot_dir / "pilot_status.json"
    traces_path = pilot_dir / "SENSITIVITY_TRACE_MANIFEST.json"
    if not status_path.is_file() or not traces_path.is_file():
        raise RuntimeError("Prior pilot status or trace manifest is missing")
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("completed_runs") != 64 or status.get("status") != "completed":
        raise RuntimeError("Prior pilot is not intact at 64/64")
    records = json.loads(traces_path.read_text(encoding="utf-8")).get("traces", [])
    expected = {(20, 7001), (20, 7002), (100, 7001), (100, 7002)}
    keys = {(int(row["density"]), int(row["seed"])) for row in records}
    if len(records) != 4 or keys != expected:
        raise RuntimeError("Prior pilot trace manifest does not contain the four expected pairs")
    files = {
        "shared_detection_trace.jsonl": "trace_sha256",
        "generated_messages.csv": "generated_messages_sha256",
        "attack_ground_truth.csv": "attack_ground_truth_sha256",
        "mobility_trace.csv": "mobility_trace_sha256",
        "scenario_manifest.json": "scenario_manifest_sha256",
    }
    for row in records:
        trace_dir = pilot_dir / "shared_inputs" / "traces" / f"density_{row['density']}" / f"seed_{row['seed']}"
        for name, hash_key in files.items():
            path = trace_dir / name
            if not path.is_file() or sha(path) != row.get(hash_key):
                raise RuntimeError(f"Prior pilot trace integrity mismatch: {path}")
    return status, tree_bytes(pilot_dir)


def save_rows(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    pd.DataFrame(rows).to_csv(temporary, index=False)
    os.replace(temporary, path)


def load_rows(path: Path) -> list[dict]:
    return pd.read_csv(path).to_dict("records") if path.exists() else []


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, path)
def tree_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def completed_cell_index(manifest_rows: list[dict]) -> dict[tuple[str, int, int, str], int]:
    """Index only unique successful checkpoints; reject ambiguous manifests."""
    result: dict[tuple[str, int, int, str], int] = {}
    for row in manifest_rows:
        if str(row.get("status")) != "completed":
            continue
        key = (str(row["variant_id"]), int(float(row["density"])),
               int(float(row["seed"])), str(row["architecture"]))
        attempt_value = row.get("attempt", 1)
        attempt = 1 if attempt_value is None or pd.isna(attempt_value) else int(float(attempt_value))
        if key in result:
            raise RuntimeError(f"Duplicate completed checkpoint for {key}")
        result[key] = attempt
    return result


def validate_cell_checkpoint(
    cell_key: tuple[str, int, int, str],
    attempt: int,
    manifest_rows: list[dict],
    metric_rows: list[dict],
    opportunity_rows: list[dict],
    decision_rows: list[dict],
) -> None:
    """Require a complete, trace-consistent set of persisted cell artifacts."""
    def matches(rows: list[dict]) -> list[dict]:
        return [row for row in rows
                if (str(row.get("variant_id")), int(float(row.get("density", 0))),
                    int(float(row.get("seed", 0))), str(row.get("architecture"))) == cell_key
                and int(float(row.get("attempt", 1))) == attempt]

    manifest = [row for row in matches(manifest_rows)
                if str(row.get("status")) == "completed"]
    metrics = matches(metric_rows)
    opportunities = matches(opportunity_rows)
    decisions = matches(decision_rows)
    if len(manifest) != 1 or len(metrics) != 1 or len(opportunities) != 1:
        raise RuntimeError(f"Completed cell artifact count mismatch: {cell_key}")
    case_count = int(float(manifest[0]["case_count"]))
    if len(decisions) != case_count:
        raise RuntimeError(f"Completed cell decision count mismatch: {cell_key}")
    expected_hash = str(manifest[0].get("trace_sha256", ""))
    if not expected_hash or any(
        str(row.get("trace_sha256", "")) != expected_hash
        for row in [metrics[0], opportunities[0], *decisions]
    ):
        raise RuntimeError(f"Completed cell trace hash mismatch: {cell_key}")


def variants(base):
    result = [("baseline", "baseline", "baseline", base)]
    for seconds in (12.0, 30.0):
        policies = {name: replace(policy, freshness_window_seconds=seconds)
                    for name, policy in base.policies.items()}
        result.append((f"freshness_{int(seconds)}s", "freshness_window_seconds",
                       str(seconds), replace(base, policies=policies)))
    for sources in (1, 3):
        policies = dict(base.policies)
        policies["position_offset"] = replace(
            policies["position_offset"], required_sources=sources)
        result.append((f"position_sources_{sources}", "position_offset.required_sources",
                       str(sources), replace(base, policies=policies)))
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    out = args.output_dir.expanduser().resolve()
    base = load_config(ROOT / BASE_CONFIG)
    base.validate()
    if abs(base.network.packet_delivery_ratio - 0.98) > 1e-12:
        raise RuntimeError("Unexpected baseline packet delivery setting")
    if abs(base.detector.case_window_seconds - WINDOW) > 1e-12:
        raise RuntimeError("Unexpected runtime case window")
    if any(abs(p.freshness_window_seconds - 15.0) > 1e-12 for p in base.policies.values()):
        raise RuntimeError("Unexpected baseline evidence freshness setting")
    if base.policies["position_offset"].required_sources != 2:
        raise RuntimeError("Unexpected position_offset source threshold")
    if base.pbft.validators != ("rsu-1", "rsu-2", "rsu-3", "rsu-4") or base.pbft.max_byzantine != 1:
        raise RuntimeError("Unexpected historical V4 membership/fault budget")

    frozen_rel = [
        "results/urban_roundabout_campaign_corrected_final/effective_config.json",
        "results/urban_roundabout_campaign_corrected_final/combined/density_metrics_by_seed.csv",
        "results/urban_roundabout_campaign_corrected_final/combined/density_decisions.csv",
        "docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_VERIFIED_METRICS.csv",
        "sumo/urban_roundabout/rsus.json",
        "sumo/urban_roundabout/attacks.json",
        "sumo/urban_roundabout/urban_roundabout.sumocfg",
        "sumo/urban_roundabout/urban_roundabout.nod.xml",
        "sumo/urban_roundabout/urban_roundabout.edg.xml",
        "sumo/urban_roundabout/urban_roundabout.rou.xml",
        "src/vpuft/sumo/attacks.py",
        "src/vpuft/sumo/runner.py",
        "src/vpuft/sumo/density.py",
        "src/vpuft/sumo/detector.py",
        "src/vpuft/sumo/prepare.py",
        "src/vpuft/sumo/sensors.py",
        "src/vpuft/architectures/base.py",
        "src/vpuft/architectures/centralized.py",
        "src/vpuft/architectures/distributed_extension.py",
        "src/vpuft/domain.py",
        "src/vpuft/consensus.py",
        "src/vpuft/config.py",
        "src/vpuft/crypto.py",
        "src/vpuft/evidence.py",
        "src/vpuft/weighting.py",
        "src/vpuft/trace.py",
        "src/vpuft/qualification.py",
        "src/vpuft/density_campaign.py",
        "src/vpuft/metrics.py",
        "src/vpuft/state_aware_evaluation.py",
        "src/vpuft/network.py",
        "scripts/sensitivity_opportunities.py",
        "scripts/analyze_final_scenario5_sensitivity.py",
        "docs/final_scenario5_sensitivity/SENSITIVITY_REPLICATION_PREREGISTRATION.md",
        "scripts/run_final_scenario5_sensitivity_replication.py",
    ]
    input_hashes = {name: sha(ROOT / name) for name in frozen_rel}
    branch = git_value("rev-parse", "--abbrev-ref", "HEAD")
    code_commit = git_value("rev-parse", "HEAD")
    if branch != "research/final-scenario5":
        raise RuntimeError(f"Expected research/final-scenario5, found {branch}")
    plan_hash = input_hashes["docs/final_scenario5_sensitivity/SENSITIVITY_REPLICATION_PREREGISTRATION.md"]
    context = {
        "design": "scenario5_sensitivity_replication_2026-11-16_v1",
        "accepted_baseline_commit": "c1878e8d6bef7a44830d8b44d5f55d47d5810f3c",
        "pilot_commit": "f52322f54a0bc4aacf46ce00fa640b7c297ebcd1",
        "execution_commit": code_commit,
        "execution_branch": branch,
        "preregistration_sha256": plan_hash,
        "source_and_input_sha256": input_hashes,
        "densities": list(DENSITIES), "seeds": list(SEEDS),
        "configuration_ids": [x[0] for x in variants(base)],
        "architectures": ["C100", "Distributed"],
        "expected_runs": EXPECTED_RUNS,
        "raw_output_cap_bytes": MAX_OUTPUT_BYTES,
        "wall_time_cap_seconds": MAX_WALL_SECONDS,
    }
    volume_root = out.anchor or str(Path.home().anchor)
    free_bytes = shutil.disk_usage(volume_root).free
    prior_pilot = ROOT / "results/final_scenario5_sensitivity/pilot_2026-11-16"
    pilot_status, pilot_bytes = verify_completed_pilot(prior_pilot)
    cloud_root = os.environ.get("OneDrive")
    output_under_onedrive = bool(cloud_root and os.path.commonpath([str(out), str(Path(cloud_root).resolve())]).lower() == str(Path(cloud_root).resolve()).lower())
    report = {
        "output_dir": str(out), "free_bytes": free_bytes,
        "minimum_free_bytes": MIN_FREE_BYTES, "output_cap_bytes": MAX_OUTPUT_BYTES,
        "prior_pilot_bytes": pilot_bytes, "prior_pilot_status": pilot_status,
        "output_under_onedrive": output_under_onedrive,
        "expected_runs": EXPECTED_RUNS,
        "expected_trace_generations": len(DENSITIES) * len(SEEDS),
        "fresh_seed_set": list(SEEDS),
    }
    if args.preflight:
        if out.exists():
            raise RuntimeError(f"Preflight target already exists; choose a new target: {out}")
        if free_bytes < MIN_FREE_BYTES:
            raise RuntimeError(f"Insufficient free space: {free_bytes} < {MIN_FREE_BYTES}")
        if output_under_onedrive:
            raise RuntimeError("Raw replication output must be outside OneDrive")
        print(json.dumps({"preflight": "passed", **report}, indent=2))
        return
    if free_bytes < MIN_FREE_BYTES:
        raise RuntimeError(f"Insufficient free space: {free_bytes} < {MIN_FREE_BYTES}")
    if output_under_onedrive:
        raise RuntimeError("Raw replication output must be outside OneDrive")
    context_path = out / "RUN_CONTEXT.json"
    if args.resume:
        if not out.is_dir() or not context_path.exists():
            raise RuntimeError("Cannot resume: target or RUN_CONTEXT.json is missing")
        existing_context = json.loads(context_path.read_text(encoding="utf-8"))
        if existing_context != context:
            raise RuntimeError("Cannot resume: source/config/preregistration context changed")
    else:
        if out.exists():
            raise RuntimeError(f"Output exists; use --resume only after inspecting it: {out}")
        out.mkdir(parents=True)
        atomic_json(context_path, context)

    frozen_path = out / "FROZEN_INPUT_HASHES.json"
    configs_path = out / "SENSITIVITY_EFFECTIVE_CONFIGS.json"
    config_rows = {}
    for variant_id, factor, level, cfg in variants(base):
        effective_config = asdict(cfg)
        config_rows[variant_id] = {
            "factor": factor, "level": level,
            "effective_config": effective_config,
            "effective_config_sha256": hashlib.sha256(
                json.dumps(effective_config, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "architecture_scope": "C100 and Distributed",
        }
    config_rows["baseline"]["baseline_values"] = {
        "freshness_window_seconds": 15.0,
        "position_offset_required_sources": 2,
        "independent_root_requirements_unchanged": True,
    }
    if args.resume:
        if json.loads(frozen_path.read_text(encoding="utf-8")) != context["source_and_input_sha256"]:
            raise RuntimeError("Frozen input hash manifest mismatch on resume")
        if json.loads(configs_path.read_text(encoding="utf-8")) != config_rows:
            raise RuntimeError("Effective configurations changed on resume")
    else:
        atomic_json(frozen_path, context["source_and_input_sha256"])
        atomic_json(configs_path, config_rows)

    manifest_path = out / "SENSITIVITY_RUN_MANIFEST.csv"
    metrics_path = out / "SENSITIVITY_METRICS_BY_SEED.csv"
    decisions_path = out / "SENSITIVITY_CASE_DECISIONS.csv"
    opportunities_path = out / "SENSITIVITY_FIXED_OPPORTUNITIES.csv"
    manifest_rows = load_rows(manifest_path) if args.resume else []
    metric_rows = load_rows(metrics_path) if args.resume else []
    decision_rows = load_rows(decisions_path) if args.resume else []
    opportunity_rows = load_rows(opportunities_path) if args.resume else []
    traces_path = out / "SENSITIVITY_TRACE_MANIFEST.json"
    trace_records = json.loads(traces_path.read_text(encoding="utf-8")).get("traces", []) if args.resume and traces_path.exists() else []
    trace_index = {(int(x["density"]), int(x["seed"])): x for x in trace_records}
    status_path = out / "replication_status.json"
    prior_elapsed = 0.0
    if args.resume and status_path.exists():
        prior_elapsed = float(json.loads(status_path.read_text(encoding="utf-8")).get("active_elapsed_seconds", 0.0))
    started = time.monotonic()
    run_count = 0
    (out / "RUN_PREFLIGHT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    atomic_json(status_path, {"status": "running", "completed_runs": 0,
                              "expected_architecture_runs": EXPECTED_RUNS,
                              "active_elapsed_seconds": prior_elapsed})

    scenario_base = ROOT / "sumo/urban_roundabout"
    scenario_manifest_path = out / "DENSITY_SCENARIO_MANIFEST.json"
    if args.resume and scenario_manifest_path.exists():
        scenario_records = json.loads(scenario_manifest_path.read_text(encoding="utf-8"))["scenarios"]
    else:
        scenario_records = []
    scenario_index = {int(x["density"]): x for x in scenario_records}
    scenario_dirs = {}

    def directory_hashes(directory: Path) -> dict[str, str]:
        return {p.relative_to(directory).as_posix(): sha(p)
                for p in sorted(directory.rglob("*")) if p.is_file()}

    for density in DENSITIES:
        if prior_elapsed + time.monotonic() - started >= MAX_WALL_SECONDS:
            raise TimeoutError("One-hour cumulative wall-time cap reached before trace preparation")
        if shutil.disk_usage(volume_root).free < MIN_FREE_BYTES:
            raise RuntimeError("Minimum free-space reserve reached before trace preparation")
        record = scenario_index.get(density)
        if record is not None:
            generated = out / record["relative_directory"]
            if not generated.is_dir() or directory_hashes(generated) != record["file_sha256"]:
                raise RuntimeError(f"Generated scenario integrity mismatch for density {density}")
        else:
            parent = out / "shared_inputs" / "generated_scenarios"
            parent.mkdir(parents=True, exist_ok=True)
            attempt = 1
            while True:
                generated = parent / f"vehicles_{density}_attempt{attempt:02d}"
                if not generated.exists():
                    break
                attempt += 1
            density_manifest = build_density_scenario(
                scenario_base, generated, vehicle_count=density,
                attack_vehicle_ratio=base.density_campaign.attack_vehicle_ratio,
                departure_window_seconds=base.density_campaign.departure_window_seconds,
                end_time_seconds=base.sumo.end_time_seconds,
            )
            record = {
                "density": density,
                "relative_directory": generated.relative_to(out).as_posix(),
                "builder_manifest": asdict(density_manifest),
                "file_sha256": directory_hashes(generated),
            }
            scenario_records.append(record)
            scenario_index[density] = record
            atomic_json(scenario_manifest_path, {"scenarios": scenario_records})
        scenario_dirs[density] = generated

    trace_paths = {}
    for density in DENSITIES:
        for seed in SEEDS:
            key = (density, seed)
            record = trace_index.get(key)
            if record is not None:
                trace_dir = out / record["trace_relative_directory"]
                checks = {
                    "shared_detection_trace.jsonl": record["trace_sha256"],
                    "generated_messages.csv": record["generated_messages_sha256"],
                    "attack_ground_truth.csv": record["attack_ground_truth_sha256"],
                    "mobility_trace.csv": record["mobility_trace_sha256"],
                    "scenario_manifest.json": record["scenario_manifest_sha256"],
                }
                if not trace_dir.is_dir() or any(not (trace_dir / name).is_file() or sha(trace_dir / name) != digest
                                                 for name, digest in checks.items()):
                    raise RuntimeError(f"Trace integrity mismatch: {density}/{seed}")
                trace_paths[key] = trace_dir
                continue
            if prior_elapsed + time.monotonic() - started >= MAX_WALL_SECONDS:
                raise TimeoutError("One-hour cumulative wall-time cap reached during trace generation")
            if shutil.disk_usage(volume_root).free < MIN_FREE_BYTES:
                raise RuntimeError("Minimum free-space reserve reached during trace generation")
            parent = out / "shared_inputs" / "traces" / f"density_{density}"
            parent.mkdir(parents=True, exist_ok=True)
            attempt = 1
            while True:
                trace_dir = parent / f"seed_{seed}_attempt{attempt:02d}"
                if not trace_dir.exists():
                    break
                attempt += 1
            trace_start = time.monotonic()
            trace_manifest = run_sumo_trace(
                base, scenario_directory=scenario_dirs[density], output_directory=trace_dir, seed=seed)
            elapsed = time.monotonic() - trace_start
            if int(trace_manifest["counts"]["unique_vehicles_observed"]) != density:
                raise RuntimeError(f"Density mismatch in trace {density}/{seed}")
            trace_record = {
                "density": density, "seed": seed,
                "trace_relative_directory": trace_dir.relative_to(out).as_posix(),
                "generated_scenario_relative_directory": scenario_dirs[density].relative_to(out).as_posix(),
                "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                "generated_messages_sha256": sha(trace_dir / "generated_messages.csv"),
                "attack_ground_truth_sha256": sha(trace_dir / "attack_ground_truth.csv"),
                "mobility_trace_sha256": sha(trace_dir / "mobility_trace.csv"),
                "scenario_manifest_sha256": sha(trace_dir / "scenario_manifest.json"),
                "unique_vehicles": trace_manifest["counts"]["unique_vehicles_observed"],
                "cases_in_raw_detection_trace": trace_manifest["counts"]["cases"],
                "v2x_messages": trace_manifest["counts"]["v2x_messages"],
                "detection_events": trace_manifest["counts"]["detection_events"],
                "trace_wall_seconds": elapsed,
            }
            trace_records.append(trace_record)
            trace_index[key] = trace_record
            trace_paths[key] = trace_dir
            atomic_json(traces_path, {"traces": trace_records})
            if tree_bytes(out) > MAX_OUTPUT_BYTES:
                raise RuntimeError("3 GB raw output cap reached after trace generation")

    if len(trace_records) != len(DENSITIES) * len(SEEDS):
        raise RuntimeError("Expected twelve shared traces")
    key_registry = KeyRegistry(base.security.deterministic_master_seed)
    variant_list = variants(base)
    def row_key(row):
        return (str(row.get("variant_id")), int(float(row.get("density", 0))),
                int(float(row.get("seed", 0))), str(row.get("architecture")))
    def row_attempt(row):
        value = row.get("attempt", 1)
        return 1 if value is None or pd.isna(value) else int(float(value))
    completed_cells = completed_cell_index(manifest_rows)
    for density in DENSITIES:
        namespace = f"urban_roundabout-vehicles-{density}"
        for seed in SEEDS:
            if prior_elapsed + time.monotonic() - started >= MAX_WALL_SECONDS:
                atomic_json(status_path, {"status":"paused_wall_cap", "completed_runs":len(completed_cells),
                                  "expected_architecture_runs":EXPECTED_RUNS,
                                  "active_elapsed_seconds":prior_elapsed + time.monotonic() - started})
                raise TimeoutError("One-hour cumulative wall-time cap reached during replay")
            trace_dir = trace_paths[(density, seed)]
            events = read_events_jsonl(trace_dir / "shared_detection_trace.jsonl")
            bundle = build_trace_bundle(
                events, key_registry, window_seconds=WINDOW, namespace=namespace)
            cases = bundle.rsu_cases
            if not cases:
                raise RuntimeError(f"No RSU cases in trace {density}/{seed}")
            truth = {case.case_id: case.ground_truth_malicious for case in cases}
            opened = {case.case_id: case.opened_at for case in cases}
            case_by_id = {case.case_id: case for case in cases}
            raw_messages = pd.read_csv(trace_dir / "generated_messages.csv")
            mobility = pd.read_csv(trace_dir / "mobility_trace.csv")
            base_emission_time = build_base_emission_times(mobility.to_dict("records"), seed=seed)
            attack_messages = raw_messages[
                raw_messages["ground_truth_malicious"].astype(str).str.lower().isin(["true", "1"])
            ].copy()
            for variant_id, factor, level, cfg in variant_list:
                arch_specs = []
                if factor != "C100_backhaul_ms":
                    dist_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=0.0))
                    c100_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=100.0))
                    arch_specs = [
                        ("Distributed", DistributedRSUExtendedVPUFT(dist_cfg, key_registry), dist_cfg),
                        ("C100", CentralizedVPUFT(c100_cfg, key_registry), c100_cfg),
                    ]
                else:
                    delay = float(level)
                    c100_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=delay))
                    arch_specs = [("C100", CentralizedVPUFT(c100_cfg, key_registry), c100_cfg)]

                for architecture, instance, run_cfg in arch_specs:
                    cell_key = (variant_id, density, seed, architecture)
                    if cell_key in completed_cells:
                        completed_attempt = completed_cells[cell_key]
                        validate_cell_checkpoint(
                            cell_key, completed_attempt, manifest_rows, metric_rows,
                            opportunity_rows, decision_rows)
                        continue
                    prior_attempts = [row_attempt(r) for rows in (manifest_rows, metric_rows, decision_rows, opportunity_rows) for r in rows if row_key(r)==cell_key]
                    attempt = max(prior_attempts, default=0) + 1
                    if prior_elapsed + time.monotonic() - started >= MAX_WALL_SECONDS:
                        atomic_json(status_path, {"status":"paused_wall_cap", "completed_runs":len(completed_cells),
                                          "expected_architecture_runs":EXPECTED_RUNS,
                                          "active_elapsed_seconds":prior_elapsed + time.monotonic() - started})
                        raise TimeoutError("One-hour cumulative wall-time cap reached before cell")
                    if shutil.disk_usage(volume_root).free < MIN_FREE_BYTES:
                        atomic_json(status_path, {
                            "status": "paused_low_disk", "completed_runs": len(completed_cells),
                            "expected_architecture_runs": EXPECTED_RUNS,
                            "active_elapsed_seconds": prior_elapsed + time.monotonic() - started,
                            "free_bytes": shutil.disk_usage(volume_root).free,
                        })
                        raise RuntimeError("Minimum free-space reserve reached before architecture cell")
                    run_count += 1
                    run_started = time.monotonic()
                    try:
                        result, cpu_seconds, peak_kb = _run_measured(
                            instance, cases, seed, architecture)
                        _assert_transport_causality(
                            result,
                            queue_rate_bytes_per_second=run_cfg.network.queue_rate_bytes_per_second)
                        metric = decision_metrics(result, truth, opened)
                        metric.update({
                            "variant_id": variant_id, "factor": factor, "level": level, "attempt": attempt,
                            "density": density, "seed": seed, "architecture": architecture,
                            "backhaul_extra_latency_ms": run_cfg.network.central_backhaul_extra_latency_ms,
                            "cpu_time_seconds": cpu_seconds, "peak_memory_kb": peak_kb,
                            "case_count": len(result.decisions),
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                        })
                        metric_rows.append(metric)

                        local_decisions = []
                        for decision in result.decisions:
                            case = case_by_id[decision.case_id]
                            local_decisions.append({
                                "variant_id": variant_id, "factor": factor, "level": level, "attempt": attempt,
                                "density": density, "seed": seed, "architecture": architecture,
                                "case_id": decision.case_id, "vehicle_id": decision.vehicle_id,
                                "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                                "attack_type": case.attack_type.value,
                                "ground_truth_malicious": int(case.ground_truth_malicious),
                                "committed": int(decision.committed),
                                "predicted_revoked": int(
                                    decision.committed and decision.new_state.value == "revoked"),
                                "new_state": decision.new_state.value,
                                "reason": decision.reason,
                                "opened_at": case.opened_at,
                                "detected_at": decision.detected_at,
                                "qualified_at": decision.qualified_at,
                                "finalized_at": decision.finalized_at,
                                "ledger_available_at": decision.ledger_available_at,
                            })
                        decision_rows.extend(local_decisions)

                        temp = pd.DataFrame([{
                            "case_id": row["case_id"], "vehicle_id": row["vehicle_id"],
                            "seed": seed, "architecture": architecture,
                            "ground_truth_malicious": row["ground_truth_malicious"],
                            "committed": row["committed"], "new_state": row["new_state"],
                            "topology": "urban_roundabout", "vehicle_count": density,
                            "backhaul_extra_latency_ms": metric["backhaul_extra_latency_ms"],
                        } for row in local_decisions])
                        independent = state_aware_first_revocation_metrics(
                            temp, window_seconds=WINDOW)
                        if len(independent) != 1:
                            raise RuntimeError("Method B evaluator did not produce one run row")
                        check = independent.iloc[0]
                        for name in ("TP", "FP", "TN", "FN",
                                     "excluded_post_revocation_windows"):
                            expected_name = "excluded_post_revocation_cases" if name.startswith("excluded") else name
                            expected = int(metric[expected_name])
                            actual = int(check["excluded_post_revocation_windows"] if name.startswith("excluded") else check[name])
                            if expected != actual:
                                raise RuntimeError(f"Method B mismatch {name}: {expected} != {actual}")

                        observation_rows = [{
                            "message_id": event.message_id, "case_id": event.case_id,
                            "seed": event.seed, "vehicle_id": event.vehicle_id,
                            "detected_at": event.detected_at,
                            "source_kind": event.source_kind.value,
                            "observation_root_id": event.observation_root_id,
                        } for event in bundle.events]
                        fixed = evaluate_attack_opportunities(
                            attack_messages.to_dict("records"), observation_rows,
                            local_decisions, base_emission_time, seed=seed,
                            window_seconds=WINDOW)
                        opportunity_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level,
                            "attempt": attempt, "density": density, "seed": seed,
                            "architecture": architecture, **fixed,
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                        })
                        elapsed = time.monotonic() - run_started
                        manifest_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level, "attempt": attempt,
                            "density": density, "seed": seed, "architecture": architecture,
                            "status": "completed", "case_count": len(result.decisions),
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                            "cpu_time_seconds": cpu_seconds, "wall_seconds": elapsed,
                            "messages_total": metric["messages_total"],
                            "bytes_total": metric["bytes_total"],
                            "pdr": metric["packet_delivery_ratio"],
                            "failure": "",
                        })
                    except Exception as exc:
                        manifest_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level, "attempt": attempt,
                            "density": density, "seed": seed, "architecture": architecture,
                            "status": "failed", "case_count": 0,
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                            "failure": repr(exc),
                        })
                        save_rows(out / "SENSITIVITY_RUN_MANIFEST.csv", manifest_rows)
                        atomic_json(status_path, {
                            "status": "failed", "completed_runs": len(completed_cells),
                            "attempts_this_session": run_count,
                            "failed_cell": manifest_rows[-1],
                            "expected_architecture_runs": EXPECTED_RUNS,
                            "active_elapsed_seconds": prior_elapsed + time.monotonic() - started,
                            "output_bytes": tree_bytes(out),
                        })
                        raise

                    save_rows(out / "SENSITIVITY_METRICS_BY_SEED.csv", metric_rows)
                    save_rows(out / "SENSITIVITY_CASE_DECISIONS.csv", decision_rows)
                    save_rows(out / "SENSITIVITY_FIXED_OPPORTUNITIES.csv", opportunity_rows)
                    save_rows(out / "SENSITIVITY_RUN_MANIFEST.csv", manifest_rows)
                    if tree_bytes(out) > MAX_OUTPUT_BYTES:
                        raise RuntimeError("3 GB output cap reached")
                    completed_cells[cell_key] = attempt
                    atomic_json(status_path, {
                        "status": "running", "completed_runs": len(completed_cells),
                        "expected_architecture_runs": EXPECTED_RUNS,
                        "attempts_this_session": run_count,
                        "active_elapsed_seconds": prior_elapsed + time.monotonic() - started,
                        "output_bytes": tree_bytes(out),
                    })

    if len(completed_cells) != EXPECTED_RUNS:
        atomic_json(status_path, {"status":"incomplete", "completed_runs":len(completed_cells),
                                  "expected_architecture_runs":EXPECTED_RUNS,
                                  "active_elapsed_seconds":prior_elapsed + time.monotonic() - started,
                                  "output_bytes":tree_bytes(out)})
        raise RuntimeError(f"Incomplete campaign: {len(completed_cells)}/{EXPECTED_RUNS} completed cells")
    atomic_json(traces_path, {"traces": trace_records})
    elapsed_total = prior_elapsed + time.monotonic() - started
    atomic_json(status_path, {"status":"completed", "completed_runs":len(completed_cells),
                              "expected_architecture_runs":EXPECTED_RUNS,
                              "trace_count":len(trace_records),
                              "attempts_this_session":run_count,
                              "active_elapsed_seconds":elapsed_total,
                              "output_bytes":tree_bytes(out)})
    print(json.dumps({"status": "completed", "completed_cells": len(completed_cells), "attempts_this_session": run_count, "output": str(out)}, indent=2))


if __name__ == "__main__":
    main()
