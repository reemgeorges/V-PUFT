from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import ResearchConfig
from ..runner import run_trace_campaign
from ..sensitivity import select_weights
from ..trace import read_events_jsonl, write_events_jsonl
from .runner import run_sumo_trace


SEED_REQUIRED_OUTPUTS = (
    "run_summary.json",
    "scenario_manifest.json",
    "shared_detection_trace.jsonl",
    "evidence_campaign.csv",
)

ARCHITECTURE_REQUIRED_OUTPUTS = (
    "run_manifest.json",
    "architecture_summary.csv",
    "metrics_by_seed.csv",
    "decisions.csv",
    "evidence_campaign.csv",
)

SENSITIVITY_REQUIRED_OUTPUTS = (
    "selected_weights.json",
    "candidate_ranking.csv",
    "bootstrap_parameter_summary.csv",
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_run_is_complete(seed_dir: Path, expected_seed: int) -> bool:
    if any(not (seed_dir / name).exists() for name in SEED_REQUIRED_OUTPUTS):
        return False
    try:
        summary = _read_json(seed_dir / "run_summary.json")
        manifest = _read_json(seed_dir / "scenario_manifest.json")
        if not bool(summary.get("completed")):
            return False
        if int(summary.get("seed")) != int(expected_seed):
            return False
        if int(manifest.get("seed")) != int(expected_seed):
            return False
        trace_path = seed_dir / "shared_detection_trace.jsonl"
        if trace_path.stat().st_size <= 0:
            return False
        # Parse the trace once so a truncated final line is not treated as complete.
        read_events_jsonl(trace_path)
        return True
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _architecture_run_is_complete(architecture_dir: Path, expected_seeds: list[int]) -> bool:
    if any(not (architecture_dir / name).exists() for name in ARCHITECTURE_REQUIRED_OUTPUTS):
        return False
    try:
        manifest = _read_json(architecture_dir / "run_manifest.json")
        actual_seeds = sorted(int(seed) for seed in manifest.get("seeds", []))
        return actual_seeds == sorted(set(int(seed) for seed in expected_seeds))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _sensitivity_run_is_complete(sensitivity_dir: Path) -> bool:
    if any(not (sensitivity_dir / name).exists() for name in SENSITIVITY_REQUIRED_OUTPUTS):
        return False
    try:
        selected = _read_json(sensitivity_dir / "selected_weights.json")
        weights = selected.get("weights", {})
        return all(name in weights for name in ("C", "rho", "F", "Q", "eta"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def run_sumo_campaign(
    config: ResearchConfig,
    *,
    scenario_directory: str | Path,
    output_directory: str | Path,
    seeds: list[int],
    run_sensitivity: bool = False,
    candidates: int = 1200,
    bootstrap_repeats: int = 200,
    min_recall: float = 0.90,
    max_frr: float = 0.08,
    resume: bool = False,
) -> dict:
    if not seeds:
        raise ValueError("At least one SUMO seed is required")

    normalized_seeds = list(dict.fromkeys(int(seed) for seed in seeds))
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)
    traces_dir = output / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)

    all_events = []
    trace_manifests = []
    resumed_seeds: list[int] = []
    executed_seeds: list[int] = []

    for seed in normalized_seeds:
        seed_dir = traces_dir / f"seed_{seed}"
        if resume and _seed_run_is_complete(seed_dir, seed):
            manifest = _read_json(seed_dir / "scenario_manifest.json")
            resumed_seeds.append(seed)
            print(f"[resume] completed SUMO seed {seed}; reusing {seed_dir}", flush=True)
        else:
            if resume and seed_dir.exists():
                print(f"[resume] seed {seed} is incomplete; rerunning it", flush=True)
            else:
                print(f"[run] SUMO seed {seed}", flush=True)
            manifest = run_sumo_trace(
                config,
                scenario_directory=scenario_directory,
                output_directory=seed_dir,
                seed=seed,
            )
            executed_seeds.append(seed)

        trace_manifests.append(manifest)
        all_events.extend(read_events_jsonl(seed_dir / "shared_detection_trace.jsonl"))

    combined_trace = output / "shared_detection_trace_all_seeds.jsonl"
    write_events_jsonl(all_events, combined_trace)

    architecture_dir = output / "architecture_campaign"
    architecture_resumed = resume and _architecture_run_is_complete(architecture_dir, normalized_seeds)
    if architecture_resumed:
        print("[resume] architecture campaign is complete; reusing it", flush=True)
        architecture_manifest = _read_json(architecture_dir / "run_manifest.json")
    else:
        print("[run] replaying the combined trace through the three architectures", flush=True)
        architecture_manifest = run_trace_campaign(config, combined_trace, architecture_dir)

    sensitivity_result = None
    sensitivity_resumed = False
    sensitivity_dir = output / "sensitivity"
    if run_sensitivity:
        if len(set(normalized_seeds)) < 4:
            raise ValueError("Sensitivity analysis requires at least four independent SUMO seeds")
        sensitivity_resumed = resume and _sensitivity_run_is_complete(sensitivity_dir)
        if sensitivity_resumed:
            print("[resume] sensitivity analysis is complete; reusing selected weights", flush=True)
            sensitivity_result = _read_json(sensitivity_dir / "selected_weights.json")
        else:
            print("[run] V-PUFT weight sensitivity analysis", flush=True)
            sensitivity_result = select_weights(
                architecture_dir / "evidence_campaign.csv",
                sensitivity_dir,
                config,
                candidates=candidates,
                bootstrap_repeats=bootstrap_repeats,
                min_recall=min_recall,
                max_frr=max_frr,
            )

    manifest = {
        "seeds": normalized_seeds,
        "combined_trace": str(combined_trace),
        "trace_manifests": trace_manifests,
        "architecture_campaign": architecture_manifest,
        "sensitivity_completed": sensitivity_result is not None,
        "selected_weights": sensitivity_result.get("weights") if sensitivity_result else None,
        "resume": {
            "enabled": resume,
            "resumed_seeds": resumed_seeds,
            "executed_seeds": executed_seeds,
            "architecture_resumed": architecture_resumed,
            "sensitivity_resumed": sensitivity_resumed,
        },
    }
    (output / "sumo_campaign_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def run_multi_topology_campaign(
    config: ResearchConfig,
    *,
    scenario_directories: list[str | Path],
    output_directory: str | Path,
    seeds: list[int],
    run_sensitivity: bool = False,
    candidates: int = 1200,
    bootstrap_repeats: int = 200,
    min_recall: float = 0.90,
    max_frr: float = 0.08,
    resume: bool = False,
) -> dict:
    """Run the same seed set on multiple SUMO road topologies, with safe resume support."""
    import pandas as pd

    normalized_seeds = list(dict.fromkeys(int(seed) for seed in seeds))
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)
    topology_manifests = []
    summary_frames = []
    evidence_frames = []

    for scenario_directory in scenario_directories:
        scenario = Path(scenario_directory).resolve()
        topology = scenario.name
        topology_output = output / topology
        print(f"\n=== topology: {topology} ===", flush=True)
        manifest = run_sumo_campaign(
            config,
            scenario_directory=scenario,
            output_directory=topology_output,
            seeds=normalized_seeds,
            run_sensitivity=False,
            resume=resume,
        )
        topology_manifests.append({"topology": topology, "manifest": manifest})

        summary_path = topology_output / "architecture_campaign" / "architecture_summary.csv"
        if summary_path.exists():
            frame = pd.read_csv(summary_path)
            frame.insert(0, "topology", topology)
            summary_frames.append(frame)

        evidence_path = topology_output / "architecture_campaign" / "evidence_campaign.csv"
        if evidence_path.exists():
            frame = pd.read_csv(evidence_path)
            frame.insert(0, "topology", topology)
            evidence_frames.append(frame)

    topology_summary = pd.concat(summary_frames, ignore_index=True) if summary_frames else pd.DataFrame()
    topology_summary.to_csv(output / "topology_architecture_summary.csv", index=False)

    combined_evidence = pd.concat(evidence_frames, ignore_index=True) if evidence_frames else pd.DataFrame()
    combined_evidence_path = output / "all_topologies_evidence_campaign.csv"
    combined_evidence.to_csv(combined_evidence_path, index=False)

    sensitivity_result = None
    sensitivity_resumed = False
    sensitivity_dir = output / "sensitivity"
    if run_sensitivity:
        if len(set(normalized_seeds)) < 4:
            raise ValueError("Sensitivity analysis requires at least four independent seeds")
        sensitivity_resumed = resume and _sensitivity_run_is_complete(sensitivity_dir)
        if sensitivity_resumed:
            print("[resume] multi-topology sensitivity is complete; reusing selected weights", flush=True)
            sensitivity_result = _read_json(sensitivity_dir / "selected_weights.json")
        else:
            print("[run] multi-topology V-PUFT sensitivity analysis", flush=True)
            sensitivity_result = select_weights(
                combined_evidence_path,
                sensitivity_dir,
                config,
                candidates=candidates,
                bootstrap_repeats=bootstrap_repeats,
                min_recall=min_recall,
                max_frr=max_frr,
            )

    result = {
        "topologies": [Path(path).name for path in scenario_directories],
        "seeds": normalized_seeds,
        "topology_manifests": topology_manifests,
        "summary": str(output / "topology_architecture_summary.csv"),
        "combined_evidence": str(combined_evidence_path),
        "sensitivity_completed": sensitivity_result is not None,
        "selected_weights": sensitivity_result.get("weights") if sensitivity_result else None,
        "resume": {
            "enabled": resume,
            "sensitivity_resumed": sensitivity_resumed,
        },
    }
    (output / "multi_topology_manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
