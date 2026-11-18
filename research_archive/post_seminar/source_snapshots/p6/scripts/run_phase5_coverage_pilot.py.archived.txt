"""Paired pilot on held-out SUMO seeds after placement preregistration."""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pandas as pd

from run_phase2_ablation import decision_frame, measured_run, metric_row
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.sumo.runner import run_sumo_trace
from vpuft.trace import build_trace_bundle, read_events_jsonl

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase2/baseline_regenerated"
OUT = ROOT / "results/post_seminar_phase5"
CONFIG = ROOT / "results/post_seminar_phase2/phase2_effective_baseline_config.json"
CELLS = ((20, 1007), (100, 1007))


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    plan = json.loads((OUT / "placement_preregistered.json").read_text())
    config = load_config(CONFIG)
    metrics = []
    for density, seed in CELLS:
        base_trace_dir = BASE / f"traces/urban_roundabout/vehicles_{density}/seed_{seed}"
        scenario_src = BASE / f"generated_scenarios/urban_roundabout/vehicles_{density}"
        scenario = OUT / f"scenarios/vehicles_{density}"
        if not scenario.exists():
            shutil.copytree(scenario_src, scenario)
            (scenario / "rsus.json").write_text(json.dumps(plan["candidate_rsus"], indent=2))
            poi = ['<?xml version="1.0" encoding="UTF-8"?>', '<additional>']
            for rsu in plan["candidate_rsus"]:
                poi.append(f'<poi id="{rsu["id"]}" x="{rsu["x"]}" y="{rsu["y"]}" color="0,0,255" layer="10" type="RSU"/>')
            poi.append('</additional>')
            (scenario / "rsus.add.xml").write_text("\n".join(poi))
        trace_dir = OUT / f"pilot/vehicles_{density}/seed_{seed}"
        if not (trace_dir / "scenario_manifest.json").exists():
            run_sumo_trace(config, scenario_directory=scenario, output_directory=trace_dir, seed=seed)
        for name in ("mobility_trace.csv", "generated_messages.csv", "attack_ground_truth.csv"):
            if sha(base_trace_dir / name) != sha(trace_dir / name):
                raise AssertionError(f"Paired input mismatch: density={density} seed={seed} {name}")
        trace = trace_dir / "shared_detection_trace.jsonl"
        bundle = build_trace_bundle(
            read_events_jsonl(trace), KeyRegistry(config.security.deterministic_master_seed),
            window_seconds=config.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        for variant, diverse in (("C1_placement_B0", False), ("C2_placement_B1", True)):
            ext = replace(config.distributed_extension, coordinator_strategy="first_observer_then_hash",
                          cache_verified_evidence_bundle=False, diversity_aware_root_assignment=diverse,
                          provenance_safe_observer_diversity=False)
            result, cpu, wall, peak = measured_run(replace(config, distributed_extension=ext), bundle.rsu_cases, seed)
            decisions = decision_frame(result, bundle.rsu_cases, density=density, seed=seed, variant=variant)
            metrics.append(metric_row(result, bundle.rsu_cases, decisions, density=density, seed=seed,
                                      variant=variant, cpu=cpu, wall=wall, peak=peak, acquisition={}))
            decisions.to_csv(trace_dir / f"{variant}_decisions.csv", index=False)
        print(f"paired pilot completed density={density} seed={seed}", flush=True)
    pd.DataFrame(metrics).to_csv(OUT / "pilot_metrics.csv", index=False)


if __name__ == "__main__":
    main()
