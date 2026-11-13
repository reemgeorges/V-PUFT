"""Generate fresh training mobility and preregister two sensing-only RSUs."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np
import pandas as pd

from vpuft.config import load_config
from vpuft.sumo.runner import run_sumo_trace

ROOT = Path(__file__).resolve().parents[1]
FROZEN = Path(r"C:\Users\reemg\OneDrive\Desktop\master\6\v10")
OUT = ROOT / "results/rsu8_pilot"
TRAIN_SEEDS = (2001, 2002, 2003, 2004, 2005, 2006)
HELDOUT_SEEDS = (2101, 2102)
DENSITIES = (20, 60, 100)
RADIUS_M = 450.0
OFFSET = 500.0
WITNESS_POOL = tuple(f"rsu-{i}" for i in range(1, 7))


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def phase6_rsus() -> list[dict]:
    source = json.loads((FROZEN / "results/post_seminar_phase6/placement_preregistered.json").read_text())
    rsus = [dict(item) for item in source["candidate_rsus"]]
    assert [item["id"] for item in rsus] == [f"rsu-{i}" for i in range(1, 7)]
    assert [(rsus[4]["x"], rsus[4]["y"]), (rsus[5]["x"], rsus[5]["y"])] == [(-150.0, 500.0), (200.0, -500.0)]
    return rsus


def write_rsu_files(scenario: Path, rsus: list[dict]) -> None:
    (scenario / "rsus.json").write_text(json.dumps(rsus, indent=2), encoding="utf-8")
    root = ET.Element("additional")
    for rsu in rsus:
        ET.SubElement(root, "poi", {
            "id": rsu["id"], "x": str(rsu["x"]), "y": str(rsu["y"]),
            "color": "0,0,255", "layer": "10", "type": "RSU",
        })
    ET.ElementTree(root).write(scenario / "rsus.add.xml", encoding="UTF-8", xml_declaration=True)


def scenario_for(density: int, placement: list[dict]) -> Path:
    target = OUT / "scenarios" / "C1_train" / f"vehicles_{density}"
    source = FROZEN / "results/post_seminar_phase2/baseline_regenerated/generated_scenarios/urban_roundabout" / f"vehicles_{density}"
    if not target.exists():
        shutil.copytree(source, target)
    write_rsu_files(target, placement)
    return target


def generate_training() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    config_path = FROZEN / "results/post_seminar_phase2/phase2_effective_baseline_config.json"
    config = load_config(config_path)
    if tuple(config.pbft.validators) != WITNESS_POOL[:4]:
        raise AssertionError("The frozen four-validator membership differs from rsu-1..rsu-4")
    placement = phase6_rsus()
    for density in DENSITIES:
        scenario = scenario_for(density, placement)
        for seed in TRAIN_SEEDS:
            output = OUT / "training" / f"vehicles_{density}" / f"seed_{seed}"
            marker = output / "run_summary.json"
            if marker.is_file():
                print(f"training cell already complete density={density} seed={seed}", flush=True)
                continue
            if output.exists() and any(output.iterdir()):
                raise RuntimeError(f"Refusing to overwrite incomplete training output: {output}")
            manifest = run_sumo_trace(
                config, scenario_directory=scenario, output_directory=output, seed=seed,
                witness_rsu_ids=WITNESS_POOL,
            )
            assert manifest["witness_rsu_ids"] == list(WITNESS_POOL)
            print(f"training cell completed density={density} seed={seed} messages={manifest['counts']['v2x_messages']}", flush=True)


def road_candidates() -> tuple[list[tuple[str, list[tuple[float, float]]]], list[tuple[float, float]]]:
    scenario = ROOT / "sumo/urban_roundabout"
    nodes = {node.attrib["id"]: (float(node.attrib["x"]), float(node.attrib["y"]))
             for node in ET.parse(scenario / "urban_roundabout.nod.xml").iter("node")}
    roads: list[tuple[str, list[tuple[float, float]]]] = []
    candidates: set[tuple[float, float]] = set()
    for edge in ET.parse(scenario / "urban_roundabout.edg.xml").iter("edge"):
        if "from" not in edge.attrib:
            continue
        points = ([tuple(map(float, item.split(","))) for item in edge.attrib["shape"].split()]
                  if "shape" in edge.attrib else [nodes[edge.attrib["from"]], nodes[edge.attrib["to"]]])
        sampled: list[tuple[float, float]] = []
        for a, b in zip(points, points[1:]):
            length = math.dist(a, b)
            for step in range(max(1, int(length // 50)) + 1):
                t = min(1.0, step * 50 / max(length, 1e-9))
                point = (round(a[0] * (1 - t) + b[0] * t, 1), round(a[1] * (1 - t) + b[1] * t, 1))
                sampled.append(point)
                candidates.add(point)
        roads.append((edge.attrib.get("id", f"edge-{len(roads)}"), sampled))
    return roads, sorted(candidates)


def cell_id(raw_x: float, raw_y: float) -> tuple[int, int]:
    return (math.floor((raw_x + OFFSET) / 250.0), math.floor((raw_y + OFFSET) / 250.0))


def choose_placement() -> dict:
    base = phase6_rsus()
    training_rows = []
    mobility_hashes = {}
    for density in DENSITIES:
        for seed in TRAIN_SEEDS:
            path = OUT / "training" / f"vehicles_{density}" / f"seed_{seed}" / "mobility_trace.csv"
            if not path.is_file():
                raise FileNotFoundError(f"Missing fresh training mobility trace: {path}")
            frame = pd.read_csv(path, usecols=["vehicle_id", "simulation_time", "x", "y"])
            # Fixed, deterministic downsampling controls the placement-only computation.
            if len(frame) > 1500:
                frame = frame.iloc[np.linspace(0, len(frame) - 1, 1500, dtype=int)]
            frame = frame.assign(density=density, seed=seed)
            training_rows.append(frame)
            mobility_hashes[f"{density}/{seed}"] = digest(path)
    points_frame = pd.concat(training_rows, ignore_index=True)
    # SUMO coordinates are translated by (+500,+500); convert to road-file coordinates.
    points = points_frame[["x", "y"]].to_numpy(dtype=float) - OFFSET
    density_values = points_frame.density.to_numpy(dtype=int)
    candidates_roads, candidates = road_candidates()
    if len(candidates) < 2:
        raise RuntimeError("Road geometry yielded fewer than two feasible candidate sites")
    base_xy = np.array([(item["x"], item["y"]) for item in base], dtype=float)
    cand_xy = np.array(candidates, dtype=float)
    base_cells = [cell_id(*point) for point in base_xy]
    cand_cells = [cell_id(*point) for point in cand_xy]
    base_cover = np.linalg.norm(points[:, None, :] - base_xy[None, :, :], axis=2) <= RADIUS_M
    candidate_cover = np.linalg.norm(points[:, None, :] - cand_xy[None, :, :], axis=2) <= RADIUS_M
    base_any = base_cover.any(axis=1)
    base_multicell = np.zeros(len(points), dtype=bool)
    for i in range(len(base)):
        for j in range(i + 1, len(base)):
            if base_cells[i] != base_cells[j]:
                base_multicell |= base_cover[:, i] & base_cover[:, j]
    candidate_other_cell = np.column_stack([
        np.logical_or.reduce([base_cover[:, k] for k in range(len(base)) if base_cells[k] != site_cell])
        if any(base_cells[k] != site_cell for k in range(len(base))) else np.zeros(len(points), dtype=bool)
        for site_cell in cand_cells
    ])

    road_xy = np.array(candidates, dtype=float)
    road_base = np.linalg.norm(road_xy[:, None, :] - base_xy[None, :, :], axis=2) <= RADIUS_M
    road_base_multi = np.zeros(len(road_xy), dtype=bool)
    for i in range(len(base)):
        for j in range(i + 1, len(base)):
            if base_cells[i] != base_cells[j]:
                road_base_multi |= road_base[:, i] & road_base[:, j]
    road_candidate = np.linalg.norm(road_xy[:, None, :] - cand_xy[None, :, :], axis=2) <= RADIUS_M
    road_candidate_other_cell = np.column_stack([
        np.logical_or.reduce([road_base[:, k] for k in range(len(base)) if base_cells[k] != site_cell])
        if any(base_cells[k] != site_cell for k in range(len(base))) else np.zeros(len(road_xy), dtype=bool)
        for site_cell in cand_cells
    ])

    excluded_near_base = np.array([
        any(math.dist(point, (r["x"], r["y"])) < 75.0 for r in base) for point in candidates
    ])
    by_density = {density: density_values == density for density in DENSITIES}
    best = None
    for i in range(len(candidates)):
        if excluded_near_base[i]:
            continue
        for j in range(i + 1, len(candidates)):
            if excluded_near_base[j] or math.dist(candidates[i], candidates[j]) < 100.0:
                continue
            multi = (base_multicell
                     | (candidate_cover[:, i] & candidate_other_cell[:, i])
                     | (candidate_cover[:, j] & candidate_other_cell[:, j])
                     | (candidate_cover[:, i] & candidate_cover[:, j] & (cand_cells[i] != cand_cells[j])))
            fractions = [float(multi[by_density[density]].mean()) for density in DENSITIES]
            road_multi = (road_base_multi
                          | (road_candidate[:, i] & road_candidate_other_cell[:, i])
                          | (road_candidate[:, j] & road_candidate_other_cell[:, j])
                          | (road_candidate[:, i] & road_candidate[:, j] & (cand_cells[i] != cand_cells[j])))
            road_any = road_base.any(axis=1) | road_candidate[:, i] | road_candidate[:, j]
            selected_xy = np.vstack([base_xy, cand_xy[[i, j]]])
            worst_gap = float(np.linalg.norm(road_xy[:, None, :] - selected_xy[None, :, :], axis=2).min(axis=1).max())
            score = (min(fractions), float(np.mean(fractions)), float(road_multi.mean()),
                     float(road_any.mean()), -worst_gap)
            if best is None or score > best[0]:
                best = (score, i, j, fractions, float(road_multi.mean()), float(road_any.mean()), worst_gap)
    if best is None:
        raise RuntimeError("No road-feasible RSU pair passed separation constraints")
    score, i, j, fractions, road_multi, road_any, worst_gap = best
    # Conservative sensor assumptions use the lowest existing RSU reliability and an existing domain.
    additions = [
        {"id": "rsu-7", "x": candidates[i][0], "y": candidates[i][1], "domain": "domain-3", "reliability": 0.900},
        {"id": "rsu-8", "x": candidates[j][0], "y": candidates[j][1], "domain": "domain-3", "reliability": 0.900},
    ]
    candidate_rsus = base + additions
    result = {
        "selection": "training-only mobility and road-geometry multi-cell coverage; no attack labels read",
        "training_seeds": list(TRAIN_SEEDS), "heldout_seeds": list(HELDOUT_SEEDS),
        "densities": list(DENSITIES), "radius_m": RADIUS_M,
        "fixed_validators": ["rsu-1", "rsu-2", "rsu-3", "rsu-4"],
        "witness_routing_pool": list(WITNESS_POOL),
        "coordinate_frame": "road-file coordinates; SUMO netOffset (+500,+500) is applied by runner",
        "training_mobility_sha256": mobility_hashes,
        "training_samples": len(points), "road_candidate_count": len(candidates),
        "selection_criteria_lexicographic": ["maximize worst-density multi-cell coverage fraction",
                                               "maximize mean density multi-cell coverage fraction",
                                               "maximize road-geometry multi-cell fraction",
                                               "maximize overall road coverage fraction",
                                               "minimize worst nearest-sensor road distance"],
        "score": {"min_density_multi_cell_fraction": score[0], "mean_density_multi_cell_fraction": score[1],
                  "multi_cell_fraction_by_density": dict(zip(map(str, DENSITIES), fractions)),
                  "road_multicell_fraction": road_multi, "road_coverage_fraction": road_any,
                  "worst_road_point_nearest_rsu_m": worst_gap},
        "reliability_and_domain_assumption": "Both new sensing-only RSUs use reliability 0.900 (the existing minimum) and existing domain-3; no favorable new reliability/domain is invented.",
        "baseline_rsus": base, "candidate_rsus": candidate_rsus,
    }
    prereg_path = OUT / "placement_preregistered.json"
    if prereg_path.exists():
        raise FileExistsError(f"Refusing to overwrite frozen placement preregistration: {prereg_path}")
    prereg_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    gate = {
        "frozen_before_heldout_results": True,
        "cells": [{"density": density, "seed": seed} for density in DENSITIES for seed in HELDOUT_SEEDS],
        "security_acceptance": {
            "introduced_false_positive_cases": 0,
            "candidate_frr_must_not_exceed_c1": True,
            "candidate_precision_drop_max_absolute": 0.005,
            "candidate_observed_attack_opportunities_must_not_fall_in_any_pair": True,
            "fixed_universe_protected_fraction_gain_aggregate_min_absolute": 0.05,
            "each_density_mean_fixed_protected_fraction_must_not_regress": True,
            "minimum_cells_with_positive_fixed_protected_fraction_gain": 4,
            "eligible_independent_roots_sources_and_cells_must_increase": True,
        },
        "resource_review_caps": {"cpu_overhead_max_fraction": 0.25, "messages_per_case_overhead_max_fraction": 0.20,
                                 "p95_e2e_overhead_max_fraction": 0.05},
        "interpretation": "Pilot only; two held-out seeds are not a powered significance test. Failure of any security gate is NO-GO; resource caps are deployment review limits.",
    }
    gate_path = OUT / "acceptance_gate_preregistered.json"
    if gate_path.exists():
        raise FileExistsError(f"Refusing to overwrite frozen acceptance gate: {gate_path}")
    gate_path.write_text(json.dumps(gate, indent=2), encoding="utf-8")
    print(json.dumps({"sites": additions, "score": result["score"], "acceptance_gate": gate}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("training", "select"))
    args = parser.parse_args()
    generate_training() if args.stage == "training" else choose_placement()


if __name__ == "__main__":
    main()
