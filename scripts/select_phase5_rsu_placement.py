"""Freeze a two-RSU relocation using road geometry and training mobility only."""
from __future__ import annotations

import json
import math
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase2/baseline_regenerated"
OUT = ROOT / "results/post_seminar_phase5"
RSUS = json.loads((ROOT / "sumo/urban_roundabout/rsus.json").read_text())
RADIUS = 450.0


def road_candidates() -> list[tuple[float, float]]:
    scenario = ROOT / "sumo/urban_roundabout"
    nodes = {n.attrib["id"]: (float(n.attrib["x"]), float(n.attrib["y"]))
             for n in ET.parse(scenario / "urban_roundabout.nod.xml").iter("node")}
    candidates = set()
    for edge in ET.parse(scenario / "urban_roundabout.edg.xml").iter("edge"):
        if "from" not in edge.attrib:
            continue
        points = ([tuple(map(float, p.split(","))) for p in edge.attrib["shape"].split()]
                  if "shape" in edge.attrib else [nodes[edge.attrib["from"]], nodes[edge.attrib["to"]]])
        for a, b in zip(points, points[1:]):
            length = math.dist(a, b)
            for i in range(int(length // 50) + 1):
                t = min(1.0, (i * 50) / max(length, 1e-9))
                candidates.add((round(a[0] * (1-t) + b[0] * t, 1),
                                round(a[1] * (1-t) + b[1] * t, 1)))
    return sorted(candidates)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    samples = []
    # No attack labels, FN lists, or evaluation seeds enter this selection.
    for density in (20, 60, 100):
        for seed in range(1001, 1007):
            path = BASE / f"traces/urban_roundabout/vehicles_{density}/seed_{seed}/mobility_trace.csv"
            frame = pd.read_csv(path, usecols=["simulation_time", "x", "y"])
            frame = frame[frame.simulation_time.mod(5).eq(0)]
            sample = frame[["x", "y"]].to_numpy() - 500.0
            if len(sample):
                sample = sample[np.linspace(0, len(sample)-1, min(1500, len(sample)), dtype=int)]
                samples.append(sample)
    positions = np.concatenate(samples)
    candidates = road_candidates()
    base = np.array([(r["x"], r["y"]) for r in RSUS[:4]])
    base_cover = (np.linalg.norm(positions[:, None, :] - base[None, :, :], axis=2) <= RADIUS)
    cand = np.array(candidates)
    cand_cover = np.linalg.norm(positions[:, None, :] - cand[None, :, :], axis=2) <= RADIUS
    base_cells = [f"cell-{int((x+500)//250)}-{int((y+500)//250)}" for x, y in base]
    cand_cells = [f"cell-{int((x+500)//250)}-{int((y+500)//250)}" for x, y in cand]
    # A training position earns two-coverage credit only from different cells.
    def score(chosen: tuple[int, int]) -> tuple[int, int]:
        rows = np.concatenate([base_cover, cand_cover[:, list(chosen)]], axis=1)
        cells = base_cells + [cand_cells[i] for i in chosen]
        multi = np.zeros(len(positions), dtype=bool)
        for i in range(6):
            for j in range(i+1, 6):
                if cells[i] != cells[j]:
                    multi |= rows[:, i] & rows[:, j]
        return int(multi.sum()), int(rows.any(axis=1).sum())
    best = None
    for i in range(len(candidates)):
        for j in range(i+1, len(candidates)):
            if math.dist(candidates[i], candidates[j]) < 100:
                continue
            if any(math.dist(candidates[i], tuple(p)) < 75 or math.dist(candidates[j], tuple(p)) < 75 for p in base):
                continue
            value = score((i, j))
            if best is None or value > best[0]:
                best = (value, i, j)
    assert best is not None
    placement = [dict(r) for r in RSUS]
    for slot, index in ((4, best[1]), (5, best[2])):
        placement[slot]["x"], placement[slot]["y"] = candidates[index]
    (OUT / "placement_preregistered.json").write_text(json.dumps({
        "training_seeds": list(range(1001, 1007)), "heldout_seeds": list(range(1007, 1011)),
        "training_densities": [20, 60, 100], "radius_m": RADIUS,
        "fixed_validators": [r["id"] for r in RSUS[:4]],
        "selection_score": best[0], "training_samples": len(positions),
        "original_rsus": RSUS, "candidate_rsus": placement,
    }, indent=2), encoding="utf-8")
    print(json.dumps({"sites": placement[4:], "score": best[0], "samples": len(positions)}))


if __name__ == "__main__":
    main()
