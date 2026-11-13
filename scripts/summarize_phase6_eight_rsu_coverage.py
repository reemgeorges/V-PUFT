"""Summarize training-only mobility and road coverage for frozen C1/C3 sites."""
from __future__ import annotations

import json
import math
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np
import pandas as pd

from run_phase6_eight_rsu_placement import DENSITIES, OUT, TRAIN_SEEDS, phase6_rsus, road_candidates


def cell(raw_x: float, raw_y: float) -> tuple[int, int]:
    return math.floor((raw_x + 500.0) / 250.0), math.floor((raw_y + 500.0) / 250.0)


def coverage(positions: np.ndarray, rsus: list[dict]) -> dict[str, float]:
    xy = np.array([(r["x"], r["y"]) for r in rsus], dtype=float)
    distance = np.linalg.norm(positions[:, None, :] - xy[None, :, :], axis=2)
    observed = distance <= 450.0
    cells = [cell(*point) for point in xy]
    multi_cell = np.zeros(len(positions), dtype=bool)
    for a in range(len(rsus)):
        for b in range(a + 1, len(rsus)):
            if cells[a] != cells[b]:
                multi_cell |= observed[:, a] & observed[:, b]
    return {
        "vehicle_snapshot_coverage_fraction": float(observed.any(axis=1).mean()),
        "multi_observer_different_cell_fraction": float(multi_cell.mean()),
        "mean_in_range_sensor_count": float(observed.sum(axis=1).mean()),
        "median_nearest_sensor_distance_m": float(distance.min(axis=1).mean()),
    }


def main() -> None:
    prereg = json.loads((OUT / "placement_preregistered.json").read_text(encoding="utf-8"))
    rows = []
    points_by_density = {}
    for density in DENSITIES:
        frames = []
        for seed in TRAIN_SEEDS:
            path = OUT / "training" / f"vehicles_{density}" / f"seed_{seed}" / "mobility_trace.csv"
            frame = pd.read_csv(path, usecols=["x", "y"])
            if len(frame) > 1500:
                frame = frame.iloc[np.linspace(0, len(frame) - 1, 1500, dtype=int)]
            frames.append(frame)
        positions = pd.concat(frames, ignore_index=True).to_numpy(dtype=float) - 500.0
        points_by_density[density] = positions
        for layout, rsus in (("C1", prereg["baseline_rsus"]), ("C3", prereg["candidate_rsus"])):
            rows.append({"density": density, "layout": layout, "training_samples": len(positions), **coverage(positions, rsus)})

    # Static road-centerline samples, derived from the same map as the placement search.
    _, candidates = road_candidates()
    road = np.array(candidates, dtype=float)
    road_rows = []
    for layout, rsus in (("C1", prereg["baseline_rsus"]), ("C3", prereg["candidate_rsus"])):
        road_rows.append({"density": "road_geometry", "layout": layout, "training_samples": len(road), **coverage(road, rsus)})
    all_rows = rows + road_rows
    frame = pd.DataFrame(all_rows)
    frame.to_csv(OUT / "training_coverage_summary.csv", index=False)
    print(frame.to_string(index=False))

    # A compact schematic (road geometry and sensor ranges; no evaluation labels).
    import matplotlib.pyplot as plt
    scenario = Path(__file__).resolve().parents[1] / "sumo/urban_roundabout"
    fig, ax = plt.subplots(figsize=(10, 8))
    nodes = {n.attrib["id"]: (float(n.attrib["x"]), float(n.attrib["y"]))
             for n in ET.parse(scenario / "urban_roundabout.nod.xml").iter("node")}
    for edge in ET.parse(scenario / "urban_roundabout.edg.xml").iter("edge"):
        if "from" not in edge.attrib:
            continue
        shape = ([tuple(map(float, p.split(","))) for p in edge.attrib["shape"].split()]
                 if "shape" in edge.attrib else [nodes[edge.attrib["from"]], nodes[edge.attrib["to"]]])
        ax.plot([p[0] for p in shape], [p[1] for p in shape], color="#9aa0a6", linewidth=1.0, zorder=1)
    c1, c3 = prereg["baseline_rsus"], prereg["candidate_rsus"]
    for r in c1:
        circle = plt.Circle((r["x"], r["y"]), 450.0, fill=False, color="#3274a1", alpha=0.10, linewidth=0.8)
        ax.add_patch(circle)
        ax.scatter(r["x"], r["y"], marker="^", color="#3274a1", s=55, zorder=3)
        ax.text(r["x"], r["y"] + 20, r["id"], fontsize=8, color="#24536e")
    for r in c3[6:]:
        circle = plt.Circle((r["x"], r["y"]), 450.0, fill=False, color="#e1812c", alpha=0.18, linewidth=1.2)
        ax.add_patch(circle)
        ax.scatter(r["x"], r["y"], marker="*", color="#e1812c", s=150, zorder=4)
        ax.text(r["x"], r["y"] + 22, r["id"], fontsize=9, color="#9a4f0b")
    ax.set_aspect("equal", adjustable="box")
    ax.set_xlabel("Road-coordinate x (m)")
    ax.set_ylabel("Road-coordinate y (m)")
    ax.set_title("Training-only road geometry and sensing ranges (450 m)")
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(OUT / "rsu8_training_coverage_map.png", dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    main()
