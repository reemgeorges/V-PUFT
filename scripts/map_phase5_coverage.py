"""Plot the registered RSU layouts against label-free training trajectories."""
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Circle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / (sys.argv[1] if len(sys.argv) > 1 else "results/post_seminar_phase5")
plan = json.loads((OUT / "placement_preregistered.json").read_text())
path = ROOT / "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout/vehicles_100/seed_1001/mobility_trace.csv"
mobility = pd.read_csv(path, usecols=["vehicle_id", "simulation_time", "x", "y"])
mobility = mobility[mobility.simulation_time.mod(3).eq(0)]
for name, rsus in (("original", plan["original_rsus"]), ("candidate", plan["candidate_rsus"])):
    fig, ax = plt.subplots(figsize=(8, 8))
    for _, group in mobility.groupby("vehicle_id"):
        ax.plot(group.x - 500, group.y - 500, color="#8898a5", alpha=.2, linewidth=.6)
    for rsu in rsus:
        ax.add_patch(Circle((rsu["x"], rsu["y"]), 450, fill=False, color="#2873b4", alpha=.3))
        ax.plot(rsu["x"], rsu["y"], "^", color="#174d84")
        ax.annotate(rsu["id"], (rsu["x"], rsu["y"]), fontsize=8)
    ax.set(xlim=(-560, 560), ylim=(-560, 560), aspect="equal", xlabel="local x (m)", ylabel="local y (m)", title=f"Six RSUs: {name}")
    fig.tight_layout()
    fig.savefig(OUT / f"coverage_{name}.png", dpi=160)
    plt.close(fig)
