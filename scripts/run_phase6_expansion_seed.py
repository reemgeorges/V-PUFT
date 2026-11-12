"""Expanded held-out check at one untouched seed across all densities."""
import json
import shutil
from pathlib import Path

import run_phase5_coverage_pilot as pilot

ROOT = Path(__file__).resolve().parents[1]
pilot.OUT = ROOT / "results/post_seminar_phase6_holdout"
pilot.CELLS = tuple((d, 1008) for d in (20, 40, 60, 80, 100))

if __name__ == "__main__":
    pilot.OUT.mkdir(exist_ok=True)
    shutil.copy2(ROOT / "results/post_seminar_phase6/placement_preregistered.json",
                 pilot.OUT / "placement_preregistered.json")
    pilot.main()
