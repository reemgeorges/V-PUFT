"""Complete only missing seed/density cells in a fresh Phase 6 output folder."""
import json
import shutil
from pathlib import Path

import run_phase5_coverage_pilot as pilot

ROOT = Path(__file__).resolve().parents[1]
pilot.OUT = ROOT / "results/post_seminar_phase6_final"
pilot.CELLS = tuple((d, s) for s, ds in ((1007, (40, 60, 80)),
                                        (1009, (20, 40, 60, 80, 100)),
                                        (1010, (20, 40, 60, 80, 100))) for d in ds)

if __name__ == "__main__":
    pilot.OUT.mkdir(exist_ok=True)
    shutil.copy2(ROOT / "results/post_seminar_phase6/placement_preregistered.json",
                 pilot.OUT / "placement_preregistered.json")
    pilot.main()
