"""Run the registered Phase 6 feasibility candidate on held-out seed 1007."""
from pathlib import Path

import run_phase5_coverage_pilot as pilot

pilot.OUT = Path(__file__).resolve().parents[1] / "results/post_seminar_phase6"
pilot.CELLS = ((20, 1007), (100, 1007))

if __name__ == "__main__":
    pilot.main()
