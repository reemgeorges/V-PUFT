from pathlib import Path
import shutil

import pytest

from vpuft.config import load_config
from vpuft.sumo.doctor import doctor_report
from vpuft.sumo.runner import run_sumo_trace


@pytest.mark.sumo
def test_bundled_sumo_smoke_when_available(tmp_path: Path):
    cfg = load_config("configs/sumo_smoke.json")
    report = doctor_report(cfg.sumo.sumo_binary, cfg.sumo.netconvert_binary)
    if not report.ready_for_sumo:
        pytest.skip("SUMO/TraCI is not installed in this environment")

    scenario_directory = tmp_path / "smoke"
    output_directory = tmp_path / "output"
    shutil.copytree(Path("sumo/smoke"), scenario_directory)

    manifest = run_sumo_trace(
        cfg,
        scenario_directory=scenario_directory,
        output_directory=output_directory,
        seed=1001,
        force_prepare=True,
    )

    assert manifest["counts"]["detection_events"] > 0
    assert (output_directory / "shared_detection_trace.jsonl").exists()
