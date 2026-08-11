from pathlib import Path

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
    manifest = run_sumo_trace(
        cfg,
        scenario_directory="sumo/smoke",
        output_directory=tmp_path,
        seed=1001,
        force_prepare=True,
    )
    assert manifest["counts"]["detection_events"] > 0
    assert (tmp_path / "shared_detection_trace.jsonl").exists()
