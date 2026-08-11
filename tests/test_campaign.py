from dataclasses import replace

from vpuft.config import ResearchConfig, SimulationConfig
from vpuft.runner import run_campaign


def test_three_architecture_smoke(tmp_path):
    cfg = replace(
        ResearchConfig(),
        simulation=SimulationConfig(seeds=(1000, 1001, 1002, 1003), cases_per_seed=8, malicious_ratio=0.4),
    )
    manifest = run_campaign(cfg, tmp_path)
    assert len(manifest["architectures"]) == 3
    assert (tmp_path / "evidence_campaign.csv").exists()
    assert (tmp_path / "architecture_summary.csv").exists()
