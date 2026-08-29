from dataclasses import replace

from vpuft.config import ResearchConfig, SimulationConfig
from vpuft.runner import run_campaign
from vpuft.sensitivity import select_weights


def test_sensitivity_smoke(tmp_path):
    cfg = replace(
        ResearchConfig(),
        simulation=SimulationConfig(seeds=(1000, 1001, 1002, 1003, 1004), cases_per_seed=10, malicious_ratio=0.4),
    )
    campaign = tmp_path / "campaign"
    run_campaign(cfg, campaign)
    selected = select_weights(
        campaign / "evidence_campaign.csv",
        tmp_path / "sensitivity",
        cfg,
        candidates=20,
        folds=3,
        min_recall=0.2,
        max_frr=0.8,
        bootstrap_repeats=3,
    )
    assert abs(sum(selected["weights"].values()) - 1.0) < 1e-8
    assert (tmp_path / "sensitivity" / "selected_weights.json").exists()
