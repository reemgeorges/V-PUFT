import json
import xml.etree.ElementTree as ET
from dataclasses import replace

import pandas as pd

import vpuft.density_campaign as density_module
from vpuft.config import (
    DensityCampaignConfig,
    NetworkConfig,
    ResearchConfig,
    SimulationConfig,
    TrustCacheConfig,
)
from vpuft.crypto import KeyRegistry
from vpuft.density_campaign import run_density_campaign
from vpuft.simulation import generate_scenario
from vpuft.sumo.density import ATTACK_CYCLE, build_density_scenario
from vpuft.trace import write_events_jsonl
from vpuft.trust_cache import simulate_topology_v2v_trust_cache


def test_density_scenario_has_exact_vehicle_count_and_balanced_attacks(tmp_path):
    generated = tmp_path / "generated"
    manifest = build_density_scenario(
        "sumo/smoke",
        generated,
        vehicle_count=40,
        attack_vehicle_ratio=0.35,
        departure_window_seconds=20.0,
        end_time_seconds=95.0,
    )
    root = ET.parse(generated / "smoke.rou.xml").getroot()
    vehicles = root.findall("vehicle")
    attacks = json.loads((generated / "attacks.json").read_text(encoding="utf-8"))

    assert len(vehicles) == 40
    assert manifest.requested_vehicle_count == 40
    assert manifest.attack_vehicle_count == 14
    assert len(attacks) == 14
    assert {attack["attack_type"] for attack in attacks} == set(ATTACK_CYCLE)
    assert len({attack["vehicle_id"] for attack in attacks}) == len(attacks)


def test_topology_cache_consumes_observed_mobility_contacts():
    config = ResearchConfig(
        network=NetworkConfig(packet_delivery_ratio=1.0),
        trust_cache=replace(TrustCacheConfig(), anomaly_ratio=0.0),
    )
    mobility_rows = []
    for timestamp in (0.0, 1.0):
        for index in range(20):
            mobility_rows.append(
                {
                    "simulation_time": timestamp,
                    "vehicle_id": f"veh_{index:03d}",
                    "x": float(index * 2),
                    "y": 0.0,
                }
            )
    result = simulate_topology_v2v_trust_cache(
        config,
        seed=1001,
        topology="smoke",
        requested_vehicle_count=20,
        ttl_seconds=5.0,
        mobility_rows=mobility_rows,
        decisions=[],
        rsus=[{"id": "rsu-1", "x": 0.0, "y": 0.0}],
    )

    assert result["observed_vehicle_count"] == 20
    assert result["interactions"] == 40
    assert result["cache_misses"] > 0
    assert result["cache_hits"] > 0
    assert result["v2i_queries_avoided"] == result["cache_hits"]
    assert result["messages_per_interaction"] > 0


def test_density_campaign_pairs_one_trace_across_architectures(tmp_path, monkeypatch):
    config = ResearchConfig(
        network=NetworkConfig(packet_delivery_ratio=1.0),
        simulation=SimulationConfig(
            seeds=(1001,), cases_per_seed=8, malicious_ratio=0.4, rsu_count=6
        ),
        trust_cache=replace(TrustCacheConfig(), ttl_seconds=(0.0, 5.0), anomaly_ratio=0.0),
        density_campaign=DensityCampaignConfig(
            vehicle_counts=(20,),
            backhaul_extra_latency_ms=(0.0, 20.0),
            include_robustness_variants=False,
            include_topology_cache=True,
        ),
    )

    def fake_sumo_trace(cfg, *, scenario_directory, output_directory, seed, **_kwargs):
        output = output_directory
        output.mkdir(parents=True, exist_ok=True)
        bundle = generate_scenario(cfg, KeyRegistry(cfg.security.deterministic_master_seed), seed)
        write_events_jsonl(bundle.events, output / "shared_detection_trace.jsonl")
        mobility = []
        for timestamp in (0.0, 1.0):
            for index in range(20):
                mobility.append(
                    {
                        "seed": seed,
                        "simulation_time": timestamp,
                        "vehicle_id": f"veh_{index:03d}",
                        "x": float(index * 2),
                        "y": 0.0,
                    }
                )
        pd.DataFrame(mobility).to_csv(output / "mobility_trace.csv", index=False)
        manifest = {
            "counts": {
                "unique_vehicles_observed": 20,
                "peak_concurrent_vehicles": 20,
                "cases": len(bundle.rsu_cases),
                "v2x_messages": len(bundle.events),
                "detection_events": len(bundle.events),
            }
        }
        (output / "scenario_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (output / "run_summary.json").write_text(
            json.dumps({"completed": True, "seed": seed}), encoding="utf-8"
        )
        return manifest

    monkeypatch.setattr(density_module, "run_sumo_trace", fake_sumo_trace)
    output = tmp_path / "campaign"
    manifest = run_density_campaign(
        config,
        scenario_directories=["sumo/smoke"],
        output_directory=output,
        seeds=(1001,),
    )
    metrics = pd.read_csv(output / "combined" / "density_metrics_by_seed.csv")
    decisions = pd.read_csv(output / "combined" / "density_decisions.csv")

    assert manifest["expected_shared_traces"] == 1
    assert set(metrics["architecture"]) == {
        "distributed_density_honest",
        "centralized_remote_0ms_control",
        "centralized_remote_20ms",
    }
    assert metrics["seed"].nunique() == 1
    assert metrics["vehicle_count"].unique().tolist() == [20]
    distributed_cases = set(
        decisions.loc[
            decisions["architecture"] == "distributed_density_honest", "case_id"
        ]
    )
    for architecture in ("centralized_remote_0ms_control", "centralized_remote_20ms"):
        assert set(decisions.loc[decisions["architecture"] == architecture, "case_id"]) == distributed_cases
