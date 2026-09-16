import json
import xml.etree.ElementTree as ET
from pathlib import Path

from vpuft.config import load_config


SCENARIO = Path("sumo/urban_roundabout")


def test_roundabout_geometry_and_fixed_experiment_cardinality():
    nodes = ET.parse(SCENARIO / "urban_roundabout.nod.xml").getroot()
    edges = ET.parse(SCENARIO / "urban_roundabout.edg.xml").getroot()
    routes = ET.parse(SCENARIO / "urban_roundabout.rou.xml").getroot()
    rsus = json.loads((SCENARIO / "rsus.json").read_text(encoding="utf-8"))
    config = load_config("configs/urban_roundabout_campaign.json")

    traffic_lights = [node for node in nodes.findall("node") if node.attrib.get("type") == "traffic_light"]
    roundabout_edges = [
        edge
        for edge in edges.findall("edge")
        if edge.attrib["id"] in {
            "rn_rne", "rne_re", "re_rse", "rse_rs",
            "rs_rsw", "rsw_rw", "rw_rnw", "rnw_rn",
        }
    ]

    assert len(traffic_lights) == 4
    assert len(roundabout_edges) == 8
    assert all(float(edge.attrib["speed"]) == 8.33 for edge in roundabout_edges)
    assert len(routes.findall("route")) == 16
    assert len(rsus) == 6
    assert {item["id"] for item in rsus} == {f"rsu-{index}" for index in range(1, 7)}
    assert config.density_campaign.vehicle_counts == (20, 40, 60, 80, 100)
    assert config.simulation.seeds == tuple(range(1001, 1011))
    assert config.density_campaign.backhaul_extra_latency_ms == (0.0, 100.0)
    evaluations = (
        len(config.density_campaign.vehicle_counts)
        * len(config.simulation.seeds)
        * (1 + len(config.density_campaign.backhaul_extra_latency_ms))
    )
    assert evaluations == 150
