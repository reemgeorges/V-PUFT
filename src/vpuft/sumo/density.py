from __future__ import annotations

import json
import shutil
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path


ATTACK_CYCLE = (
    "position_offset",
    "speed_offset",
    "replay",
    "certificate_tamper",
    "flood",
    "false_denm",
    "mixed",
)


@dataclass(frozen=True)
class DensityScenarioManifest:
    topology: str
    source_scenario: str
    generated_scenario: str
    requested_vehicle_count: int
    attack_vehicle_count: int
    attack_vehicle_ratio: float
    departure_window_seconds: float
    route_ids: tuple[str, ...]


def _attack_parameters(name: str) -> dict:
    return {
        "position_offset": {"position_offset_m": 65.0},
        "speed_offset": {"speed_offset_mps": 11.0},
        "replay": {"replay_delay_steps": 4},
        "certificate_tamper": {},
        "flood": {"messages_per_step": 5},
        "false_denm": {"denm_period_seconds": 5.0},
        "mixed": {
            "position_offset_m": 45.0,
            "speed_offset_mps": 8.0,
            "messages_per_step": 4,
        },
    }[name]


def _evenly_spaced_indices(total: int, selected: int) -> list[int]:
    if selected < 1 or selected > total:
        raise ValueError("selected must be within [1, total]")
    if selected == 1:
        return [0]
    return [round(index * (total - 1) / (selected - 1)) for index in range(selected)]


def build_density_scenario(
    source_scenario: str | Path,
    output_scenario: str | Path,
    *,
    vehicle_count: int,
    attack_vehicle_ratio: float,
    departure_window_seconds: float,
    end_time_seconds: float,
) -> DensityScenarioManifest:
    """Create a self-contained SUMO scenario with a controlled vehicle demand.

    The topology, RSUs and routes are copied unchanged. Explicit vehicles and
    their attack schedule are regenerated so every requested vehicle is part of
    the same paired trace used by all architectures.
    """

    source = Path(source_scenario).resolve()
    output = Path(output_scenario).resolve()
    if vehicle_count < len(ATTACK_CYCLE):
        raise ValueError("vehicle_count must represent every modeled attack type")
    if not 0 < attack_vehicle_ratio < 1:
        raise ValueError("attack_vehicle_ratio must be within (0, 1)")
    output.mkdir(parents=True, exist_ok=True)

    node_files = sorted(source.glob("*.nod.xml"))
    route_files = sorted(source.glob("*.rou.xml"))
    if len(node_files) != 1 or len(route_files) != 1:
        raise FileNotFoundError("Density generation requires one *.nod.xml and one *.rou.xml")
    prefix = node_files[0].name.removesuffix(".nod.xml")

    required = (
        f"{prefix}.nod.xml",
        f"{prefix}.edg.xml",
        f"{prefix}.net.xml",
        f"{prefix}.sumocfg",
        "rsus.add.xml",
        "rsus.json",
    )
    for name in required:
        path = source / name
        if not path.exists():
            raise FileNotFoundError(path)
        shutil.copy2(path, output / name)

    base_tree = ET.parse(route_files[0])
    base_root = base_tree.getroot()
    generated_root = ET.Element("routes")
    for child in base_root:
        if child.tag in {"vType", "route"}:
            generated_root.append(child)
    route_ids = tuple(
        element.attrib["id"] for element in generated_root.findall("route")
    )
    if not route_ids:
        raise ValueError(f"No named routes found in {route_files[0]}")

    effective_window = min(float(departure_window_seconds), max(1.0, end_time_seconds * 0.30))
    departures: dict[str, float] = {}
    for index in range(vehicle_count):
        depart = 0.0 if vehicle_count == 1 else index * effective_window / (vehicle_count - 1)
        vehicle_id = f"veh_{index:03d}"
        departures[vehicle_id] = depart
        ET.SubElement(
            generated_root,
            "vehicle",
            {
                "id": vehicle_id,
                "type": "passenger",
                "route": route_ids[index % len(route_ids)],
                "depart": f"{depart:.3f}",
                "departSpeed": "12" if index % 2 == 0 else "13",
                "departLane": "best",
            },
        )
    ET.indent(generated_root, space="    ")
    ET.ElementTree(generated_root).write(
        output / f"{prefix}.rou.xml", encoding="utf-8", xml_declaration=True
    )

    # 35% yields 7, 14, 21, 28 and 35 attackers for the prescribed sweep,
    # keeping the seven attack classes balanced at every density.
    attack_count = max(len(ATTACK_CYCLE), round(vehicle_count * attack_vehicle_ratio))
    attack_count = min(vehicle_count, attack_count)
    attack_indices = _evenly_spaced_indices(vehicle_count, attack_count)
    attacks = []
    for ordinal, vehicle_index in enumerate(attack_indices):
        vehicle_id = f"veh_{vehicle_index:03d}"
        attack_type = ATTACK_CYCLE[ordinal % len(ATTACK_CYCLE)]
        start = min(departures[vehicle_id] + 5.0, end_time_seconds - 12.0)
        end = min(start + 30.0, end_time_seconds - 1.0)
        attacks.append(
            {
                "vehicle_id": vehicle_id,
                "attack_type": attack_type,
                "start": round(start, 3),
                "end": round(end, 3),
                **_attack_parameters(attack_type),
            }
        )
    (output / "attacks.json").write_text(
        json.dumps(attacks, indent=2), encoding="utf-8"
    )

    manifest = DensityScenarioManifest(
        topology=prefix,
        source_scenario=str(source),
        generated_scenario=str(output),
        requested_vehicle_count=vehicle_count,
        attack_vehicle_count=attack_count,
        attack_vehicle_ratio=attack_count / vehicle_count,
        departure_window_seconds=effective_window,
        route_ids=route_ids,
    )
    (output / "density_scenario_manifest.json").write_text(
        json.dumps(asdict(manifest), indent=2), encoding="utf-8"
    )
    return manifest
