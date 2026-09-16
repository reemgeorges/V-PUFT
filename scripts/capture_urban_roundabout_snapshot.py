from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib import transforms
from matplotlib.lines import Line2D
from matplotlib.patches import Circle, Patch, Rectangle

from vpuft.sumo.density import build_density_scenario
from vpuft.sumo.doctor import resolve_binary


def _load_sumolib():
    try:
        import sumolib

        return sumolib
    except ModuleNotFoundError:
        sumo_home = os.environ.get("SUMO_HOME")
        if sumo_home:
            tools = str(Path(sumo_home) / "tools")
            if tools not in sys.path:
                sys.path.append(tools)
            import sumolib

            return sumolib
        raise RuntimeError("sumolib is required; set SUMO_HOME or install SUMO tools")


def _snapshot(fcd_path: Path, requested_time: float) -> tuple[float, list[dict]]:
    best_time = -1.0
    best_rows: list[dict] = []
    best_distance = float("inf")
    for _event, element in ET.iterparse(fcd_path, events=("end",)):
        if element.tag != "timestep":
            continue
        timestamp = float(element.attrib["time"])
        distance = abs(timestamp - requested_time)
        if distance < best_distance:
            best_distance = distance
            best_time = timestamp
            best_rows = [
                {
                    "id": vehicle.attrib["id"],
                    "x": float(vehicle.attrib["x"]),
                    "y": float(vehicle.attrib["y"]),
                    "angle": float(vehicle.attrib.get("angle", 0.0)),
                }
                for vehicle in element.findall("vehicle")
            ]
        element.clear()
    if best_time < 0:
        raise RuntimeError(f"No vehicle timestep was written to {fcd_path}")
    return best_time, best_rows


def capture_snapshot(
    *,
    project_root: Path,
    output: Path,
    vehicle_count: int,
    seed: int,
    snapshot_time: float,
) -> Path:
    sumo_binary = resolve_binary("sumo")
    if not sumo_binary:
        raise RuntimeError("SUMO was not found in PATH or SUMO_HOME/bin")
    sumolib = _load_sumolib()
    source = project_root / "sumo" / "urban_roundabout"
    with tempfile.TemporaryDirectory(prefix="vpuft-roundabout-") as temporary:
        generated = Path(temporary) / "scenario"
        build_density_scenario(
            source,
            generated,
            vehicle_count=vehicle_count,
            attack_vehicle_ratio=0.35,
            departure_window_seconds=20.0,
            end_time_seconds=95.0,
        )
        fcd_path = Path(temporary) / "mobility.xml"
        command = [
            sumo_binary,
            "-c",
            str(generated / "urban_roundabout.sumocfg"),
            "--seed",
            str(seed),
            "--fcd-output",
            str(fcd_path),
            "--fcd-output.geo",
            "false",
            "--no-step-log",
            "true",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"SUMO snapshot run failed:\n{completed.stderr}")
        actual_time, vehicles = _snapshot(fcd_path, snapshot_time)
        network = sumolib.net.readNet(str(generated / "urban_roundabout.net.xml"))
        offset_x, offset_y = network.getLocationOffset()
        attacks = json.loads((generated / "attacks.json").read_text(encoding="utf-8"))
        rsus = json.loads((generated / "rsus.json").read_text(encoding="utf-8"))

    active_malicious = {
        item["vehicle_id"]
        for item in attacks
        if float(item["start"]) <= actual_time <= float(item["end"])
    }
    figure, axis = plt.subplots(figsize=(11, 8), dpi=180)
    figure.patch.set_facecolor("white")
    axis.set_facecolor("white")

    for edge in network.getEdges(withInternal=False):
        shape = edge.getRawShape()
        if len(shape) < 2:
            continue
        x_values, y_values = zip(*shape)
        axis.plot(
            x_values,
            y_values,
            color="#a3a3a3",
            linewidth=2.2,
            solid_capstyle="round",
            zorder=1,
        )

    for rsu in rsus:
        rsu_x = float(rsu["x"]) + offset_x
        rsu_y = float(rsu["y"]) + offset_y
        axis.add_patch(
            Circle(
                (rsu_x, rsu_y),
                50,
                facecolor="none",
                edgecolor="#3759ff",
                linewidth=1.2,
                linestyle=(0, (4, 3)),
                alpha=0.9,
                zorder=2,
            )
        )
        axis.scatter(rsu_x, rsu_y, marker="^", s=70, color="#163cff", edgecolor="#163cff", zorder=5)
        axis.text(rsu_x, rsu_y + 18, rsu["id"].upper(), fontsize=7, color="#163cff", weight="bold", ha="center", zorder=6)

    signal_positions = ((0, 90, "N"), (90, 0, "E"), (0, -90, "S"), (-90, 0, "W"))
    for x, y, label in signal_positions:
        x += offset_x
        y += offset_y
        axis.scatter(x, y, marker="s", s=30, color="#16a34a", edgecolor="#14532d", linewidth=0.6, zorder=7)
        axis.text(x + 8, y + 8, f"TLS-{label}", fontsize=6, color="#166534", zorder=7)

    for row in vehicles:
        is_malicious = row["id"] in active_malicious
        color = "#ff9800" if is_malicious else "#8f8f8f"
        vehicle = Rectangle(
            (row["x"] - 4.5, row["y"] - 2.2),
            9,
            4.4,
            facecolor=color,
            edgecolor="#2f2f2f",
            linewidth=0.55,
            zorder=8,
        )
        vehicle.set_transform(
            transforms.Affine2D().rotate_deg_around(
                row["x"], row["y"], 90.0 - row["angle"]
            )
            + axis.transData
        )
        axis.add_patch(vehicle)
        if is_malicious:
            axis.text(
                row["x"],
                row["y"] + 8,
                row["id"].removeprefix("veh_"),
                fontsize=5,
                color="#9a3412",
                weight="bold",
                ha="center",
                zorder=9,
            )

    x_min, y_min, x_max, y_max = network.getBoundary()
    margin = 65
    axis.set_xlim(x_min - margin, x_max + margin)
    axis.set_ylim(y_min - margin, y_max + margin)
    axis.set_aspect("equal", adjustable="box")
    axis.grid(True, color="#e8e8e8", linewidth=0.6)
    axis.set_xlabel("X (m)", fontsize=9)
    axis.set_ylabel("Y (m)", fontsize=9)
    axis.tick_params(labelsize=8)
    axis.set_title(
        f"V-PUFT VANET Security Simulation | Scenario 5 | Step {actual_time:.0f}",
        fontsize=14,
        weight="bold",
        pad=10,
    )
    legend = [
        Patch(facecolor="#8f8f8f", edgecolor="#2f2f2f", label="Trusted / no active attack"),
        Patch(facecolor="#ff9800", edgecolor="#2f2f2f", label="Active malicious schedule"),
        Line2D([0], [0], marker="^", color="w", markerfacecolor="#163cff", markeredgecolor="#163cff", markersize=8, label="RSU"),
        Line2D([0], [0], marker="s", color="w", markerfacecolor="#16a34a", markeredgecolor="#14532d", markersize=7, label="Traffic light"),
    ]
    axis.legend(handles=legend, loc="upper right", fontsize=8, frameon=True)
    axis.text(
        0.01,
        0.015,
        f"SUMO trace | vehicles={vehicle_count} | seed={seed} | active attacks={len(active_malicious)} | RSUs=6\n"
        "Dashed RSU rings are visual markers, not radio-range boundaries.",
        transform=axis.transAxes,
        fontsize=7,
        color="#444444",
        va="bottom",
        bbox={"facecolor": "white", "edgecolor": "#d4d4d4", "alpha": 0.9, "pad": 4},
        zorder=20,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, bbox_inches="tight", facecolor=figure.get_facecolor())
    plt.close(figure)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture the canonical SUMO-derived Scenario 5 image")
    parser.add_argument("--output", default="results/urban_roundabout/scenario_5_sumo_60_seed_1001.png")
    parser.add_argument("--vehicles", type=int, default=60)
    parser.add_argument("--seed", type=int, default=1001)
    parser.add_argument("--time", type=float, default=25.0)
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    result = capture_snapshot(
        project_root=project_root,
        output=(project_root / args.output).resolve(),
        vehicle_count=args.vehicles,
        seed=args.seed,
        snapshot_time=args.time,
    )
    print(result)


if __name__ == "__main__":
    main()
