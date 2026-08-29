from __future__ import annotations

import subprocess
from pathlib import Path

from .doctor import resolve_binary


def scenario_prefix(directory: Path) -> str:
    node_files = sorted(directory.glob("*.nod.xml"))
    if len(node_files) != 1:
        raise FileNotFoundError(f"Expected exactly one *.nod.xml in {directory}; found {len(node_files)}")
    return node_files[0].name.removesuffix(".nod.xml")


def prepare_sumo_scenario(
    scenario_directory: str | Path,
    *,
    netconvert_binary: str | None = None,
    force: bool = False,
) -> Path:
    directory = Path(scenario_directory).resolve()
    prefix = scenario_prefix(directory)
    nodes = directory / f"{prefix}.nod.xml"
    edges = directory / f"{prefix}.edg.xml"
    network = directory / f"{prefix}.net.xml"
    if network.exists() and not force:
        return network
    if not nodes.exists() or not edges.exists():
        raise FileNotFoundError(f"Missing SUMO nodes or edges in {directory}")
    netconvert = resolve_binary("netconvert", netconvert_binary)
    if not netconvert:
        raise RuntimeError(
            "netconvert was not found. Install SUMO and add its bin directory to PATH, "
            "or set SUMO_HOME/configure sumo.netconvert_binary."
        )
    command = [
        netconvert,
        "--node-files", str(nodes),
        "--edge-files", str(edges),
        "--output-file", str(network),
        "--no-turnarounds", "true",
        "--junctions.join", "false",
    ]
    completed = subprocess.run(command, cwd=directory, capture_output=True, text=True, check=False)
    if completed.returncode != 0 or not network.exists():
        raise RuntimeError(
            "netconvert failed.\n"
            f"Command: {' '.join(command)}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return network
