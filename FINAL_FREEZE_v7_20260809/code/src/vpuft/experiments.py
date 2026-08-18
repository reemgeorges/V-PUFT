from __future__ import annotations

import json
from dataclasses import replace
from itertools import product
from pathlib import Path

import pandas as pd

from .config import ResearchConfig
from .runner import run_campaign


def run_experiment_grid(config: ResearchConfig, grid_path: str | Path, output_dir: str | Path) -> Path:
    grid = json.loads(Path(grid_path).read_text(encoding="utf-8"))
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows = []

    loads = grid.get("cases_per_seed", [config.simulation.cases_per_seed])
    malicious_ratios = grid.get("malicious_ratio", [config.simulation.malicious_ratio])
    pdrs = grid.get("packet_delivery_ratio", [config.network.packet_delivery_ratio])
    worker_counts = grid.get("central_workers", [config.central.workers])

    for run_id, (load, malicious_ratio, pdr, workers) in enumerate(product(loads, malicious_ratios, pdrs, worker_counts), start=1):
        scenario_cfg = replace(
            config,
            simulation=replace(config.simulation, cases_per_seed=int(load), malicious_ratio=float(malicious_ratio)),
            network=replace(config.network, packet_delivery_ratio=float(pdr)),
            central=replace(config.central, workers=int(workers)),
        )
        run_dir = output / f"run_{run_id:03d}"
        run_campaign(scenario_cfg, run_dir)
        summary = pd.read_csv(run_dir / "architecture_summary.csv")
        summary["run_id"] = run_id
        summary["cases_per_seed"] = load
        summary["malicious_ratio"] = malicious_ratio
        summary["packet_delivery_ratio"] = pdr
        summary["central_workers"] = workers
        rows.append(summary)

    combined = pd.concat(rows, ignore_index=True)
    destination = output / "grid_summary.csv"
    combined.to_csv(destination, index=False)
    return destination
