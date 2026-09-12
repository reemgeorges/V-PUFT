from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from vpuft.config import load_config
from vpuft.trust_cache import simulate_v2v_trust_cache


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/full_experiment.json")
    parser.add_argument("--output-dir", default="results/extension_frozen_replay/combined")
    args = parser.parse_args()
    config = load_config(args.config)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    rows = [
        simulate_v2v_trust_cache(config, seed=seed, vehicle_count=count, ttl_seconds=ttl)
        for seed in config.simulation.seeds
        for count in config.trust_cache.vehicle_counts
        for ttl in config.trust_cache.ttl_seconds
    ]
    frame = pd.DataFrame(rows)
    frame["messages_per_interaction"] = frame["messages_total"] / frame["interactions"]
    frame["bytes_per_interaction"] = frame["bytes_total"] / frame["interactions"]
    frame["queries_per_interaction"] = frame["v2i_queries"] / frame["interactions"]
    frame.to_csv(output / "v2v_trust_cache_sensitivity.csv", index=False)
    frame.groupby(["vehicle_count", "ttl_seconds"], as_index=False).mean(numeric_only=True).to_csv(
        output / "v2v_trust_cache_summary.csv", index=False
    )


if __name__ == "__main__":
    main()
