from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


TOPOLOGIES = ("smoke", "corridor", "intersection", "grid")
TABLES = (
    "extension_metrics_by_seed.csv",
    "extension_decisions.csv",
    "extension_case_agreement.csv",
    "extension_network_messages.csv",
    "extension_consensus_outcomes.csv",
    "compromised_evidence_injection_audit.csv",
)


def _read_many(root: Path, filename: str) -> pd.DataFrame:
    frames = []
    for topology in TOPOLOGIES:
        path = root / topology / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing completed extension output: {path}")
        frame = pd.read_csv(path)
        if "topology" not in frame.columns:
            frame.insert(0, "topology", topology)
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", default="results/extension_frozen_replay")
    parser.add_argument("--output-dir", default="results/extension_frozen_replay/combined")
    args = parser.parse_args()
    root = Path(args.input_root)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    tables = {filename: _read_many(root, filename) for filename in TABLES}
    for filename, frame in tables.items():
        frame.to_csv(output / filename, index=False)

    metrics = tables["extension_metrics_by_seed.csv"]
    metrics.groupby("architecture", as_index=False).mean(numeric_only=True).to_csv(
        output / "extension_global_summary.csv", index=False
    )
    metrics.groupby(["topology", "architecture"], as_index=False).mean(numeric_only=True).to_csv(
        output / "extension_topology_summary.csv", index=False
    )

    v2v_frames = [pd.read_csv(root / topology / "v2v_trust_cache_sensitivity.csv") for topology in TOPOLOGIES]
    v2v = pd.concat(v2v_frames, ignore_index=True).drop_duplicates(
        subset=["seed", "vehicle_count", "ttl_seconds"]
    )
    v2v.to_csv(output / "v2v_trust_cache_sensitivity.csv", index=False)
    v2v.groupby(["vehicle_count", "ttl_seconds"], as_index=False).mean(numeric_only=True).to_csv(
        output / "v2v_trust_cache_summary.csv", index=False
    )

    manifest = {
        "campaign": "post_freeze_extension_combined",
        "topologies": list(TOPOLOGIES),
        "centralized_near_edge_rerun": False,
        "source": "frozen v7 sensor traces; no SUMO rerun",
        "files": sorted(path.name for path in output.iterdir() if path.is_file()),
    }
    (output / "combined_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
