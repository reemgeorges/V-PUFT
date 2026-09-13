#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

config="configs/full_experiment.json"
weights="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"
output="results/density_architecture_campaign"

vpuft doctor --config "$config"
vpuft density-campaign \
  --config "$config" \
  --weights "$weights" \
  --scenarios sumo/smoke sumo/corridor sumo/intersection sumo/grid \
  --output-dir "$output" \
  --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 \
  --resume

PYTHONPATH=src python scripts/analyze_density_campaign.py \
  --input-dir "$output/combined"

echo "[done] density results: $output/combined"
