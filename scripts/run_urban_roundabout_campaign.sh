#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

vpuft density-campaign \
  --config configs/urban_roundabout_campaign.json \
  --weights results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json \
  --scenarios sumo/urban_roundabout \
  --output-dir results/urban_roundabout_campaign \
  --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 \
  --resume

python scripts/analyze_density_campaign.py \
  --input-dir results/urban_roundabout_campaign/combined

python scripts/capture_urban_roundabout_snapshot.py \
  --output results/urban_roundabout_campaign/scenario_5_sumo_reference_style_60_seed_1001.png \
  --vehicles 60 \
  --seed 1001 \
  --time 25

python scripts/summarize_urban_roundabout_terminal.py \
  --campaign results/urban_roundabout_campaign
