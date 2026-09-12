#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-python}"
CONFIG="configs/full_experiment.json"
WEIGHTS="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"
OUTPUT_ROOT="${OUTPUT_ROOT:-results/extension_frozen_replay}"

for topology in smoke corridor intersection grid; do
  output_dir="$OUTPUT_ROOT/$topology"
  manifest="$output_dir/extension_manifest.json"
  if [[ -f "$manifest" ]]; then
    echo "[resume] $topology already complete"
    continue
  fi
  echo "[extension] replaying frozen $topology trace; SUMO=NO; Centralized Near-Edge=NO"
  PYTHONPATH=src "$PYTHON_BIN" -m vpuft.cli extension-campaign \
    --config "$CONFIG" \
    --weights "$WEIGHTS" \
    --traces "results/full_campaign_v7/$topology/sensor_detection_trace_all_seeds.jsonl" \
    --output-dir "$output_dir"
done

PYTHONPATH=src "$PYTHON_BIN" scripts/combine_extension_results.py \
  --input-root "$OUTPUT_ROOT" \
  --output-dir "$OUTPUT_ROOT/combined"
PYTHONPATH=src "$PYTHON_BIN" scripts/run_v2v_cache_sensitivity.py \
  --config "$CONFIG" \
  --output-dir "$OUTPUT_ROOT/combined"
PYTHONPATH=src "$PYTHON_BIN" scripts/analyze_extension_results.py \
  --input-dir "$OUTPUT_ROOT/combined"

echo "[done] combined results: $OUTPUT_ROOT/combined"
