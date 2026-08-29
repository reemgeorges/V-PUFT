#!/usr/bin/env bash
set -euo pipefail
python ./defense_v8/frozen_contract_v8.py --config ./configs/full_experiment.json --weights ./results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json --traces ./results/full_campaign_v7 --freeze-root ./FINAL_FREEZE_v7_20260809 --write-manifest ./results/full_campaign_v7/defense_v8_contract_manifest.json
python ./defense_v8/paired_stats_v8.py --metrics ./results/full_campaign_v7/final_architectures/final_metrics_by_seed.csv --decisions ./results/full_campaign_v7/final_architectures/final_decisions.csv --output ./results/full_campaign_v7/statistical_inference --bootstrap 10000 --permutations 20000 --seed 20260814
python ./defense_v8/case_agreement_v8.py --decisions ./results/full_campaign_v7/final_architectures/final_decisions.csv --output ./results/full_campaign_v7/case_agreement --exact-threshold 25
python ./defense_v8/latency_decomposition_v8.py --metrics ./results/full_campaign_v7/final_architectures/final_metrics_by_seed.csv --output ./results/full_campaign_v7/latency_decomposition
echo "=== PHASE A COMPLETE ==="
