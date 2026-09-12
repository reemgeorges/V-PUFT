$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$Config = "configs/full_experiment.json"
$Weights = "results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"
$OutputRoot = "results/extension_frozen_replay"

foreach ($Topology in @("smoke", "corridor", "intersection", "grid")) {
    $OutputDir = Join-Path $OutputRoot $Topology
    $Manifest = Join-Path $OutputDir "extension_manifest.json"
    if (Test-Path $Manifest) {
        Write-Host "[resume] $Topology already complete"
        continue
    }
    Write-Host "[extension] replaying frozen $Topology trace; SUMO=NO; Centralized Near-Edge=NO"
    $env:PYTHONPATH = "src"
    python -m vpuft.cli extension-campaign `
        --config $Config `
        --weights $Weights `
        --traces "results/full_campaign_v7/$Topology/sensor_detection_trace_all_seeds.jsonl" `
        --output-dir $OutputDir
}

$env:PYTHONPATH = "src"
python scripts/combine_extension_results.py `
    --input-root $OutputRoot `
    --output-dir "$OutputRoot/combined"
$env:PYTHONPATH = "src"
python scripts/run_v2v_cache_sensitivity.py `
    --config $Config `
    --output-dir "$OutputRoot/combined"
$env:PYTHONPATH = "src"
python scripts/analyze_extension_results.py `
    --input-dir "$OutputRoot/combined"

Write-Host "[done] combined results: $OutputRoot/combined"
