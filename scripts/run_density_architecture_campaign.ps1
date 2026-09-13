$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$Config = "configs/full_experiment.json"
$Weights = "results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"
$Output = "results/density_architecture_campaign"
$Seeds = @(1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010)
$Scenarios = @("sumo/smoke", "sumo/corridor", "sumo/intersection", "sumo/grid")

Write-Host "[density] checking SUMO and TraCI"
vpuft doctor --config $Config

Write-Host "[density] 4 topologies x 5 vehicle counts x 10 seeds"
Write-Host "[density] each trace is shared by Distributed RSU and all Centralized Remote levels"
vpuft density-campaign `
    --config $Config `
    --weights $Weights `
    --scenarios $Scenarios `
    --output-dir $Output `
    --seeds $Seeds `
    --resume

$env:PYTHONPATH = "src"
python scripts/analyze_density_campaign.py `
    --input-dir "$Output/combined"

Write-Host "[done] density results: $Output/combined"
