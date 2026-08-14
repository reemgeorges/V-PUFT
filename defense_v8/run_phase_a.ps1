$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== V-PUFT DEFENSE v8 / PHASE A ==="
Write-Host "No SUMO, detector, calibration, or experiment replay is performed."
Write-Host ""

$python = "python"

function Run-Step {
    param([string]$Name,[string[]]$CommandArgs)
    Write-Host ""
    Write-Host "=== $Name ==="
    & $python @CommandArgs
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE }
}

Run-Step "Frozen v7 contract" @(
    ".\\defense_v8\\frozen_contract_v8.py",
    "--config", ".\\configs\\full_experiment.json",
    "--weights", ".\\results\\full_campaign_v7\\sensitivity_shared_views_mixedfix\\selected_weights.json",
    "--traces", ".\\results\\full_campaign_v7",
    "--freeze-root", ".\\FINAL_FREEZE_v7_20260809",
    "--write-manifest", ".\\results\\full_campaign_v7\\defense_v8_contract_manifest.json"
)

Run-Step "Paired statistical validation" @(
    ".\\defense_v8\\paired_stats_v8.py",
    "--metrics", ".\\results\\full_campaign_v7\\final_architectures\\final_metrics_by_seed.csv",
    "--decisions", ".\\results\\full_campaign_v7\\final_architectures\\final_decisions.csv",
    "--output", ".\\results\\full_campaign_v7\\statistical_inference",
    "--bootstrap", "10000", "--permutations", "20000", "--seed", "20260814"
)

Run-Step "Case-level agreement" @(
    ".\\defense_v8\\case_agreement_v8.py",
    "--decisions", ".\\results\\full_campaign_v7\\final_architectures\\final_decisions.csv",
    "--output", ".\\results\\full_campaign_v7\\case_agreement",
    "--exact-threshold", "25"
)

Run-Step "Latency decomposition" @(
    ".\\defense_v8\\latency_decomposition_v8.py",
    "--metrics", ".\\results\\full_campaign_v7\\final_architectures\\final_metrics_by_seed.csv",
    "--output", ".\\results\\full_campaign_v7\\latency_decomposition"
)

Write-Host ""
Write-Host "=== PHASE A COMPLETE ===" -ForegroundColor Green
Write-Host "Send these files for review:"
Write-Host "  results\\full_campaign_v7\\statistical_inference\\SUMMARY.md"
Write-Host "  results\\full_campaign_v7\\case_agreement\\SUMMARY.md"
Write-Host "  results\\full_campaign_v7\\latency_decomposition\\SUMMARY.md"
