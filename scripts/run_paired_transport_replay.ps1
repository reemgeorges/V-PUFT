$ErrorActionPreference = "Stop"

$SourceRoot = Join-Path $env:USERPROFILE "VPUFT_density_results"
$OutputRoot = Join-Path $env:USERPROFILE "VPUFT_density_paired_replay"
$LogPath = Join-Path $OutputRoot "paired_transport_replay.log"

if (-not (Test-Path (Join-Path $SourceRoot "traces"))) {
    throw "Saved density traces were not found under $SourceRoot\traces"
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

python .\scripts\run_paired_transport_replay.py `
    --source-root $SourceRoot `
    --output-dir $OutputRoot `
    --config .\configs\full_experiment.json `
    --weights .\results\full_campaign_v7\sensitivity_shared_views_mixedfix\selected_weights.json `
    --topologies smoke corridor intersection grid `
    --vehicle-counts 20 40 60 80 100 `
    --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 `
    --resume 2>&1 | Tee-Object -FilePath $LogPath

if ($LASTEXITCODE -ne 0) {
    throw "Paired transport replay failed with exit code $LASTEXITCODE"
}

python .\scripts\analyze_paired_transport_replay.py `
    --input-dir (Join-Path $OutputRoot "combined")

if ($LASTEXITCODE -ne 0) {
    throw "Paired transport analysis failed with exit code $LASTEXITCODE"
}

Get-Content `
    (Join-Path $OutputRoot "combined\PAIRED_TRANSPORT_RESULTS_AUDIT.md") `
    -Encoding UTF8
