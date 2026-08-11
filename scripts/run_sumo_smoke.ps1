$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
vpuft doctor --config configs/sumo_smoke.json
vpuft prepare-sumo --config configs/sumo_smoke.json --force
vpuft sumo-trace --config configs/sumo_smoke.json --scenario-dir sumo/smoke --seed 1001 --output-dir results/sumo_seed_1001
vpuft replay --config configs/sumo_smoke.json --trace results/sumo_seed_1001/shared_detection_trace.jsonl --output-dir results/sumo_seed_1001_models
