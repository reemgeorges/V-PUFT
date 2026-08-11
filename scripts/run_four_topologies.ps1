$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
vpuft doctor --config configs/full_experiment.json
foreach ($scenario in @("sumo/smoke", "sumo/corridor", "sumo/intersection", "sumo/grid")) {
    vpuft prepare-sumo --config configs/full_experiment.json --scenario-dir $scenario
}
vpuft topology-campaign --config configs/full_experiment.json --scenarios sumo/smoke sumo/corridor sumo/intersection sumo/grid --output-dir results/four_topologies --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 --sensitivity --candidates 5000 --bootstrap-repeats 500 --min-recall 0.95 --max-frr 0.05
