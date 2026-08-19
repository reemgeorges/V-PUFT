# V-PUFT final reproduction runbook

Historical baseline: `files/clean @ 10b7ab507351818a7d8a1685d13a6c6b5cfd867b`.

## LFS
```powershell
git lfs install
git lfs pull
git lfs status
```
Unresolved LFS pointer text is not scientific data; report a missing object as a blocker.

## Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

### Exact-environment limitation
The frozen baseline does not contain a dependency lockfile or captured `pip freeze`, so the exact package versions
used by the original run are not reconstructible from the repository alone. `pyproject.toml` records version ranges,
not an exact environment. A reproduction must therefore record its own:
```powershell
python --version
pip freeze
```
This is a reproducibility limitation, not evidence that the frozen numerical results were regenerated.


## Effective final configuration
Base config: `configs/full_experiment.json`.
Final candidate-650 weights come from
`results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json`.
The embedded default weights in the base config are not the final replay weights.
`selection_feasible=false` must remain explicit.

`effective_final_configuration.json` contains a self-contained runtime snapshot equal to
`configs/full_experiment.json` at the frozen baseline with **only** the `weights` object replaced by the selected
candidate-650 weights, matching `replay_final_v7.py`.

## Replay without SUMO/recalibration
The CLI default output is intentionally outside the frozen tree: `reproduction_check/final_architectures`.
Use a new output folder:
```powershell
python replay_final_v7.py `
  --input-v4 results/full_campaign_v7 `
  --output reproduction_check/final_architectures `
  --config configs/full_experiment.json `
  --weights results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json
```

Centralized and Distributed consume `bundle.rsu_cases`; Ahmed consumes `bundle.witness_cases`.
The frozen baseline has `validator_behaviors={}` and does not support an empirical Byzantine-safety claim.
MCC is descriptive only after Holm (adjusted p≈0.1986).
Authenticated message-exchange integration methods are compared empirically; cryptographic-primitive benchmarking was not executed beyond the deliberately constant Ed25519 primitive.
