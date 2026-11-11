import pandas as pd

from scripts.run_phase2_ablation import select_profile_trace


def test_profile_trace_selection_supports_single_cell_smoke_runs():
    traces = pd.DataFrame([{"density": 20, "seed": 1001, "trace_path": "trace.jsonl"}])
    selected = select_profile_trace(traces)
    assert selected.trace_path == "trace.jsonl"
