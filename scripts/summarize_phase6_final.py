"""Seed-paired summaries and small-sample uncertainty for Phase 6 final holdout."""
from pathlib import Path
import json
import numpy as np
import pandas as pd
from scipy.stats import t

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/post_seminar_phase6_final"
data = pd.read_csv(OUT / "final_paired_comparison.csv")
metrics = ["opportunity_recall", "fixed_protected_fraction", "TP", "FP", "FN", "frr",
           "cpu", "e2e_ms", "messages_per_case", "pdr", "ledger_delay_ms",
           "observed_opportunities", "multi_observer_messages", "multicell_messages"]
summaries = []
for density, group in data.groupby("density"):
    row = {"density": int(density), "n_seeds": len(group)}
    for metric in metrics:
        delta = group[f"candidate_{metric}"].to_numpy() - group[f"baseline_{metric}"].to_numpy()
        mean = float(delta.mean())
        half = float(t.ppf(.975, len(delta)-1) * delta.std(ddof=1) / np.sqrt(len(delta))) if len(delta) > 1 else float("nan")
        row.update({f"{metric}_mean_delta": mean, f"{metric}_median_delta": float(np.median(delta)),
                    f"{metric}_wins": int((delta > 1e-12).sum()), f"{metric}_ties": int((abs(delta) <= 1e-12).sum()),
                    f"{metric}_losses": int((delta < -1e-12).sum()), f"{metric}_ci95_low": mean-half,
                    f"{metric}_ci95_high": mean+half})
    summaries.append(row)
summary = pd.DataFrame(summaries)
summary.to_csv(OUT / "paired_seed_statistics.csv", index=False)
overall = {}
for metric in metrics:
    delta = data[f"candidate_{metric}"] - data[f"baseline_{metric}"]
    by_seed = data.assign(delta=delta).groupby("seed").delta.mean()
    mean = float(by_seed.mean())
    half = float(t.ppf(.975, len(by_seed)-1) * by_seed.std(ddof=1) / np.sqrt(len(by_seed)))
    overall[metric] = {"seed_mean_delta": mean, "seed_ci95": [mean-half, mean+half],
                       "seed_median_delta": float(by_seed.median()),
                       "cohens_dz": float(mean / by_seed.std(ddof=1)) if by_seed.std(ddof=1) else None,
                       "improved_seeds": int((by_seed > 1e-12).sum()), "unchanged_seeds": int((abs(by_seed) <= 1e-12).sum()),
                       "worsened_seeds": int((by_seed < -1e-12).sum())}
(OUT / "paired_seed_statistics.json").write_text(json.dumps({"n_seeds": 4, "n_cells": len(data),
    "ci_method": "two-sided Student t interval on four seed-level paired mean differences; descriptive, underpowered",
    "metrics": overall}, indent=2), encoding="utf-8")
print(summary[["density", "opportunity_recall_mean_delta", "opportunity_recall_wins", "fixed_protected_fraction_mean_delta",
               "fixed_protected_fraction_wins", "TP_mean_delta", "TP_wins", "FP_mean_delta", "FP_wins",
               "cpu_mean_delta", "e2e_ms_mean_delta", "multi_observer_messages_mean_delta"]].to_string(index=False))
