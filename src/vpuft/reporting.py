from __future__ import annotations

from pathlib import Path

import matplotlib

# Headless backend: reporting only writes image files and must not depend on
# Tcl/Tk or an interactive desktop session.
matplotlib.use("Agg", force=True)

import matplotlib.pyplot as plt
import pandas as pd


def plot_architecture_summary(summary_csv: str | Path, output_png: str | Path) -> None:
    df = pd.read_csv(summary_csv)
    metrics = ["mean_mcc", "mean_recall", "mean_frr", "mean_pdr"]
    available = [m for m in metrics if m in df.columns]
    if not available:
        return
    plot_df = df.set_index("architecture")[available]
    ax = plot_df.plot(kind="bar", figsize=(11, 6))
    ax.set_ylabel("Metric value")
    ax.set_title("V-PUFT architecture comparison")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="best")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()


def plot_weight_stability(summary_csv: str | Path, output_png: str | Path) -> None:
    df = pd.read_csv(summary_csv)
    weights = df[df["parameter"].str.startswith("alpha_")].copy()
    if weights.empty:
        return

    # Use the bootstrap median as the plotted centre because it is guaranteed
    # to lie inside the percentile interval. A skewed bootstrap distribution
    # can place the arithmetic mean outside [ci95_low, ci95_high], which makes
    # Matplotlib reject the resulting negative asymmetric error length.
    centre = weights["median"].astype(float)
    ci_low = weights[["ci95_low", "ci95_high"]].min(axis=1).astype(float)
    ci_high = weights[["ci95_low", "ci95_high"]].max(axis=1).astype(float)
    lower = (centre - ci_low).clip(lower=0.0)
    upper = (ci_high - centre).clip(lower=0.0)

    plot_df = weights.assign(plot_value=centre)
    ax = plot_df.plot(
        x="parameter",
        y="plot_value",
        kind="bar",
        yerr=[lower.to_numpy(), upper.to_numpy()],
        legend=False,
        figsize=(9, 5),
        capsize=4,
    )
    ax.set_ylabel("Selected exponent (bootstrap median)")
    ax.set_title("Bootstrap stability of V-PUFT weights")
    ax.set_ylim(0, max(0.5, float(ci_high.max()) + 0.05))
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()
