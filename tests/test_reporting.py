from pathlib import Path

import pandas as pd

from vpuft.reporting import plot_weight_stability


def test_weight_stability_handles_mean_outside_percentile_interval(tmp_path: Path):
    # This can occur with a small, strongly skewed bootstrap sample.
    summary = pd.DataFrame(
        [
            {
                "parameter": "alpha_C",
                "mean": 0.40,
                "std": 0.10,
                "median": 0.20,
                "ci95_low": 0.10,
                "ci95_high": 0.30,
                "coefficient_of_variation": 0.25,
            },
            {
                "parameter": "alpha_eta",
                "mean": 0.30,
                "std": 0.05,
                "median": 0.31,
                "ci95_low": 0.22,
                "ci95_high": 0.39,
                "coefficient_of_variation": 0.17,
            },
        ]
    )
    csv_path = tmp_path / "bootstrap_parameter_summary.csv"
    png_path = tmp_path / "weight_stability.png"
    summary.to_csv(csv_path, index=False)

    plot_weight_stability(csv_path, png_path)

    assert png_path.exists()
    assert png_path.stat().st_size > 0
