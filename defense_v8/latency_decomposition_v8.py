"""
V-PUFT v8 - Latency decomposition (rewritten).

POST-FREEZE ANALYSIS. No experiment is re-run.

WHY THE PREVIOUS VERSION WAS DISCARDED
--------------------------------------
It fell back to reconstructing the case open time as

    opened = groupby("case_id")["detected_at"].min()

That is not case_opened_at. It invents the start of the case from whichever
architecture detected first, which drives the detection stage artificially
toward zero. That must never reach the thesis. This version does not
reconstruct anything.

WHAT CHANGED
------------
The decomposition is read directly from final_metrics_by_seed.csv, because
metrics.py already computes the three stages as INDEPENDENT durations:

    detection_latency_p95_ms      detected_at  - case_opened_at
    qualification_latency_p95_ms  qualified_at - detected_at
    consensus_latency_p95_ms      finalized_at - qualified_at
    latency_p95_ms                finalized_at - case_opened_at

(verified in metrics.py lines 43-50: each append is a stage delta, not a
cumulative sum). So no reconstruction is needed and no new export is required.

TWO HARD RULES ENFORCED BY THIS SCRIPT
--------------------------------------
1. NO STACKED BARS. P95(A) + P95(B) + P95(C) != P95(A+B+C). Percentiles are
   not additive. The figure produced here is GROUPED, never stacked, and the
   script refuses to emit a "sum of stages" column.

2. NO SHARE-OF-TOTAL. Statements like "qualification is X% of P95" require
   paired per-case timings, which are not exported. If --share is requested
   without a real case_opened_at column, the script fails closed rather than
   approximating.

Because each row is a per-seed P95, the aggregate reported here is the
distribution of per-seed P95 values across the 40 seed-topology units. That is
stated explicitly in the output and must be stated in the thesis too.

USAGE
-----
  python latency_decomposition_v8.py \
      --metrics results/full_campaign_v7/final_architectures/final_metrics_by_seed.csv \
      --output  results/full_campaign_v7/latency_decomposition
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

ARCH_ORDER = [
    "centralized_vpuft",
    "distributed_rsu_vpuft",
    "ahmed_inspired_witness_vpuft",
]

ARCH_LABEL = {
    "centralized_vpuft": "Centralized V-PUFT",
    "distributed_rsu_vpuft": "Distributed RSU V-PUFT",
    "ahmed_inspired_witness_vpuft": "Ahmed-Inspired Witness V-PUFT",
}

STAGE_COLUMNS = {
    "detection_latency_p95_ms": "Detection / evidence acquisition",
    "qualification_latency_p95_ms": "Qualification (V-PUFT)",
    "consensus_latency_p95_ms": "Finalization (central or PBFT)",
}

TOTAL_COLUMN = "latency_p95_ms"

# Interpretation labels only. We deliberately do NOT label the detection stage
# as "shared" or "not architecture-attributable": the final data show that its
# P95 can differ across architectures, and evidence source/delivery path can be
# part of the broader architectural effect.
STAGE_SCOPE = {
    "detection_latency_p95_ms":
        "Evidence acquisition/detection; may vary with evidence view and delivery path",
    "qualification_latency_p95_ms":
        "V-PUFT qualification after detection",
    "consensus_latency_p95_ms":
        "Finalization path; cleanest Central-vs-PBFT comparison",
    TOTAL_COLUMN:
        "End-to-end case latency from case opening to finalization",
}


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest().upper()


def describe(series: pd.Series) -> dict[str, float]:
    s = series.dropna()
    if s.empty:
        return {"median": np.nan, "q1": np.nan, "q3": np.nan,
                "min": np.nan, "max": np.nan, "mean": np.nan, "n_seeds": 0}
    return {
        "median": float(s.median()),
        "q1": float(s.quantile(0.25)),
        "q3": float(s.quantile(0.75)),
        "min": float(s.min()),
        "max": float(s.max()),
        "mean": float(s.mean()),
        "n_seeds": int(s.size),
    }


def paired_stage_test(wide: pd.DataFrame, stage: str, a: str, b: str) -> dict:
    """Paired comparison of a single stage across the same seed-topology units."""
    if (stage, a) not in wide.columns or (stage, b) not in wide.columns:
        return {}
    va = wide[(stage, a)].to_numpy(dtype=float)
    vb = wide[(stage, b)].to_numpy(dtype=float)
    mask = np.isfinite(va) & np.isfinite(vb)
    va, vb = va[mask], vb[mask]
    if va.size < 3:
        return {}
    diff = vb - va
    try:
        from scipy.stats import wilcoxon  # type: ignore
        d = diff[diff != 0]
        _, p = wilcoxon(d, alternative="two-sided") if d.size else (np.nan, np.nan)
    except Exception:
        p = np.nan
    return {
        "stage": stage,
        "arch_a": ARCH_LABEL.get(a, a),
        "arch_b": ARCH_LABEL.get(b, b),
        "n_pairs": int(va.size),
        "median_a_ms": float(np.median(va)),
        "median_b_ms": float(np.median(vb)),
        "median_difference_ms": float(np.median(diff)),
        "wilcoxon_p": float(p) if np.isfinite(p) else np.nan,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Post-freeze latency decomposition.")
    ap.add_argument("--metrics", required=True, help="final_metrics_by_seed.csv")
    ap.add_argument("--output", default="results/full_campaign_v7/latency_decomposition")
    ap.add_argument("--share", action="store_true",
                    help="Attempt share-of-total analysis. Fails closed without per-case timings.")
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.metrics)

    # ---- fail closed on missing stage columns ----
    missing = [c for c in STAGE_COLUMNS if c not in df.columns]
    if missing:
        print("FAIL CLOSED: the metrics file does not contain the stage columns:",
              file=sys.stderr)
        for c in missing:
            print(f"  - {c}", file=sys.stderr)
        print("\nThis script will NOT reconstruct stage boundaries from decision "
              "timestamps. Re-export metrics_by_seed.csv from the frozen runner "
              "instead.", file=sys.stderr)
        sys.exit(2)

    if args.share:
        print("FAIL CLOSED: share-of-total requires paired per-case timings "
              "(case_opened_at per decision), which are not exported by the frozen "
              "runner. Reporting a stage as a percentage of the P95 total would be "
              "arithmetically invalid because percentiles are not additive.",
              file=sys.stderr)
        sys.exit(2)

    print("=== POST-FREEZE LATENCY DECOMPOSITION ===")
    print("No experiment is re-run. Reading stage durations already computed by metrics.py.")
    print("Unit of analysis: per-seed P95, aggregated across seed-topology units.\n")

    present = [a for a in ARCH_ORDER if a in set(df["architecture"].unique())]

    # ---- per-architecture stage distributions ----
    rows = []
    for arch in present:
        grp = df[df["architecture"] == arch]
        for col, label in STAGE_COLUMNS.items():
            rows.append({
                "architecture": ARCH_LABEL[arch],
                "stage": label,
                "stage_column": col,
                "interpretation_scope": STAGE_SCOPE[col],
                **describe(grp[col]),
            })
        if TOTAL_COLUMN in grp.columns:
            rows.append({
                "architecture": ARCH_LABEL[arch],
                "stage": "End-to-end (NOT the sum of the stages above)",
                "stage_column": TOTAL_COLUMN,
                "interpretation_scope": STAGE_SCOPE[TOTAL_COLUMN],
                **describe(grp[TOTAL_COLUMN]),
            })
    comp = pd.DataFrame(rows)
    comp.to_csv(out / "latency_stages.csv", index=False)
    print(f"[1] wrote latency_stages.csv ({len(comp)} rows)")

    # ---- paired stage comparisons ----
    key_cols = [c for c in ("topology", "seed") if c in df.columns]
    stage_cols = list(STAGE_COLUMNS) + ([TOTAL_COLUMN] if TOTAL_COLUMN in df.columns else [])
    wide = df.pivot_table(index=key_cols, columns="architecture", values=stage_cols, aggfunc="mean")

    test_rows = []
    for stage in stage_cols:
        for a, b in combinations(present, 2):
            r = paired_stage_test(wide, stage, a, b)
            if r:
                r["stage_label"] = STAGE_COLUMNS.get(stage, "End-to-end")
                r["interpretation_scope"] = STAGE_SCOPE.get(stage, "End-to-end case latency")
                test_rows.append(r)
    tests = pd.DataFrame(test_rows)
    tests.to_csv(out / "latency_paired_tests.csv", index=False)
    print(f"[2] wrote latency_paired_tests.csv ({len(tests)} rows)")

    # ---- grouped figure, never stacked ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        stages = list(STAGE_COLUMNS)
        labels = [ARCH_LABEL[a] for a in present]
        x = np.arange(len(stages))
        width = 0.8 / max(1, len(present))

        fig, ax = plt.subplots(figsize=(10, 5.5))
        for i, arch in enumerate(present):
            grp = df[df["architecture"] == arch]
            vals = [grp[c].median() for c in stages]
            ax.bar(x + i * width - 0.4 + width / 2, vals, width,
                   label=ARCH_LABEL[arch])

        ax.set_xticks(x)
        ax.set_xticklabels([STAGE_COLUMNS[c] for c in stages], rotation=10, ha="center")
        ax.set_ylabel("Median of per-seed P95 (ms)")
        ax.set_title("Decision latency by stage (stages shown separately; percentiles are not additive)")
        ax.set_yscale("log")
        ax.legend()
        plt.tight_layout()
        fig.savefig(out / "latency_stages_grouped.png", dpi=200)
        plt.close(fig)
        print("[3] wrote latency_stages_grouped.png (grouped, log scale, not stacked)")
    except Exception as exc:
        print(f"[3] figure skipped: {exc}")

    # ---- narrative ----
    lines = ["# Latency Decomposition (V-PUFT v8, post-freeze)\n"]
    lines.append("No experiment was re-run. Stage durations are read from the frozen")
    lines.append("`final_metrics_by_seed.csv`, where metrics.py already defines them as")
    lines.append("independent stage deltas rather than cumulative sums.\n")
    lines.append("**Unit of analysis:** each row is a per-seed P95; the tables report the")
    lines.append("distribution of those per-seed P95 values across the seed-topology units.\n")
    lines.append("**Arithmetic warning carried into the thesis:** the stage values below do")
    lines.append("not sum to the end-to-end value, and must never be drawn as a stacked bar.")
    lines.append("P95(A) + P95(B) + P95(C) is not P95(A+B+C).\n")

    lines.append("## Stage medians (of per-seed P95, ms)\n")
    lines.append("| Architecture | Stage | Median | IQR | Interpretation scope |")
    lines.append("|---|---|---|---|---|")
    for _, r in comp.iterrows():
        iqr = (f"{r['q1']:.1f} - {r['q3']:.1f}" if np.isfinite(r["q1"]) else "-")
        med = f"{r['median']:.1f}" if np.isfinite(r["median"]) else "-"
        lines.append(
            f"| {r['architecture']} | {r['stage']} | {med} | {iqr} | "
            f"{r['interpretation_scope']} |"
        )

    if not tests.empty:
        lines.append("\n## Paired stage comparisons\n")
        lines.append("| Stage | Comparison | n | Median diff (ms) | Wilcoxon p | Interpretation scope |")
        lines.append("|---|---|---|---|---|---|")
        for _, r in tests.iterrows():
            p = f"{r['wilcoxon_p']:.4g}" if np.isfinite(r["wilcoxon_p"]) else "-"
            lines.append(
                f"| {r['stage_label']} | {r['arch_b']} vs {r['arch_a']} | {r['n_pairs']} | "
                f"{r['median_difference_ms']:+.2f} | {p} | "
                f"{r['interpretation_scope']} |"
            )

    lines.append("\n## Text for section 5.12 - place BEFORE any number\n")
    lines.append(
        "> The end-to-end value reported here is measured from the opening of an evidence "
        "case until finalization, not from the arrival of a single V2X message. It therefore "
        "includes evidence acquisition/detection, V-PUFT qualification and finalization. "
        "The detection/evidence-acquisition stage is not assumed to be identical across "
        "architectures: it may vary with the evidence view and delivery path and is therefore "
        "part of the broader architectural comparison. The qualification stage reports the "
        "V-PUFT interval after detection, while the finalization stage is the cleanest measure "
        "for comparing centralized finalization with PBFT. The end-to-end figure is not a "
        "single-message dissemination latency and should not be interpreted as such. Finally, "
        "the reported values are percentiles and are not additive: P95(A)+P95(B)+P95(C) is "
        "not P95(A+B+C), so the stages are shown separately and no share-of-total claim is made.\n"
    )
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "analysis_type": "post_freeze_latency_decomposition",
        "experiments_rerun": False,
        "stage_source": "final_metrics_by_seed.csv (metrics.py stage deltas)",
        "reconstruction_used": False,
        "stacked_visualisation": False,
        "share_of_total_reported": False,
        "share_of_total_blocked_reason": "requires paired per-case timings; percentiles are not additive",
        "detection_stage_assumed_shared_across_architectures": False,
        "finalization_stage_is_cleanest_central_vs_pbft_comparison": True,
        "input_metrics": args.metrics,
        "input_metrics_sha256": sha256_file(args.metrics),
    }
    (out / "latency_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n[done] -> {out}")


if __name__ == "__main__":
    main()
