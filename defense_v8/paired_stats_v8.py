"""
V-PUFT v8 - Paired statistical inference (corrected).

POST-FREEZE STATISTICAL VALIDATION. No experiment is re-run by this script.
It reads the frozen v7 result files and produces intervals, paired tests and
effect sizes. Nothing it writes replaces any v7 number.

CORRECTIONS APPLIED IN THIS VERSION
-----------------------------------
1. STRATIFIED cluster bootstrap. The previous version resampled all 40
   (topology, seed) clusters from one pool, so a replicate could contain
   17 grid and 4 smoke. Topology is a fixed design factor here, not a random
   sample from a population of topologies, so each replicate now resamples
   10 clusters WITHIN each topology and preserves the 4x10 design.

2. Cliff's delta REMOVED. It is an independent-samples effect size and the
   design is paired. Replaced with matched-pairs rank-biserial correlation
   plus Cohen's dz.

3. Multiple-comparison families SEPARATED. Holm correction is applied to a
   small predeclared primary family (recall, FRR, MCC) only. Precision, F1,
   latency, messages, bytes and memory form a separate exploratory family and
   are labelled as such. Correcting 27 tests as one family and then calling
   all of them primary is not defensible.

4. Holm reporting is explicit. The primary-family table now records both the
   raw paired p-value and the Holm-adjusted p-value, plus the Holm reject flag.
   This avoids the misleading presentation of (for example) raw p < 0.05 next
   to a non-significant Holm-corrected decision without showing why.

5. Frozen-contract check is optional here (this script touches no config), but
   the RNG seed is recorded in the manifest so every interval is reproducible.

USAGE
-----
  python paired_stats_v8.py \
      --metrics   results/full_campaign_v7/final_architectures/final_metrics_by_seed.csv \
      --decisions results/full_campaign_v7/final_architectures/final_decisions.csv \
      --output    results/full_campaign_v7/statistical_inference \
      --bootstrap 10000 --permutations 20000 --seed 20260814
"""

from __future__ import annotations

import argparse
import hashlib
import json
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

# Predeclared PRIMARY family. Holm correction is applied to these only.
PRIMARY_METRICS = {
    "malicious_revocation_recall": +1,
    "false_revocation_rate": -1,
    "mcc": +1,
}

# Exploratory family. Reported with uncorrected p-values, explicitly labelled.
SECONDARY_METRICS = {
    "trust_precision": +1,
    "trust_f1": +1,
    "latency_p95_ms": -1,
    "messages_per_decision": -1,
    "bytes_per_decision": -1,
    "peak_memory_kb": -1,
}

PRIMARY_POOLED = ["recall", "frr", "mcc"]
SECONDARY_POOLED = ["precision", "f1"]


# ---------------------------------------------------------------------------
# Reproducibility helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Confusion metrics
# ---------------------------------------------------------------------------

def _safe_div(num: float, den: float) -> float:
    return float(num) / float(den) if den else float("nan")


def pooled_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    frr = _safe_div(fp, fp + tn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else float("nan")
    denom = np.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": precision, "recall": recall,
        "frr": frr, "f1": f1, "mcc": _safe_div(tp * tn - fp * fn, denom),
    }


# ---------------------------------------------------------------------------
# Stratified cluster bootstrap
# ---------------------------------------------------------------------------

def stratified_cluster_bootstrap(
    decisions: pd.DataFrame,
    arch_a: str,
    arch_b: str,
    n_boot: int,
    rng: np.random.Generator,
    stratum_col: str | None,
    cluster_cols: list[str],
) -> tuple[dict[str, dict[str, float]], dict[str, int]]:
    """
    Resample whole (topology, seed) clusters WITHIN each topology.

    Two properties matter for the defence:

      - Clusters, not rows. Cases inside one seed share a mobility trace and are
        not independent. Row-level resampling would produce intervals that are
        far too narrow.

      - Stratified by topology. The campaign design is a fixed 4 x 10 grid.
        Topology is a controlled factor, not a draw from a population of
        possible topologies, so every replicate must keep the same topology
        composition. Otherwise the interval absorbs between-topology variance
        that the design deliberately fixed.
    """
    sub = decisions[decisions["architecture"].isin([arch_a, arch_b])].copy()
    sub["_cluster"] = sub[cluster_cols].astype(str).agg("|".join, axis=1)

    store: dict[str, dict[str, tuple[np.ndarray, np.ndarray]]] = {}
    cluster_stratum: dict[str, str] = {}

    for cluster, grp in sub.groupby("_cluster", sort=True):
        entry = {}
        for arch in (arch_a, arch_b):
            g = grp[grp["architecture"] == arch]
            entry[arch] = (
                g["ground_truth_malicious"].to_numpy(dtype=np.int8),
                g["predicted_revoked"].to_numpy(dtype=np.int8),
            )
        store[cluster] = entry
        if stratum_col and stratum_col in grp.columns:
            cluster_stratum[cluster] = str(grp[stratum_col].iloc[0])
        else:
            cluster_stratum[cluster] = "_all"

    # Group cluster ids by stratum, preserving the design composition.
    strata: dict[str, list[str]] = {}
    for cluster, stratum in cluster_stratum.items():
        strata.setdefault(stratum, []).append(cluster)
    for key in strata:
        strata[key].sort()

    composition = {k: len(v) for k, v in strata.items()}
    if sum(composition.values()) < 2:
        raise ValueError("Need at least 2 clusters for a bootstrap.")

    strata_arrays = {k: np.array(v) for k, v in strata.items()}
    metric_names = ["recall", "frr", "precision", "f1", "mcc"]
    draws = {m: np.empty(n_boot, dtype=float) for m in metric_names}

    for b in range(n_boot):
        picked: list[str] = []
        for key, arr in strata_arrays.items():
            # Same number of clusters drawn from this stratum every replicate.
            idx = rng.integers(0, arr.size, size=arr.size)
            picked.extend(arr[idx].tolist())
        ya = np.concatenate([store[c][arch_a][0] for c in picked])
        pa = np.concatenate([store[c][arch_a][1] for c in picked])
        yb = np.concatenate([store[c][arch_b][0] for c in picked])
        pb = np.concatenate([store[c][arch_b][1] for c in picked])
        ma = pooled_metrics(ya, pa)
        mb = pooled_metrics(yb, pb)
        for m in metric_names:
            draws[m][b] = mb[m] - ma[m]

    all_clusters = sorted(store.keys())
    ya = np.concatenate([store[c][arch_a][0] for c in all_clusters])
    pa = np.concatenate([store[c][arch_a][1] for c in all_clusters])
    yb = np.concatenate([store[c][arch_b][0] for c in all_clusters])
    pb = np.concatenate([store[c][arch_b][1] for c in all_clusters])
    obs_a = pooled_metrics(ya, pa)
    obs_b = pooled_metrics(yb, pb)

    out: dict[str, dict[str, float]] = {}
    for m in metric_names:
        d = draws[m][np.isfinite(draws[m])]
        lo, hi = (np.percentile(d, [2.5, 97.5]) if d.size else (np.nan, np.nan))
        out[m] = {
            "value_a": obs_a[m],
            "value_b": obs_b[m],
            "difference": obs_b[m] - obs_a[m],
            "ci_low": float(lo),
            "ci_high": float(hi),
            "excludes_zero": bool(np.isfinite(lo) and np.isfinite(hi) and (lo > 0 or hi < 0)),
            "n_clusters": len(all_clusters),
        }
    return out, composition


# ---------------------------------------------------------------------------
# Paired tests and paired effect sizes
# ---------------------------------------------------------------------------

def wilcoxon_signed_rank(diff: np.ndarray) -> tuple[float, float]:
    d = diff[diff != 0]
    if d.size == 0:
        return float("nan"), float("nan")
    try:
        from scipy.stats import wilcoxon  # type: ignore
        stat, p = wilcoxon(d, alternative="two-sided", zero_method="wilcox")
        return float(stat), float(p)
    except Exception:
        return float("nan"), float("nan")


def paired_permutation_p(diff: np.ndarray, n_perm: int, rng: np.random.Generator) -> float:
    """Sign-flip permutation test. Under the null the sign of each pair is exchangeable."""
    d = diff[np.isfinite(diff)]
    if d.size == 0:
        return float("nan")
    observed = abs(d.mean())
    signs = rng.choice(np.array([-1.0, 1.0]), size=(n_perm, d.size))
    null = np.abs((signs * d).mean(axis=1))
    return float((np.sum(null >= observed) + 1) / (n_perm + 1))


def cohens_dz(diff: np.ndarray) -> float:
    d = diff[np.isfinite(diff)]
    sd = d.std(ddof=1)
    return float(d.mean() / sd) if d.size > 1 and sd > 0 else float("nan")


def matched_pairs_rank_biserial(diff: np.ndarray) -> float:
    """
    Matched-pairs rank-biserial correlation.

        r = (sum of positive ranks - sum of negative ranks) / total rank sum

    ranks are taken on |diff| over the non-zero differences. This is the
    effect size that belongs with Wilcoxon signed-rank, and unlike Cliff's
    delta it respects the pairing in the design.

    Range is [-1, +1]. +1 means arch_b exceeded arch_a on every pair.
    """
    d = diff[np.isfinite(diff)]
    d = d[d != 0]
    if d.size == 0:
        return float("nan")
    try:
        from scipy.stats import rankdata  # type: ignore
        ranks = rankdata(np.abs(d))
    except Exception:
        order = np.argsort(np.abs(d), kind="mergesort")
        ranks = np.empty(d.size, dtype=float)
        ranks[order] = np.arange(1, d.size + 1, dtype=float)
    total = ranks.sum()
    if total == 0:
        return float("nan")
    return float((ranks[d > 0].sum() - ranks[d < 0].sum()) / total)


def interpret_rb(r: float) -> str:
    if not np.isfinite(r):
        return "undefined"
    a = abs(r)
    if a < 0.1:
        return "negligible"
    if a < 0.3:
        return "small"
    if a < 0.5:
        return "medium"
    return "large"


def holm_bonferroni(
    pvals: list[float], alpha: float = 0.05
) -> tuple[list[float], list[bool]]:
    """
    Holm step-down family-wise error-rate correction.

    Returns
    -------
    adjusted_p : list[float]
        Holm-adjusted p-values in the ORIGINAL input order. Non-finite input
        p-values remain NaN. The monotonic cumulative-maximum form is used:

            p_adj(i) = max_{j<=i} ((m-j+1) * p_(j)), capped at 1.

    reject : list[bool]
        True exactly where the Holm-adjusted p-value is <= alpha.

    Keeping both values is important for the thesis table: a raw p-value can
    be below 0.05 while the Holm-adjusted p-value is above 0.05.
    """
    n = len(pvals)
    adjusted = [float("nan")] * n
    reject = [False] * n

    finite_idx = [i for i, p in enumerate(pvals) if np.isfinite(p)]
    if not finite_idx:
        return adjusted, reject

    order = sorted(finite_idx, key=lambda i: float(pvals[i]))
    m = len(order)

    running_max = 0.0
    for sorted_rank, original_i in enumerate(order):
        multiplier = m - sorted_rank
        candidate = multiplier * float(pvals[original_i])
        running_max = max(running_max, candidate)
        adjusted[original_i] = min(1.0, running_max)

    for i in finite_idx:
        reject[i] = bool(adjusted[i] <= alpha)

    return adjusted, reject


# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Post-freeze paired statistical validation.")
    ap.add_argument("--metrics", required=True)
    ap.add_argument("--decisions", required=True)
    ap.add_argument("--output", default="results/full_campaign_v7/statistical_inference")
    ap.add_argument("--bootstrap", type=int, default=10000)
    ap.add_argument("--permutations", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=20260814)
    ap.add_argument("--alpha", type=float, default=0.05)
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(args.seed)

    metrics = pd.read_csv(args.metrics)
    decisions = pd.read_csv(args.decisions)

    cluster_cols = [c for c in ("topology", "seed") if c in decisions.columns]
    if "seed" not in cluster_cols:
        raise ValueError("decisions file has no 'seed' column; cannot pair.")
    stratum_col = "topology" if "topology" in decisions.columns else None

    print("=== POST-FREEZE STATISTICAL VALIDATION ===")
    print(f"No experiment is re-run. Analysis only.")
    print(f"Pairing unit ......... {cluster_cols}")
    print(f"Bootstrap strata ..... {stratum_col or 'none (unstratified)'}")
    print(f"RNG seed ............. {args.seed}\n")

    present = [a for a in ARCH_ORDER if a in set(metrics["architecture"].unique())]

    # ---- (A) stratified cluster bootstrap ----
    rows = []
    composition = {}
    for a, b in combinations(present, 2):
        res, composition = stratified_cluster_bootstrap(
            decisions, a, b, args.bootstrap, rng, stratum_col, cluster_cols
        )
        for metric, r in res.items():
            family = "primary" if metric in PRIMARY_POOLED else "secondary"
            rows.append({
                "family": family,
                "comparison": f"{ARCH_LABEL[b]} vs {ARCH_LABEL[a]}",
                "arch_a": ARCH_LABEL[a],
                "arch_b": ARCH_LABEL[b],
                "metric": metric,
                **r,
            })
    boot_df = pd.DataFrame(rows)
    boot_df.to_csv(out / "bootstrap_pooled_differences.csv", index=False)
    print(f"[A] bootstrap composition per replicate: {composition}")
    print(f"[A] wrote bootstrap_pooled_differences.csv ({len(boot_df)} rows)")

    # ---- (A2) attack-stratified recall: EXPLORATORY ONLY ----
    # Attack-specific differences were inspected after the global results were
    # already known. They are therefore not part of the confirmatory primary
    # family and are not multiplicity-adjusted here.
    attack_rows = []
    if "attack_type" in decisions.columns:
        for attack, grp in decisions.groupby("attack_type"):
            if str(attack).lower() == "benign":
                continue
            for a, b in combinations(present, 2):
                try:
                    res, _ = stratified_cluster_bootstrap(
                        grp, a, b, max(2000, args.bootstrap // 5), rng, stratum_col, cluster_cols
                    )
                except ValueError:
                    continue
                r = res["recall"]
                if not np.isfinite(r["value_a"]) or not np.isfinite(r["value_b"]):
                    continue
                attack_rows.append({
                    "analysis_family": "exploratory_attack_stratified_unadjusted",
                    "attack_type": attack,
                    "comparison": f"{ARCH_LABEL[b]} vs {ARCH_LABEL[a]}",
                    "recall_a": r["value_a"], "recall_b": r["value_b"],
                    "difference": r["difference"],
                    "ci_low": r["ci_low"], "ci_high": r["ci_high"],
                    "excludes_zero": r["excludes_zero"],
                    "multiplicity_adjusted": False,
                })
    attack_df = pd.DataFrame(attack_rows)
    attack_df.to_csv(out / "bootstrap_by_attack.csv", index=False)
    print(f"[A] wrote bootstrap_by_attack.csv ({len(attack_rows)} exploratory rows)")

    # ---- (B) paired tests, families kept separate ----
    key_cols = [c for c in ("topology", "seed") if c in metrics.columns]
    families = [("primary", PRIMARY_METRICS), ("secondary", SECONDARY_METRICS)]
    available = [m for fam, spec in families for m in spec if m in metrics.columns]
    wide = metrics.pivot_table(index=key_cols, columns="architecture", values=available, aggfunc="mean")
    wide.to_csv(out / "per_seed_wide.csv")

    test_rows = []
    for family_name, spec in families:
        for metric, direction in spec.items():
            if metric not in metrics.columns:
                continue
            for a, b in combinations(present, 2):
                if (metric, a) not in wide.columns or (metric, b) not in wide.columns:
                    continue
                va = wide[(metric, a)].to_numpy(dtype=float)
                vb = wide[(metric, b)].to_numpy(dtype=float)
                mask = np.isfinite(va) & np.isfinite(vb)
                va, vb = va[mask], vb[mask]
                if va.size < 3:
                    continue
                diff = vb - va
                w_stat, w_p = wilcoxon_signed_rank(diff)
                perm_p = paired_permutation_p(diff, args.permutations, rng)
                rb = matched_pairs_rank_biserial(diff)
                test_rows.append({
                    "family": family_name,
                    "metric": metric,
                    "higher_is_better": direction > 0,
                    "arch_a": ARCH_LABEL[a],
                    "arch_b": ARCH_LABEL[b],
                    "n_pairs": int(va.size),
                    "mean_a": float(va.mean()),
                    "mean_b": float(vb.mean()),
                    "mean_difference": float(diff.mean()),
                    "median_difference": float(np.median(diff)),
                    "wilcoxon_stat": w_stat,
                    "wilcoxon_p": w_p,
                    "permutation_p": perm_p,
                    "cohens_dz": cohens_dz(diff),
                    "rank_biserial": rb,
                    "effect_magnitude": interpret_rb(rb),
                })

    tests = pd.DataFrame(test_rows)
    if not tests.empty:
        # Selected raw paired p-value: Wilcoxon when available, otherwise the
        # paired sign-flip permutation p-value. Keep the old `primary_p` alias
        # for backward compatibility with any downstream notebook/report.
        tests["raw_p"] = tests["wilcoxon_p"].where(
            tests["wilcoxon_p"].notna(), tests["permutation_p"]
        )
        tests["primary_p"] = tests["raw_p"]

        # Holm is applied WITHIN the predeclared PRIMARY family only.
        # Secondary/exploratory results deliberately receive no multiplicity
        # correction and therefore keep holm_adjusted_p = NaN.
        tests["holm_corrected"] = False
        tests["holm_adjusted_p"] = np.nan
        tests["holm_reject"] = False
        tests["significant"] = False  # backward-compatible decision column

        prim = tests["family"] == "primary"
        if prim.any():
            adjusted, flags = holm_bonferroni(
                tests.loc[prim, "raw_p"].tolist(), args.alpha
            )
            tests.loc[prim, "holm_corrected"] = True
            tests.loc[prim, "holm_adjusted_p"] = adjusted
            tests.loc[prim, "holm_reject"] = flags
            tests.loc[prim, "significant"] = flags

        sec = tests["family"] == "secondary"
        tests.loc[sec, "significant"] = tests.loc[sec, "raw_p"] < args.alpha
    tests.to_csv(out / "paired_tests_by_seed.csv", index=False)
    print(f"[B] wrote paired_tests_by_seed.csv "
          f"({int((tests['family'] == 'primary').sum())} primary, "
          f"{int((tests['family'] == 'secondary').sum())} exploratory)")

    # ---- narrative ----
    lines = ["# Post-Freeze Statistical Validation (V-PUFT v8)\n"]
    lines.append("This analysis re-runs no experiment. It reports intervals, paired tests and")
    lines.append("effect sizes over the frozen v7 results. No v7 number is replaced.\n")
    lines.append(f"- Pairing unit: `{cluster_cols}`")
    lines.append(f"- Bootstrap: stratified cluster resampling, composition per replicate {composition}")
    lines.append(f"- Resamples: {args.bootstrap} bootstrap, {args.permutations} permutation")
    lines.append(f"- Effect sizes: matched-pairs rank-biserial and Cohen's dz (paired design)")
    lines.append(f"- Primary family: recall, FRR, MCC, Holm-corrected at alpha = {args.alpha}")
    lines.append(f"- Exploratory family: precision, F1, latency, messages, bytes, memory (uncorrected)")
    lines.append(f"- RNG seed: {args.seed}\n")

    for fam in ("primary", "secondary"):
        sub = boot_df[boot_df["family"] == fam]
        if sub.empty:
            continue
        title = "Primary metrics" if fam == "primary" else "Exploratory metrics"
        lines.append(f"## {title} - pooled difference with 95% stratified cluster-bootstrap CI\n")
        lines.append("| Comparison | Metric | A | B | Difference | 95% CI | CI excludes 0 |")
        lines.append("|---|---|---|---|---|---|---|")
        for _, r in sub.iterrows():
            lines.append(
                f"| {r['comparison']} | {r['metric']} | {r['value_a']:.4f} | {r['value_b']:.4f} | "
                f"{r['difference']:+.4f} | [{r['ci_low']:+.4f}, {r['ci_high']:+.4f}] | "
                f"{'YES' if r['excludes_zero'] else 'no'} |"
            )
        lines.append("")

    if not attack_df.empty:
        lines.append("## Exploratory attack-stratified recall - unadjusted for multiplicity\n")
        lines.append(
            "This section is explicitly exploratory. Attack-specific contrasts were examined "
            "after the global pattern was known, so the intervals below must not be presented "
            "as confirmatory hypothesis tests. `CI excludes 0` is descriptive evidence of a "
            "stable direction under the stratified cluster bootstrap, not a multiplicity-adjusted "
            "claim of statistical significance.\n"
        )
        lines.append("| Attack | Comparison | Recall A | Recall B | Difference | 95% CI | CI excludes 0 |")
        lines.append("|---|---|---|---|---|---|---|")
        for _, r in attack_df.sort_values(["attack_type", "comparison"]).iterrows():
            lines.append(
                f"| {r['attack_type']} | {r['comparison']} | {r['recall_a']:.4f} | "
                f"{r['recall_b']:.4f} | {r['difference']:+.4f} | "
                f"[{r['ci_low']:+.4f}, {r['ci_high']:+.4f}] | "
                f"{'YES' if r['excludes_zero'] else 'no'} |"
            )
        lines.append("")

    if not tests.empty:
        for fam in ("primary", "secondary"):
            sub = tests[tests["family"] == fam]
            if sub.empty:
                continue
            title = ("Primary family - Holm-corrected" if fam == "primary"
                     else "Exploratory family - uncorrected, not confirmatory")
            lines.append(f"## {title}\n")
            if fam == "primary":
                lines.append(
                    "| Metric | Comparison | n | Mean diff | Raw p | Holm-adjusted p | "
                    "rank-biserial | Effect | Holm reject |"
                )
                lines.append("|---|---|---|---|---|---|---|---|---|")
                for _, r in sub.iterrows():
                    raw_p = "-" if not np.isfinite(r["raw_p"]) else f"{r['raw_p']:.4g}"
                    adj_p = (
                        "-" if not np.isfinite(r["holm_adjusted_p"])
                        else f"{r['holm_adjusted_p']:.4g}"
                    )
                    rb_text = (
                        "undefined" if not np.isfinite(r["rank_biserial"])
                        else f"{r['rank_biserial']:+.3f}"
                    )
                    lines.append(
                        f"| {r['metric']} | {r['arch_b']} vs {r['arch_a']} | {r['n_pairs']} | "
                        f"{r['mean_difference']:+.4f} | {raw_p} | {adj_p} | {rb_text} | "
                        f"{r['effect_magnitude']} | {'YES' if r['holm_reject'] else 'no'} |"
                    )
            else:
                lines.append(
                    "| Metric | Comparison | n | Mean diff | Raw p (uncorrected) | "
                    "rank-biserial | Effect | Raw p < alpha?* |"
                )
                lines.append("|---|---|---|---|---|---|---|---|")
                for _, r in sub.iterrows():
                    raw_p = "-" if not np.isfinite(r["raw_p"]) else f"{r['raw_p']:.4g}"
                    rb_text = (
                        "undefined" if not np.isfinite(r["rank_biserial"])
                        else f"{r['rank_biserial']:+.3f}"
                    )
                    lines.append(
                        f"| {r['metric']} | {r['arch_b']} vs {r['arch_a']} | {r['n_pairs']} | "
                        f"{r['mean_difference']:+.4f} | {raw_p} | {rb_text} | "
                        f"{r['effect_magnitude']} | {'YES' if r['significant'] else 'no'} |"
                    )
                lines.append(
                    "\n* Exploratory only: this flag uses the uncorrected raw p-value and "
                    "is not a confirmatory multiplicity-adjusted decision."
                )
            lines.append("")

    lines.append("## Wording rules for Chapter 5\n")
    lines.append(
        "1. Every point estimate gets an interval. Replace \"improved recall by 8.49 points\" with "
        "\"improved pooled recall by X.XX points (95% stratified cluster-bootstrap CI [L, U], "
        "paired across N seed-topology units, Wilcoxon p = ..., rank-biserial r = ...)\".\n"
    )
    lines.append(
        "2. If an interval includes zero, say so and downgrade the claim to \"no difference "
        "detectable at this sample size\". A reported null is stronger than an unqualified estimate.\n"
    )
    lines.append(
        "3. Exploratory-family results must be labelled exploratory in the text. They are not "
        "corrected for multiplicity and must not carry a confirmatory claim.\n"
    )
    lines.append(
        "4. Attack-stratified recall is exploratory and unadjusted for multiplicity. If an "
        "attack-specific bootstrap CI excludes zero, describe the direction as stable under "
        "the exploratory stratified bootstrap; do not call it a confirmatory significant "
        "difference.\n"
    )
    lines.append(
        "5. For the primary family, always report both the raw paired p-value and the "
        "Holm-adjusted p-value. The confirmatory decision follows `holm_reject`, not the "
        "raw p-value alone.\n"
    )
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "analysis_type": "post_freeze_statistical_validation",
        "experiments_rerun": False,
        "bootstrap_resamples": args.bootstrap,
        "bootstrap_stratified_by": stratum_col,
        "bootstrap_composition": composition,
        "permutation_resamples": args.permutations,
        "rng_seed": args.seed,
        "alpha": args.alpha,
        "cluster_columns": cluster_cols,
        "primary_family": list(PRIMARY_METRICS),
        "primary_multiplicity_correction": "Holm step-down FWER",
        "primary_reported_p_values": ["raw_p", "holm_adjusted_p"],
        "primary_decision_column": "holm_reject",
        "secondary_family": list(SECONDARY_METRICS),
        "secondary_multiplicity_correction": None,
        "effect_sizes": ["matched_pairs_rank_biserial", "cohens_dz"],
        "architectures": present,
        "input_metrics": args.metrics,
        "input_metrics_sha256": sha256_file(args.metrics),
        "input_decisions": args.decisions,
        "input_decisions_sha256": sha256_file(args.decisions),
        "attack_stratified_analysis": {
            "status": "exploratory",
            "multiplicity_adjusted": False,
            "metric": "recall",
            "benign_excluded": True,
        },
    }
    (out / "inference_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n[done] -> {out}")


if __name__ == "__main__":
    main()
