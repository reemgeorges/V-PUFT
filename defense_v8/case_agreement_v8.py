"""
V-PUFT v8 - Case-level agreement between architectures (corrected).

POST-FREEZE ANALYSIS. No experiment is re-run.

PURPOSE
-------
Chapter 5 reports Centralized and Distributed RSU as identical to sixteen
decimal places and presents this as a methodological finding. Aggregate
equality is weak evidence and reads to a sceptical examiner as a duplicated
result. This script measures case-level agreement instead, which is strong
evidence either way.

CORRECTIONS APPLIED IN THIS VERSION
-----------------------------------
1. COVERAGE COUNTS reported before agreement. The previous version computed
   agreement only over the intersection of case ids, so one architecture
   holding fewer cases would be silently hidden behind a high kappa. Now
   n_cases_A, n_cases_B, n_shared, n_A_only and n_B_only are reported first,
   and a coverage warning is emitted when the sets differ.

2. EXACT McNEMAR by default. The chi-square approximation is unreliable when
   the discordant count is small, which is exactly the regime expected here.
   The exact binomial test is used whenever discordant <= --exact-threshold,
   and the choice is recorded per row.

3. FOCUS PAIR. Centralized vs Distributed RSU is analysed and reported first,
   since that is the pair whose identical aggregates need explaining.

BOTH OUTCOMES ARE SCIENTIFICALLY ACCEPTABLE
-------------------------------------------
  agreement < 100%  -> aggregates coincide, individual cases do not
  agreement = 100%  -> the two paths made the same trust decisions, so the
                       comparison isolates finalization and ledger effects

The second is not a failure. It is only a failure if it is discovered during
the defence rather than before it.

USAGE
-----
  python case_agreement_v8.py \
      --decisions results/full_campaign_v7/final_architectures/final_decisions.csv \
      --output    results/full_campaign_v7/case_agreement
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from itertools import combinations
from math import comb
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

FOCUS_PAIR = ("centralized_vpuft", "distributed_rsu_vpuft")


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


def cohens_kappa(a: np.ndarray, b: np.ndarray) -> float:
    n = a.size
    if n == 0:
        return float("nan")
    po = float((a == b).mean())
    pa1, pb1 = a.mean(), b.mean()
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    return float((po - pe) / (1 - pe)) if pe < 1 else float("nan")


def mcnemar(a: np.ndarray, b: np.ndarray, exact_threshold: int = 25) -> dict:
    """
    McNemar test on discordant pairs.

    Exact binomial is used when the discordant count is small, because the
    continuity-corrected chi-square is unreliable in that regime and this
    comparison is expected to produce few discordant pairs.
    """
    b01 = int(((a == 0) & (b == 1)).sum())
    b10 = int(((a == 1) & (b == 0)).sum())
    n_disc = b01 + b10

    if n_disc == 0:
        return {"b01": 0, "b10": 0, "n_discordant": 0,
                "test": "none", "statistic": np.nan, "p_value": 1.0}

    if n_disc <= exact_threshold:
        k = min(b01, b10)
        tail = sum(comb(n_disc, i) for i in range(k + 1))
        p = min(1.0, 2.0 * tail / (2 ** n_disc))
        return {"b01": b01, "b10": b10, "n_discordant": n_disc,
                "test": "exact_binomial", "statistic": float(k), "p_value": float(p)}

    chi2 = (abs(b01 - b10) - 1) ** 2 / n_disc
    try:
        from scipy.stats import chi2 as chi2_dist  # type: ignore
        p = float(1.0 - chi2_dist.cdf(chi2, df=1))
    except Exception:
        p = float("nan")
    return {"b01": b01, "b10": b10, "n_discordant": n_disc,
            "test": "chi2_continuity_corrected", "statistic": float(chi2), "p_value": p}


def parse_reason(value) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    try:
        d = ast.literal_eval(value)
        if isinstance(d, dict):
            for key in ("failure_reason", "reason", "qualification_reason"):
                if key in d:
                    return str(d[key])
    except Exception:
        pass
    return ""


def analyse_pair(df: pd.DataFrame, a: str, b: str, exact_threshold: int):
    da = df[df["architecture"] == a].set_index("_key")
    db = df[df["architecture"] == b].set_index("_key")

    shared = da.index.intersection(db.index)
    a_only = da.index.difference(db.index)
    b_only = db.index.difference(da.index)

    coverage = {
        "n_cases_A": int(da.index.size),
        "n_cases_B": int(db.index.size),
        "n_shared": int(shared.size),
        "n_A_only": int(a_only.size),
        "n_B_only": int(b_only.size),
        "coverage_identical": bool(a_only.size == 0 and b_only.size == 0),
    }

    if shared.empty:
        return {**coverage, "arch_a": ARCH_LABEL[a], "arch_b": ARCH_LABEL[b]}, None

    sa = da.loc[shared]
    sb = db.loc[shared]

    truth_a = sa["ground_truth_malicious"].to_numpy(dtype=int)
    truth_b = sb["ground_truth_malicious"].to_numpy(dtype=int)
    if not np.array_equal(truth_a, truth_b):
        bad = shared[truth_a != truth_b]
        sample = ", ".join(map(str, bad[:10]))
        raise ValueError(
            f"Ground-truth mismatch between {ARCH_LABEL[a]} and {ARCH_LABEL[b]} "
            f"for {len(bad)} shared cases. Example keys: {sample}"
        )

    if "attack_type" in sa.columns and "attack_type" in sb.columns:
        aa = sa["attack_type"].astype(str).to_numpy()
        ab = sb["attack_type"].astype(str).to_numpy()
        if not np.array_equal(aa, ab):
            bad = shared[aa != ab]
            sample = ", ".join(map(str, bad[:10]))
            raise ValueError(
                f"Attack-label mismatch between {ARCH_LABEL[a]} and {ARCH_LABEL[b]} "
                f"for {len(bad)} shared cases. Example keys: {sample}"
            )

    pa = sa["predicted_revoked"].to_numpy(dtype=int)
    pb = sb["predicted_revoked"].to_numpy(dtype=int)
    truth = truth_a

    agree = int((pa == pb).sum())
    mc = mcnemar(pa, pb, exact_threshold)

    summary = {
        "arch_a": ARCH_LABEL[a],
        "arch_b": ARCH_LABEL[b],
        **coverage,
        "n_agree": agree,
        "n_disagree": int(shared.size) - agree,
        "agreement_rate": agree / shared.size,
        "cohens_kappa": cohens_kappa(pa, pb),
        "a_revoked_b_kept": mc["b10"],
        "a_kept_b_revoked": mc["b01"],
        "n_discordant": mc["n_discordant"],
        "mcnemar_test": mc["test"],
        "mcnemar_statistic": mc["statistic"],
        "mcnemar_p": mc["p_value"],
    }

    mask = pa != pb
    dis = None
    if mask.any():
        dis = pd.DataFrame({
            "case_key": shared[mask],
            "arch_a": ARCH_LABEL[a],
            "arch_b": ARCH_LABEL[b],
            "ground_truth_malicious": truth[mask],
            "a_predicted_revoked": pa[mask],
            "b_predicted_revoked": pb[mask],
            "a_reason": sa["_reason"].to_numpy()[mask],
            "b_reason": sb["_reason"].to_numpy()[mask],
        })
        if "attack_type" in sa.columns:
            dis["attack_type"] = sa["attack_type"].to_numpy()[mask]
    return summary, dis


def main() -> None:
    ap = argparse.ArgumentParser(description="Post-freeze case-level agreement analysis.")
    ap.add_argument("--decisions", required=True)
    ap.add_argument("--output", default="results/full_campaign_v7/case_agreement")
    ap.add_argument("--exact-threshold", type=int, default=25,
                    help="Use exact binomial McNemar when discordant count is at or below this.")
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.decisions)
    required = {"case_id", "architecture", "predicted_revoked", "ground_truth_malicious"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"decisions file is missing required columns: {sorted(missing)}")

    key_cols = ["topology", "seed", "case_id"]
    missing_key = [c for c in key_cols if c not in df.columns]
    if missing_key:
        print(
            "FAIL CLOSED: case-level agreement requires the full "
            f"(topology, seed, case_id) key; missing {missing_key}.",
            file=sys.stderr,
        )
        sys.exit(2)

    df["_key"] = df[key_cols].astype(str).agg("|".join, axis=1)

    duplicate_mask = df.duplicated(["architecture", "_key"], keep=False)
    if duplicate_mask.any():
        dup = df.loc[duplicate_mask, ["architecture", *key_cols]].copy()
        dup.to_csv(out / "DUPLICATE_CASE_KEYS_FAIL_CLOSED.csv", index=False)
        print(
            "FAIL CLOSED: duplicate (architecture, topology, seed, case_id) rows were found. "
            "They were NOT silently dropped. See DUPLICATE_CASE_KEYS_FAIL_CLOSED.csv.",
            file=sys.stderr,
        )
        sys.exit(2)

    df["_reason"] = df["metadata"].map(parse_reason) if "metadata" in df.columns else ""
    if "reason" in df.columns:
        df["_reason"] = np.where(df["_reason"] == "", df["reason"].astype(str), df["_reason"])

    print("=== POST-FREEZE CASE-LEVEL AGREEMENT ===")
    print("No experiment is re-run.")
    print(f"Case key ............. {key_cols}\n")

    present = [a for a in ARCH_ORDER if a in set(df["architecture"].unique())]

    # Focus pair first, then the rest.
    pairs = []
    if all(a in present for a in FOCUS_PAIR):
        pairs.append(FOCUS_PAIR)
    for pair in combinations(present, 2):
        if pair not in pairs and tuple(reversed(pair)) not in pairs:
            pairs.append(pair)

    summaries, disagreements = [], []
    for a, b in pairs:
        summary, dis = analyse_pair(df, a, b, args.exact_threshold)
        summaries.append(summary)
        if dis is not None:
            disagreements.append(dis)

        is_focus = (a, b) == FOCUS_PAIR
        tag = "  <-- FOCUS PAIR" if is_focus else ""
        print(f"{ARCH_LABEL[a]} vs {ARCH_LABEL[b]}{tag}")
        print(f"  cases A / B / shared : {summary['n_cases_A']} / "
              f"{summary['n_cases_B']} / {summary['n_shared']}")
        if not summary["coverage_identical"]:
            print(f"  ** COVERAGE WARNING: A-only={summary['n_A_only']}, "
                  f"B-only={summary['n_B_only']} - agreement below is computed on the "
                  f"shared subset only **")
        if "agreement_rate" in summary:
            print(f"  agreement            : {summary['agreement_rate']:.6f}")
            print(f"  cohen's kappa        : {summary['cohens_kappa']:.6f}")
            print(f"  discordant           : {summary['n_discordant']} "
                  f"({summary['mcnemar_test']}, p = {summary['mcnemar_p']:.4g})")
        print()

    summary_df = pd.DataFrame(summaries)
    summary_df.to_csv(out / "agreement_summary.csv", index=False)

    if disagreements:
        dis_all = pd.concat(disagreements, ignore_index=True)
        dis_all.to_csv(out / "disagreement_cases.csv", index=False)
        print(f"wrote disagreement_cases.csv ({len(dis_all)} rows)")
        if "attack_type" in dis_all.columns:
            (dis_all.groupby(["arch_a", "arch_b", "attack_type"])
             .size().reset_index(name="n_disagreements")
             .to_csv(out / "disagreement_by_attack.csv", index=False))
            print("wrote disagreement_by_attack.csv")
    else:
        print("no disagreements found between any pair")

    # ---- narrative, branching on the focus-pair outcome ----
    focus = next((s for s in summaries
                  if s["arch_a"] == ARCH_LABEL[FOCUS_PAIR[0]]
                  and s["arch_b"] == ARCH_LABEL[FOCUS_PAIR[1]]), None)

    lines = ["# Case-Level Agreement (V-PUFT v8, post-freeze)\n"]
    lines.append("No experiment was re-run. This analysis explains, at the level of individual")
    lines.append("cases, why two architectures report identical aggregate confusion matrices.\n")

    lines.append("## Coverage and agreement\n")
    lines.append("| Pair | A | B | Shared | A-only | B-only | Agreement | Kappa | Discordant | Test | p |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for s in summaries:
        if "agreement_rate" not in s:
            continue
        lines.append(
            f"| {s['arch_a']} vs {s['arch_b']} | {s['n_cases_A']} | {s['n_cases_B']} | "
            f"{s['n_shared']} | {s['n_A_only']} | {s['n_B_only']} | "
            f"{s['agreement_rate']:.6f} | {s['cohens_kappa']:.4f} | {s['n_discordant']} | "
            f"{s['mcnemar_test']} | {s['mcnemar_p']:.4g} |"
        )

    lines.append("\n## Text for section 5.17\n")
    if focus and "agreement_rate" in focus:
        if focus["agreement_rate"] < 1.0:
            lines.append(
                "The measured agreement is below 1.0. Suggested wording:\n\n"
                f"> The two RSU-based architectures produced identical aggregate confusion matrices, "
                f"but the aggregate equality does not imply identical case-level decisions. Across "
                f"{focus['n_shared']} shared cases, the measured agreement was "
                f"{focus['agreement_rate']:.4f} (Cohen's kappa = {focus['cohens_kappa']:.4f}), and "
                f"{focus['n_disagree']} cases were decided differently. The aggregate equality must "
                f"therefore be interpreted as equality of totals, not proof that the two decision "
                f"paths are identical on every case. The disagreement_cases.csv output is used to "
                f"inspect which attack families and failure reasons account for those differences.\n"
            )
        else:
            lines.append(
                "The measured agreement is exactly 1.0. Suggested wording:\n\n"
                f"> Across all {focus['n_shared']} shared cases, the two RSU-based architectures "
                "issued identical trust decisions. Their identical aggregate confusion matrices are "
                "therefore explained by complete case-level classification agreement on the shared "
                "case set. This supports treating classification quality as equivalent for those "
                "cases in the frozen campaign, while communication, latency, consensus and ledger "
                "metrics remain separate dimensions of the architectural comparison. This result "
                "does not by itself prove that the internal evidence sets or processing traces were "
                "identical.\n"
            )
    if focus and not focus.get("coverage_identical", True):
        lines.append(
            "\n**Coverage warning for the thesis text:** the two architectures do not hold the "
            "same case set. State the shared-subset size explicitly wherever the agreement rate "
            "is quoted, and report the non-shared counts, otherwise the agreement figure "
            "overstates comparability.\n"
        )

    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "analysis_type": "post_freeze_case_agreement",
        "experiments_rerun": False,
        "case_key": key_cols,
        "focus_pair": [ARCH_LABEL[a] for a in FOCUS_PAIR],
        "exact_mcnemar_threshold": args.exact_threshold,
        "duplicate_case_keys_allowed": False,
        "ground_truth_consistency_required": True,
        "attack_label_consistency_required": True,
        "input_decisions": args.decisions,
        "input_decisions_sha256": sha256_file(args.decisions),
    }
    (out / "agreement_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n[done] -> {out}")


if __name__ == "__main__":
    main()
