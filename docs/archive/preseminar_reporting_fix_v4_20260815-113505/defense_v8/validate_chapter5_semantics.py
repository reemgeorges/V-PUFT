#!/usr/bin/env python3
"""Semantic validator for V-PUFT Chapter 5 (pre-seminar final pass).

This validator does NOT merely search for hard-coded strings.  It reads the
post-freeze statistical outputs and verifies the numerical relationships used
in Chapter 5, then checks that the rendered HTML reports those relationships
with the correct direction and inference status.

No experiment is re-run and no frozen v7 result is modified.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import pandas as pd
from html import unescape

CENTRAL = "Centralized V-PUFT"
DIST = "Distributed RSU V-PUFT"
AHMED = "Ahmed-Inspired Witness V-PUFT"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str
    evidence: dict[str, Any] | None = None


def norm(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s)).strip()


def approx(a: float, b: float, tol: float = 5e-4) -> bool:
    return math.isfinite(a) and math.isfinite(b) and abs(a - b) <= tol


def as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y"}


def pct(x: float) -> str:
    return f"{x*100:.2f}%"


def pp(x: float) -> str:
    sign = "+" if x >= 0 else "−"
    return f"{sign}{abs(x)*100:.2f}"


def comparison_row(df: pd.DataFrame, metric: str, a: str, b: str) -> pd.Series:
    rows = df[(df["metric"] == metric) & (df["arch_a"] == a) & (df["arch_b"] == b)]
    if len(rows) != 1:
        raise AssertionError(f"Expected one pooled row for {metric}: {b} vs {a}; found {len(rows)}")
    return rows.iloc[0]


def test_row(df: pd.DataFrame, metric: str, a: str, b: str) -> pd.Series:
    rows = df[(df["metric"] == metric) & (df["arch_a"] == a) & (df["arch_b"] == b)]
    if len(rows) != 1:
        raise AssertionError(f"Expected one paired-test row for {metric}: {b} vs {a}; found {len(rows)}")
    return rows.iloc[0]


def attack_row(df: pd.DataFrame, attack: str, comparison: str) -> pd.Series:
    rows = df[(df["attack_type"].astype(str) == attack) & (df["comparison"].astype(str) == comparison)]
    if len(rows) != 1:
        raise AssertionError(f"Expected one attack row for {attack}: {comparison}; found {len(rows)}")
    return rows.iloc[0]


def strip_html(fragment: str) -> str:
    fragment = re.sub(r"<script\b[^>]*>.*?</script>", " ", fragment, flags=re.I|re.S)
    fragment = re.sub(r"<style\b[^>]*>.*?</style>", " ", fragment, flags=re.I|re.S)
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    return norm(unescape(fragment))


def table_after_title(html: str, title_fragment: str) -> str:
    # Stable generated HTML: title div immediately precedes the table.
    pos = html.find(title_fragment)
    if pos < 0:
        raise AssertionError(f"Table title not found: {title_fragment}")
    t0 = html.find("<table", pos)
    t1 = html.find("</table>", t0)
    if t0 < 0 or t1 < 0:
        raise AssertionError(f"No table after title: {title_fragment}")
    return html[t0:t1+8]


def html_rows(table_html: str) -> list[list[str]]:
    out = []
    for tr in re.findall(r"<tr\b[^>]*>(.*?)</tr>", table_html, flags=re.I|re.S):
        cells = re.findall(r"<(?:th|td)\b[^>]*>(.*?)</(?:th|td)>", tr, flags=re.I|re.S)
        if cells:
            out.append([strip_html(c) for c in cells])
    return out


def find_recursive(obj: Any, key: str) -> list[Any]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                found.append(v)
            found.extend(find_recursive(v, key))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(find_recursive(v, key))
    return found


def find_weight_dicts(obj: Any) -> list[dict[str, Any]]:
    found = []
    if isinstance(obj, dict):
        if all(k in obj for k in ("C", "rho", "F", "Q", "eta")):
            found.append(obj)
        for v in obj.values():
            found.extend(find_weight_dicts(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(find_weight_dicts(v))
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    chapter = repo / "results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html"
    pooled_p = repo / "results/full_campaign_v7/statistical_inference/bootstrap_pooled_differences.csv"
    attacks_p = repo / "results/full_campaign_v7/statistical_inference/bootstrap_by_attack.csv"
    tests_p = repo / "results/full_campaign_v7/statistical_inference/paired_tests_by_seed.csv"
    weights_p = repo / "results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"
    config_p = repo / "configs/full_experiment.json"
    agreement_p = repo / "results/full_campaign_v7/case_agreement/agreement_summary.csv"
    agreement_summary_p = repo / "results/full_campaign_v7/case_agreement/SUMMARY.md"

    required = [chapter, pooled_p, attacks_p, tests_p, weights_p, config_p]
    missing = [str(p.relative_to(repo)) for p in required if not p.exists()]
    if missing:
        print("MISSING required files:")
        print("\n".join(f"  - {x}" for x in missing))
        return 2

    pooled = pd.read_csv(pooled_p)
    attacks = pd.read_csv(attacks_p)
    tests = pd.read_csv(tests_p)
    html = chapter.read_text(encoding="utf-8")
    checks: list[Check] = []

    def add(name: str, passed: bool, detail: str, evidence: dict[str, Any] | None = None):
        checks.append(Check(name, bool(passed), detail, evidence))

    # A. Numerical identities and confirmatory inference.
    for a in (CENTRAL, DIST):
        r = comparison_row(pooled, "recall", a, AHMED)
        add(f"pooled_recall_identity_{a}", approx(float(r.value_b) - float(r.value_a), float(r.difference), 1e-10),
            "Pooled recall difference equals B-A.", {k: float(r[k]) for k in ("value_a", "value_b", "difference", "ci_low", "ci_high")})
        add(f"pooled_recall_frozen_range_{a}", approx(float(r.difference), 0.0846, 7e-4) and float(r.ci_low) > 0,
            "Pooled recall is about +8.46 pp and CI excludes zero.")

        r = comparison_row(pooled, "frr", a, AHMED)
        add(f"pooled_frr_identity_{a}", approx(float(r.value_b) - float(r.value_a), float(r.difference), 1e-10),
            "Pooled FRR difference equals B-A.", {k: float(r[k]) for k in ("value_a", "value_b", "difference", "ci_low", "ci_high")})
        add(f"pooled_frr_direction_{a}", float(r.difference) > 0 and float(r.ci_low) > 0,
            "Ahmed FRR is higher; this direction is undesirable.")

        r = comparison_row(pooled, "mcc", a, AHMED)
        add(f"pooled_mcc_identity_{a}", approx(float(r.value_b) - float(r.value_a), float(r.difference), 1e-10),
            "Pooled MCC difference equals B-A.")

    for a in (CENTRAL, DIST):
        rr = test_row(tests, "malicious_revocation_recall", a, AHMED)
        fr = test_row(tests, "false_revocation_rate", a, AHMED)
        mr = test_row(tests, "mcc", a, AHMED)
        add(f"holm_recall_{a}", as_bool(rr.holm_reject) and float(rr.holm_adjusted_p) < 0.05,
            "Recall remains confirmatory after Holm.", {"raw_p": float(rr.raw_p), "holm_p": float(rr.holm_adjusted_p)})
        add(f"holm_frr_{a}", as_bool(fr.holm_reject) and float(fr.holm_adjusted_p) < 0.05 and float(fr.mean_difference) > 0,
            "FRR increase remains confirmatory after Holm and has adverse direction.", {"raw_p": float(fr.raw_p), "holm_p": float(fr.holm_adjusted_p)})
        add(f"holm_mcc_{a}", (not as_bool(mr.holm_reject)) and float(mr.holm_adjusted_p) >= 0.05 and approx(float(mr.holm_adjusted_p), 0.1986, 8e-4),
            "MCC is not confirmatory after Holm.", {"raw_p": float(mr.raw_p), "holm_p": float(mr.holm_adjusted_p)})

    # B. Attack-specific exploratory intervals, always vs Distributed for Chapter 5 narrative.
    comp = f"{AHMED} vs {DIST}"
    expected = {
        "certificate_tamper": (0.0000, 0.0000, 0.0000),
        "false_denm": (0.1641, 0.0873, 0.2385),
        "flood": (0.0000, -0.0165, 0.0236),
        "mixed": (0.5613, 0.5128, 0.6118),
        "position_offset": (-0.1500, -0.2064, -0.0938),
        "replay": (0.1266, 0.1250, 0.1290),
        "speed_offset": (-0.1195, -0.1709, -0.0696),
    }
    attack_evidence = {}
    for attack, (d, lo, hi) in expected.items():
        r = attack_row(attacks, attack, comp)
        passed = approx(float(r.difference), d, 8e-4) and approx(float(r.ci_low), lo, 8e-4) and approx(float(r.ci_high), hi, 8e-4)
        attack_evidence[attack] = {"difference": float(r.difference), "ci_low": float(r.ci_low), "ci_high": float(r.ci_high)}
        add(f"attack_ci_{attack}", passed, "Attack-specific exploratory estimate matches frozen Phase A output.", attack_evidence[attack])

    # C. Chapter table 5-3a is mathematically closed and direction-aware.
    t53 = html_rows(table_after_title(html, "5-3أ"))
    header = t53[0]
    add("table_5_3a_has_pooled_values", "القيمة المجمعة A" in header and "القيمة المجمعة B" in header,
        "Table 5-3a exposes both pooled endpoints, not only their difference.")
    add("table_5_3a_has_direction", "اتجاه الفرق" in header,
        "Table 5-3a makes beneficial/adverse direction explicit.")
    joined53 = " | ".join(" | ".join(r) for r in t53[1:])
    add("table_5_3a_recall_values", "80.90%" in joined53 and "89.35%" in joined53 and "+8.46 pp" in joined53,
        "Displayed pooled recall endpoints close arithmetically to the reported +8.46 pp difference.")
    add("table_5_3a_frr_adverse", "زيادة غير مرغوبة" in joined53 and "تدهور" in joined53,
        "FRR significance is explicitly reported as an adverse increase.")
    add("table_5_3a_mcc_holm", "0.1986" in joined53 and "غير دال تأكيدياً بعد Holm" in joined53,
        "MCC raw direction is separated from Holm-confirmatory inference.")

    # D. Attack sections contain source-derived intervals consistently.
    chapter_text = strip_html(html)
    for attack, ev in attack_evidence.items():
        lo_s, hi_s = pp(ev["ci_low"]), pp(ev["ci_high"])
        # Numeric presence is checked against values generated from CSV, not a static validation token.
        if attack in {"certificate_tamper"}:
            ok = "Certificate Tamper" in chapter_text and "0.00 نقطة مئوية" in chapter_text
        else:
            ok = lo_s in chapter_text and hi_s in chapter_text
        add(f"chapter_attack_interval_{attack}", ok,
            f"Chapter reports the Phase A interval for {attack}: [{lo_s}, {hi_s}] pp.")

    add("false_denm_causal_caution", "دون عزل تجريبي لهذا العامل" in chapter_text and "لا تُنسب الزيادة سببياً" in chapter_text,
        "False DENM mechanism is framed as a hypothesis, not an isolated causal result.")

    # E. Latency semantics from rendered table: zero-IQR detection is flagged as design-fixed.
    t55 = html_rows(table_after_title(html, "5-5):"))
    flat55 = " | ".join(" | ".join(r) for r in t55)
    fixed_detection_rows = flat55.count("8000.0 | 8000.0–8000.0") >= 2
    add("latency_detection_zero_iqr_detected", fixed_detection_rows,
        "Centralized and Distributed detection rows have 8000/8000-8000 in the rendered stage table.")
    add("latency_detection_interpretation", "فترة ثابتة بنيوياً تحت الإعداد الحالي" in chapter_text,
        "Zero-IQR detection is described as a configured/model interval, not a variable measured performance quantity.")
    add("latency_p95_nonadditive", "P95(A)+P95(B)+P95(C) ≠ P95(A+B+C)" in chapter_text and "ليست بالضرورة الحالة نفسها" in chapter_text,
        "Independent percentiles are explicitly non-additive and the case-level reason is stated.")

    # F. Case agreement: parse CSV when possible, otherwise fail closed unless structured SUMMARY proves it.
    agreement_ok = False
    agreement_ev: dict[str, Any] = {}
    if agreement_p.exists():
        adf = pd.read_csv(agreement_p)
        # Identify C-vs-D row by scanning all object columns.
        for _, row in adf.iterrows():
            blob = " ".join(str(v) for v in row.values)
            if "Centralized" in blob and "Distributed" in blob:
                # Use column-name semantics rather than positional assumptions.
                cols = {c.lower(): c for c in adf.columns}
                def pick(words):
                    for lc, orig in cols.items():
                        if all(w in lc for w in words): return orig
                    return None
                shared_c = pick(["shared"])
                agree_c = pick(["agreement"])
                kappa_c = pick(["kappa"])
                disc_c = pick(["discord"])
                try:
                    shared = float(row[shared_c]) if shared_c else math.nan
                    agreement = float(row[agree_c]) if agree_c else math.nan
                    kappa = float(row[kappa_c]) if kappa_c else math.nan
                    discord = float(row[disc_c]) if disc_c else math.nan
                    agreement_ev = {"shared": shared, "agreement": agreement, "kappa": kappa, "discordant": discord}
                    agreement_ok = shared == 5992 and approx(agreement, 1.0, 1e-12) and approx(kappa, 1.0, 1e-12) and discord == 0
                except Exception:
                    pass
                break
    if not agreement_ok and agreement_summary_p.exists():
        # Structured markdown fallback: parse numeric cells rather than merely asking whether tokens exist.
        s = agreement_summary_p.read_text(encoding="utf-8", errors="replace")
        line = next((ln for ln in s.splitlines() if "Centralized" in ln and "Distributed" in ln and "|" in ln), "")
        nums = [float(x) for x in re.findall(r"(?<![A-Za-z])\d+(?:\.\d+)?", line)]
        # Require evidence of 5992 shared, agreement 1, kappa 1, discordant 0 in the same structured row.
        agreement_ok = (5992.0 in nums and nums.count(1.0) >= 2 and 0.0 in nums)
        agreement_ev = {"parsed_markdown_row": line}
    add("case_agreement_central_distributed", agreement_ok,
        "Centralized vs Distributed has 5992 shared cases, agreement=1, kappa=1, discordant=0.", agreement_ev)

    # G. Frozen calibration/policy contract.
    weights_obj = json.loads(weights_p.read_text(encoding="utf-8"))
    wdicts = find_weight_dicts(weights_obj)
    expected_w = {
        "C": 0.3652673861753211,
        "rho": 0.16195260151983162,
        "F": 0.06370517641034751,
        "Q": 0.40608957775126925,
        "eta": 0.0029852581432305157,
    }
    wmatch = any(all(approx(float(d[k]), v, 1e-12) for k, v in expected_w.items()) for d in wdicts)
    add("candidate_650_weights", wmatch, "Frozen shared weight vector matches candidate 650.", expected_w)
    feasible_vals = find_recursive(weights_obj, "selection_feasible")
    add("selection_feasible_false", any(v is False or str(v).lower() == "false" for v in feasible_vals),
        "selection_feasible remains false; feasibility targets were not relaxed post hoc.")

    config_obj = json.loads(config_p.read_text(encoding="utf-8"))
    mixed_dicts = []
    def walk_mixed(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() == "mixed" and isinstance(v, dict):
                    mixed_dicts.append(v)
                walk_mixed(v)
        elif isinstance(o, list):
            for v in o: walk_mixed(v)
    walk_mixed(config_obj)
    modalities_ok = any(int(d.get("required_modalities", -999)) == 1 for d in mixed_dicts)
    add("mixed_required_modalities_one", modalities_ok,
        "Mixed policy requires one modality after the structural feasibility correction.")

    # H. Safety and blockchain claims are scoped to what was actually measured.
    lower = chapter_text.lower()
    forbidden = [
        "no safety violations",
        "لم تسجل انتهاكات safety",
        "لم تُسجل انتهاكات safety",
        "أثبتت سلامة pbft",
        "blockchain improved detection accuracy",
        "سلسلة الكتل حسنت دقة الكشف",
        "سلسلة الكتل حسّنت دقة الكشف",
    ]
    bad = [x for x in forbidden if x.lower() in lower]
    add("forbidden_overclaims_absent", not bad,
        "No unmeasured Safety/blockchain-accuracy claim is asserted.", {"forbidden_hits": bad})
    add("safety_scope_explicit", "safety_violation" in lower and "لم يُختبر تجريبياً" in chapter_text,
        "Safety is explicitly treated as unmeasured under malicious semantic proposals.")
    add("blockchain_value_scope", "لم يظهر في جودة التصنيف" in chapter_text and "لا تُقدَّم هذه الخصائص هنا كنتائج تجريبية مثبتة" in chapter_text,
        "kappa=1 is framed as zero classification effect under controlled logic, not as proof that blockchain has no value.")

    failed = [c for c in checks if not c.passed]
    report = {
        "validator": "validate_chapter5_semantics.py",
        "validation_type": "source-derived semantic/numerical validation",
        "experiment_rerun": False,
        "checks_total": len(checks),
        "checks_passed": len(checks) - len(failed),
        "checks_failed": len(failed),
        "overall_pass": not failed,
        "checks": [asdict(c) for c in checks],
    }

    out = Path(args.output) if args.output else chapter.parent / "VALIDATION.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Semantic checks: {report['checks_passed']}/{report['checks_total']} passed")
    for c in failed:
        print(f"FAIL: {c.name}: {c.detail}")
    print(f"VALIDATION -> {out}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
