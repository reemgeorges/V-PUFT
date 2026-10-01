from __future__ import annotations

from math import sqrt
import re

import numpy as np
import pandas as pd


_WINDOW_RE = re.compile(r"-w(\d+)$")


def _safe_div(a: float, b: float) -> float:
    return float(a / b) if b else 0.0


def _validate(frame: pd.DataFrame) -> None:
    required = {
        "case_id",
        "vehicle_id",
        "seed",
        "architecture",
        "ground_truth_malicious",
        "committed",
        "new_state",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Missing required decision columns: {missing}")


def prepare_state_aware_decisions(
    frame: pd.DataFrame,
    *,
    window_seconds: float = 15.0,
) -> pd.DataFrame:
    """Prepare Scenario-5 decision rows for post-hoc state-aware evaluation.

    This function does NOT change the original campaign predictions.

    Method B semantics:
    - a vehicle remains in the first-revocation risk set until its first
      committed revocation;
    - the first committed-revocation window remains evaluable;
    - all later windows are excluded from the first-revocation confusion matrix.

    The original window-level evaluation remains unchanged in metrics.py.
    """
    _validate(frame)
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    out = frame.copy()

    extracted = out["case_id"].astype(str).str.extract(r"-w(\d+)$")[0]
    if extracted.isna().any():
        bad = out.loc[extracted.isna(), "case_id"].astype(str).head(5).tolist()
        raise ValueError(f"Cannot extract window index from case_id values: {bad}")

    out["window_index"] = extracted.astype(int)
    out["opened_at"] = out["window_index"].astype(float) * float(window_seconds)

    committed = pd.to_numeric(out["committed"], errors="coerce").fillna(0).astype(int).eq(1)
    revoked_state = out["new_state"].astype(str).str.lower().eq("revoked")

    out["is_committed_revocation"] = committed & revoked_state
    out["is_revoked_state"] = revoked_state

    group_keys = [
        column
        for column in ("topology", "vehicle_count", "seed", "architecture", "vehicle_id")
        if column in out.columns
    ]

    first_revocation = (
        out.loc[out["is_committed_revocation"]]
        .groupby(group_keys, dropna=False)["window_index"]
        .min()
        .rename("first_revocation_window")
        .reset_index()
    )

    out = out.merge(first_revocation, on=group_keys, how="left")

    out["in_first_revocation_risk_set"] = (
        out["first_revocation_window"].isna()
        | (out["window_index"] <= out["first_revocation_window"])
    )

    out["post_first_revocation"] = (
        out["first_revocation_window"].notna()
        & (out["window_index"] > out["first_revocation_window"])
    )

    actual = pd.to_numeric(
        out["ground_truth_malicious"], errors="coerce"
    ).fillna(0).astype(int).eq(1)

    predicted = out["is_committed_revocation"]

    labels = np.full(len(out), "EXCLUDED_POST_REVOCATION", dtype=object)

    at_risk = out["in_first_revocation_risk_set"].to_numpy()
    actual_np = actual.to_numpy()
    predicted_np = predicted.to_numpy()

    labels[at_risk & actual_np & predicted_np] = "TP"
    labels[at_risk & ~actual_np & predicted_np] = "FP"
    labels[at_risk & ~actual_np & ~predicted_np] = "TN"
    labels[at_risk & actual_np & ~predicted_np] = "FN"

    out["state_aware_label"] = labels

    return out


def state_aware_first_revocation_metrics(
    frame: pd.DataFrame,
    *,
    window_seconds: float = 15.0,
) -> pd.DataFrame:
    """Method B: At-Risk Window First-Revocation Evaluation, per run/seed."""
    prepared = prepare_state_aware_decisions(
        frame,
        window_seconds=window_seconds,
    )

    run_keys = [
        column
        for column in (
            "topology",
            "vehicle_count",
            "seed",
            "architecture",
            "backhaul_extra_latency_ms",
        )
        if column in prepared.columns
    ]

    rows: list[dict] = []

    for key, group in prepared.groupby(run_keys, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        context = dict(zip(run_keys, key))

        counts = group["state_aware_label"].value_counts()

        tp = int(counts.get("TP", 0))
        fp = int(counts.get("FP", 0))
        tn = int(counts.get("TN", 0))
        fn = int(counts.get("FN", 0))
        excluded = int(counts.get("EXCLUDED_POST_REVOCATION", 0))

        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        frr = _safe_div(fp, fp + tn)
        f1 = _safe_div(2 * precision * recall, precision + recall)

        denom = sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = _safe_div(tp * tn - fp * fn, denom)

        rows.append(
            {
                **context,
                "evaluation": "at_risk_window_first_revocation",
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision": precision,
                "recall": recall,
                "false_revocation_rate": frr,
                "f1": f1,
                "mcc": mcc,
                "at_risk_windows": tp + fp + tn + fn,
                "excluded_post_revocation_windows": excluded,
                "all_windows": len(group),
            }
        )

    return pd.DataFrame(rows)


def persistent_revocation_state_metrics(
    frame: pd.DataFrame,
    *,
    window_seconds: float = 15.0,
) -> pd.DataFrame:
    """Method C: descriptive persistence of the REVOKED state after first event.

    This is NOT a packet-prevention metric and must not be labelled as Recall.
    """
    prepared = prepare_state_aware_decisions(
        frame,
        window_seconds=window_seconds,
    )

    run_keys = [
        column
        for column in (
            "topology",
            "vehicle_count",
            "seed",
            "architecture",
            "backhaul_extra_latency_ms",
        )
        if column in prepared.columns
    ]

    rows: list[dict] = []

    for key, group in prepared.groupby(run_keys, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        context = dict(zip(run_keys, key))

        post = group.loc[group["post_first_revocation"]].copy()

        malicious = pd.to_numeric(
            post["ground_truth_malicious"], errors="coerce"
        ).fillna(0).astype(int).eq(1)

        revoked = post["is_revoked_state"].astype(bool)

        malicious_post = int(malicious.sum())
        benign_post = int((~malicious).sum())

        malicious_revoked = int((malicious & revoked).sum())
        benign_revoked = int(((~malicious) & revoked).sum())

        repeated_commits = int(post["is_committed_revocation"].sum())

        rows.append(
            {
                **context,
                "evaluation": "persistent_revocation_state",
                "post_revocation_windows": len(post),
                "malicious_post_revocation_windows": malicious_post,
                "benign_post_revocation_windows": benign_post,
                "malicious_post_windows_in_revoked_state": malicious_revoked,
                "benign_post_windows_in_revoked_state": benign_revoked,
                "malicious_revoked_state_coverage": _safe_div(
                    malicious_revoked,
                    malicious_post,
                ),
                "benign_revoked_state_persistence": _safe_div(
                    benign_revoked,
                    benign_post,
                ),
                "repeated_committed_revocations_after_first": repeated_commits,
            }
        )

    return pd.DataFrame(rows)


def first_revocation_timing(
    frame: pd.DataFrame,
    *,
    window_seconds: float = 15.0,
) -> pd.DataFrame:
    """Method D: descriptive time from first malicious case start to first revocation.

    This is case-window based. It is not a full survival/censoring analysis.
    """
    prepared = prepare_state_aware_decisions(
        frame,
        window_seconds=window_seconds,
    )

    vehicle_keys = [
        column
        for column in ("topology", "vehicle_count", "seed", "architecture", "vehicle_id")
        if column in prepared.columns
    ]

    rows: list[dict] = []

    for key, group in prepared.groupby(vehicle_keys, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        context = dict(zip(vehicle_keys, key))

        malicious = pd.to_numeric(
            group["ground_truth_malicious"], errors="coerce"
        ).fillna(0).astype(int).eq(1)

        malicious_rows = group.loc[malicious]

        if malicious_rows.empty:
            continue

        first_malicious_case_start = float(malicious_rows["opened_at"].min())

        revocations = group.loc[group["is_committed_revocation"]].copy()
        revocations["finalized_numeric"] = pd.to_numeric(
            revocations.get("finalized_at"),
            errors="coerce",
        )

        valid_revocations = revocations.loc[
            revocations["finalized_numeric"].notna()
        ]

        first_revocation_at = (
            float(valid_revocations["finalized_numeric"].min())
            if not valid_revocations.empty
            else np.nan
        )

        revoked_before_first_malicious = bool(
            np.isfinite(first_revocation_at)
            and first_revocation_at < first_malicious_case_start
        )

        valid_detection_event = bool(
            np.isfinite(first_revocation_at)
            and first_revocation_at >= first_malicious_case_start
        )

        time_to_first_revocation_ms = (
            1000.0 * (first_revocation_at - first_malicious_case_start)
            if valid_detection_event
            else np.nan
        )

        rows.append(
            {
                **context,
                "first_malicious_case_start": first_malicious_case_start,
                "first_committed_revocation_at": first_revocation_at,
                "first_revocation_observed_after_malicious_case": int(
                    valid_detection_event
                ),
                "revoked_before_first_malicious_case": int(
                    revoked_before_first_malicious
                ),
                "time_to_first_revocation_ms": time_to_first_revocation_ms,
            }
        )

    return pd.DataFrame(rows)
