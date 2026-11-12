"""Detection-independent attack opportunities for paired Scenario 5 evaluation."""
from __future__ import annotations

import pandas as pd


def opportunity_frame(messages: pd.DataFrame, decisions: pd.DataFrame,
                      observed_message_ids: set[str], *, window_seconds: float = 15.0) -> pd.DataFrame:
    """One row per vehicle/fixed window containing an actually emitted attack.

    `messages` is the emission log, before RSU filtering. A first committed
    revocation is credited to its originating window. Later opportunities are
    terminal and reported separately; they cannot inflate first-detection TP.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    needed = {"message_id", "sender_vehicle_id", "generated_at", "ground_truth_malicious"}
    if not needed <= set(messages):
        raise ValueError(f"Missing emission columns: {sorted(needed - set(messages))}")
    emitted = messages.copy()
    emitted["window_index"] = (emitted.generated_at.astype(float) // window_seconds).astype(int)
    emitted["malicious"] = emitted.ground_truth_malicious.astype(str).str.lower().isin(("true", "1"))
    emitted = emitted[emitted.malicious]
    emitted["observed"] = emitted.message_id.isin(observed_message_ids)
    grouped = emitted.groupby(["sender_vehicle_id", "window_index"], as_index=False).agg(
        emitted_malicious_messages=("message_id", "nunique"),
        observed_malicious_messages=("observed", "sum"),
    ).rename(columns={"sender_vehicle_id": "vehicle_id"})
    grouped["opportunity_id"] = grouped.vehicle_id + "-w" + grouped.window_index.astype(str).str.zfill(4)
    revoked = decisions[(decisions.committed.astype(str).str.lower().isin(("true", "1")))
                        & decisions.new_state.astype(str).str.lower().eq("revoked")].copy()
    if not revoked.empty:
        revoked["window_index"] = revoked.case_id.str.extract(r"-w(\d+)$")[0].astype(int)
        first = revoked.groupby("vehicle_id").window_index.min().rename("first_revocation_window")
        grouped = grouped.join(first, on="vehicle_id")
    else:
        grouped["first_revocation_window"] = float("nan")
    grouped["observed_opportunity"] = grouped.observed_malicious_messages.gt(0)
    grouped["detected_opportunity"] = grouped.first_revocation_window.eq(grouped.window_index)
    grouped["terminal_after_revocation"] = grouped.first_revocation_window.lt(grouped.window_index)
    grouped["missed_opportunity"] = (~grouped.detected_opportunity & ~grouped.terminal_after_revocation)
    return grouped.sort_values(["vehicle_id", "window_index"]).reset_index(drop=True)


def opportunity_metrics(frame: pd.DataFrame) -> dict[str, float | int]:
    active = frame[~frame.terminal_after_revocation]
    tp = int(active.detected_opportunity.sum())
    fn = int(active.missed_opportunity.sum())
    total = len(frame)
    terminal = int(frame.terminal_after_revocation.sum())
    return {"total_opportunities": total, "observed_opportunities": int(frame.observed_opportunity.sum()),
            "terminal_opportunities": int(frame.terminal_after_revocation.sum()),
            "opportunity_TP": tp, "opportunity_FN": fn,
            "opportunity_recall": tp / (tp + fn) if tp + fn else 0.0,
            "fixed_universe_first_detection_fraction": tp / total if total else 0.0,
            "fixed_universe_protected_fraction": (tp + terminal) / total if total else 0.0}
