from __future__ import annotations

from dataclasses import asdict
from math import sqrt

import numpy as np
import pandas as pd

from .domain import ArchitectureRunResult, TrustState


def _safe_div(a: float, b: float) -> float:
    return float(a / b) if b else 0.0


def decision_metrics(
    result: ArchitectureRunResult,
    truth: dict[str, bool],
    opened_at: dict[str, float],
) -> dict[str, float | int | str]:
    tp = fp = tn = fn = 0
    e2e_latencies: list[float] = []
    detection_latencies: list[float] = []
    qualification_latencies: list[float] = []
    consensus_latencies: list[float] = []
    ledger_latencies: list[float] = []
    false_revocations_from_compromise = 0

    for decision in result.decisions:
        actual = bool(truth[decision.case_id])
        predicted = decision.new_state == TrustState.REVOKED and decision.committed
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
            if "compromise" in decision.reason:
                false_revocations_from_compromise += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1
        opened = opened_at[decision.case_id]
        if decision.detected_at is not None:
            detection_latencies.append(max(0.0, decision.detected_at - opened))
        if decision.qualified_at is not None and decision.detected_at is not None:
            qualification_latencies.append(max(0.0, decision.qualified_at - decision.detected_at))
        if decision.finalized_at is not None:
            e2e_latencies.append(max(0.0, decision.finalized_at - opened))
        if decision.finalized_at is not None and decision.qualified_at is not None:
            consensus_latencies.append(max(0.0, decision.finalized_at - decision.qualified_at))
        if decision.ledger_available_at is not None and decision.finalized_at is not None:
            ledger_latencies.append(max(0.0, decision.ledger_available_at - decision.finalized_at))

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    frr = _safe_div(fp, fp + tn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    denom = sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = _safe_div(tp * tn - fp * fn, denom)
    delivered = sum(not m.dropped for m in result.messages)
    pdr = _safe_div(delivered, len(result.messages))
    committed_consensus = sum(o.committed for o in result.consensus)
    liveness_failures = sum(not o.committed for o in result.consensus)
    safety_violations = sum(o.safety_violation for o in result.consensus)

    def percentile(values: list[float], q: float) -> float:
        return float(np.percentile(values, q) * 1000.0) if values else np.nan

    return {
        "architecture": result.architecture,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "trust_precision": precision,
        "malicious_revocation_recall": recall,
        "false_revocation_rate": frr,
        "malicious_acceptance_rate": _safe_div(fn, tp + fn),
        "specificity": specificity,
        "trust_f1": f1,
        "mcc": mcc,
        "detection_latency_p95_ms": percentile(detection_latencies, 95),
        "qualification_latency_p95_ms": percentile(qualification_latencies, 95),
        "consensus_latency_p95_ms": percentile(consensus_latencies, 95),
        "latency_p50_ms": percentile(e2e_latencies, 50),
        "latency_p95_ms": percentile(e2e_latencies, 95),
        "latency_p99_ms": percentile(e2e_latencies, 99),
        "ledger_consistency_delay_p95_ms": percentile(ledger_latencies, 95),
        "messages_total": len(result.messages),
        "messages_per_decision": _safe_div(len(result.messages), max(1, len(result.decisions))),
        "bytes_total": sum(m.size_bytes for m in result.messages),
        "bytes_per_decision": _safe_div(sum(m.size_bytes for m in result.messages), max(1, len(result.decisions))),
        "retransmissions": sum(m.retransmission > 0 for m in result.messages),
        "mean_queue_delay_ms": float(np.mean([m.queue_delay_ms for m in result.messages])) if result.messages else 0.0,
        "packet_delivery_ratio": pdr,
        "consensus_success_rate": _safe_div(committed_consensus, len(result.consensus)) if result.consensus else np.nan,
        "consensus_liveness_failures": liveness_failures,
        "safety_violations": safety_violations,
        "view_changes": sum(o.view_changes for o in result.consensus),
        "ledger_blocks": result.ledger_blocks,
        "ledger_consistent": int(result.ledger_consistent),
        "state_recoveries": result.state_recoveries,
        "false_revocations_from_compromise": false_revocations_from_compromise,
        "runtime_seconds": result.runtime_seconds,
    }


def decisions_frame(
    results: list[ArchitectureRunResult],
    truth: dict[str, bool],
    attack_types: dict[str, str] | None = None,
) -> pd.DataFrame:
    rows = []
    attack_types = attack_types or {}
    for result in results:
        for decision in result.decisions:
            data = asdict(decision)
            data["metadata"] = str(dict(decision.metadata))
            data["previous_state"] = decision.previous_state.value
            data["new_state"] = decision.new_state.value
            rows.append({
                **data,
                "attack_type": attack_types.get(decision.case_id, "unknown"),
                "ground_truth_malicious": int(truth[decision.case_id]),
                "predicted_revoked": int(decision.committed and decision.new_state == TrustState.REVOKED),
                "article_native_reference_qualified": int(bool(decision.metadata.get("article_native_reference_qualified", False))),
            })
    return pd.DataFrame(rows)


def confusion_metrics(frame: pd.DataFrame) -> dict[str, float | int]:
    if frame.empty:
        return {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "precision": 0.0, "recall": 0.0, "frr": 0.0, "mcc": 0.0}
    y = frame["ground_truth_malicious"].astype(int).to_numpy()
    p = frame["predicted_revoked"].astype(int).to_numpy()
    tp = int(((y == 1) & (p == 1)).sum())
    fp = int(((y == 0) & (p == 1)).sum())
    tn = int(((y == 0) & (p == 0)).sum())
    fn = int(((y == 1) & (p == 0)).sum())
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    frr = _safe_div(fp, fp + tn)
    denom = sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": precision, "recall": recall, "frr": frr, "mcc": _safe_div(tp * tn - fp * fn, denom)}
