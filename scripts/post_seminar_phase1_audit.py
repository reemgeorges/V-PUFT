from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import pandas as pd


CANONICAL_ARCHITECTURE = "distributed_density_honest"


def _metadata(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if pd.isna(value):
        return {}
    return json.loads(str(value))


def _window_index(case_id: str) -> int:
    marker = str(case_id).rsplit("-w", 1)
    if len(marker) != 2 or not marker[1].isdigit():
        raise ValueError(f"Cannot extract window index from case_id={case_id!r}")
    return int(marker[1])


def classify_false_negatives(
    decisions: pd.DataFrame,
    policies: dict[str, dict],
    *,
    architecture: str = CANONICAL_ARCHITECTURE,
) -> pd.DataFrame:
    required = {
        "architecture", "vehicle_count", "seed", "case_id", "vehicle_id",
        "attack_type", "ground_truth_malicious", "predicted_revoked", "committed",
        "reason", "metadata_json", "decision_margin",
    }
    missing = sorted(required - set(decisions.columns))
    if missing:
        raise ValueError(f"Missing decision columns: {missing}")

    frame = decisions.loc[decisions["architecture"].eq(architecture)].copy()
    if frame.empty:
        raise ValueError(f"Architecture not found: {architecture}")
    frame["window_index"] = frame["case_id"].map(_window_index)
    frame["metadata"] = frame["metadata_json"].map(_metadata)
    frame["is_revocation"] = (
        pd.to_numeric(frame["predicted_revoked"], errors="coerce").fillna(0).eq(1)
        & pd.to_numeric(frame["committed"], errors="coerce").fillna(0).eq(1)
    )
    keys = ["vehicle_count", "seed", "vehicle_id"]
    first = (
        frame.loc[frame["is_revocation"]]
        .groupby(keys, dropna=False)["window_index"]
        .min()
        .rename("first_revocation_window")
        .reset_index()
    )
    frame = frame.merge(first, on=keys, how="left")
    false_negatives = frame.loc[
        pd.to_numeric(frame["ground_truth_malicious"], errors="coerce").fillna(0).eq(1)
        & ~frame["is_revocation"]
    ].copy()

    def classify(row: pd.Series) -> str:
        first_window = row["first_revocation_window"]
        if pd.notna(first_window) and row["window_index"] > int(first_window):
            return "post_revocation_terminal_window"
        reason = str(row["reason"])
        metadata = row["metadata"]
        attempted = int(metadata.get("attempted_attestations", 0) or 0)
        arrived = int(metadata.get("arrived_attestations", attempted) or 0)
        expired = int(metadata.get("expired_evidence", 0) or 0)
        if reason in {"consensus_failed", "timeout", "quorum_not_reached"}:
            return "failed_finalization"
        if reason == "no_fresh_valid_evidence" or (expired and arrived == 0):
            return "stale_evidence"
        if reason == "insufficient_weighted_margin":
            return "margin_threshold"
        if reason == "insufficient_independent_evidence_diversity":
            policy = policies[str(row["attack_type"])]
            roots = int(metadata.get("independent_roots", 0) or 0)
            if roots < int(policy["required_roots"]):
                return "insufficient_independent_roots"
            if arrived < attempted:
                return "message_loss_with_unresolved_diversity"
            return "source_zone_or_modality_diversity_unresolved"
        if arrived < attempted:
            return "message_loss"
        return f"unclassified:{reason}"

    false_negatives["fn_cause"] = false_negatives.apply(classify, axis=1)
    false_negatives["eventually_revoked"] = false_negatives["first_revocation_window"].notna()
    false_negatives["independent_roots"] = false_negatives["metadata"].map(
        lambda value: int(value.get("independent_roots", 0) or 0)
    )
    false_negatives["arrived_attestations"] = false_negatives["metadata"].map(
        lambda value: int(value.get("arrived_attestations", 0) or 0)
    )
    false_negatives["attempted_attestations"] = false_negatives["metadata"].map(
        lambda value: int(value.get("attempted_attestations", 0) or 0)
    )
    false_negatives["expired_evidence"] = false_negatives["metadata"].map(
        lambda value: int(value.get("expired_evidence", 0) or 0)
    )
    malicious = frame.loc[
        pd.to_numeric(frame["ground_truth_malicious"], errors="coerce").fillna(0).eq(1)
    ]
    population = malicious[keys].drop_duplicates()
    revoked_population = frame.loc[frame["is_revocation"], keys].drop_duplicates()
    false_negatives.attrs["malicious_vehicle_count"] = int(len(population))
    false_negatives.attrs["eventually_revoked_vehicle_count"] = int(
        len(population.merge(revoked_population, on=keys, how="inner"))
    )
    return false_negatives


def build_report(false_negatives: pd.DataFrame) -> dict:
    at_risk = false_negatives.loc[
        false_negatives["fn_cause"].ne("post_revocation_terminal_window")
    ]
    vehicle_keys = ["vehicle_count", "seed", "vehicle_id"]
    fn_vehicles = false_negatives[vehicle_keys].drop_duplicates()
    fn_eventually = false_negatives.loc[
        false_negatives["eventually_revoked"], vehicle_keys
    ].drop_duplicates()
    malicious_vehicle_count = int(
        false_negatives.attrs.get("malicious_vehicle_count", len(fn_vehicles))
    )
    eventually_revoked_count = int(
        false_negatives.attrs.get("eventually_revoked_vehicle_count", len(fn_eventually))
    )

    def records(group_columns: list[str], frame: pd.DataFrame) -> list[dict]:
        return (
            frame.groupby(group_columns, dropna=False)
            .size().rename("count").reset_index()
            .sort_values(group_columns).to_dict(orient="records")
        )

    return {
        "window_level_non_revoked_malicious_rows": int(len(false_negatives)),
        "post_revocation_terminal_windows": int(
            false_negatives["fn_cause"].eq("post_revocation_terminal_window").sum()
        ),
        "at_risk_false_negative_windows": int(len(at_risk)),
        "malicious_vehicles": malicious_vehicle_count,
        "vehicles_eventually_revoked": eventually_revoked_count,
        "vehicles_never_revoked": malicious_vehicle_count - eventually_revoked_count,
        "vehicles_with_at_least_one_fn_window": int(len(fn_vehicles)),
        "fn_vehicles_eventually_revoked": int(len(fn_eventually)),
        "cause_totals": dict(sorted(Counter(at_risk["fn_cause"]).items())),
        "by_density_attack_cause": records(
            ["vehicle_count", "attack_type", "fn_cause"], false_negatives
        ),
        "at_risk_by_density_attack": records(
            ["vehicle_count", "attack_type"], at_risk
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Scenario 5 Phase-1 FN audit")
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--architecture", default=CANONICAL_ARCHITECTURE)
    parser.add_argument("--output", type=Path, help="Optional new JSON output; existing files are refused")
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    decisions = pd.read_csv(args.decisions)
    false_negatives = classify_false_negatives(
        decisions, config["policies"], architecture=args.architecture
    )
    report = build_report(false_negatives)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        if args.output.exists():
            raise FileExistsError(f"Refusing to overwrite existing output: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
