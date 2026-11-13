from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignments", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = pd.read_csv(args.assignments)
    selected = rows.loc[rows.stage.eq("available_before_transport")].copy()
    keys = ["case_id", "observation_root_id", "source_id", "direction"]
    varied_fields = [
        "attestation_id", "validator_rsu_id", "geographic_cell", "sensor_modality", "validity",
        "observed_at", "arrival_at", "age_at_qualification_seconds", "evidence_weight", "fresh", "weight_eligible",
    ]
    grouped = selected.groupby(keys, dropna=False)
    variations = grouped[varied_fields].nunique(dropna=False).gt(1).sum().to_dict()
    record = {
        "stage": "available_before_transport",
        "report_rows": int(len(selected)),
        "unique_case_root_source_direction_groups": int(grouped.ngroups),
        "row_reduction_if_one_per_group_percent": 100.0 * (1.0 - grouped.ngroups / len(selected)),
        "groups_with_more_than_one_report": int((grouped.size() > 1).sum()),
        "exact_duplicate_rows_across_exported_columns": int(selected.duplicated().sum()),
        "groups_with_field_variation": {key: int(value) for key, value in variations.items()},
        "columns_absent_from_diagnostic_export": [
            "detector_confidence", "source_reliability", "freshness_factor", "verifiability", "independence",
            "evidence_hash", "signature", "public_key_id", "reason_codes", "source_kind", "administrative_domain_id",
        ],
        "interpretation": "row-count upper bound only; not a measured CPU or network saving",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
