from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


CELLS = ((20, 2101), (20, 2102), (60, 2101), (60, 2102), (100, 2101), (100, 2102))


def completed_trace_dir(root: Path, layout: str, density: int, seed: int) -> Path:
    parent = root / "pilot" / layout / f"vehicles_{density}"
    direct = parent / f"seed_{seed}"
    if (direct / "run_summary.json").is_file():
        return direct
    completed = sorted(
        path for path in parent.glob(f"seed_{seed}_retry*")
        if (path / "run_summary.json").is_file()
    )
    if len(completed) != 1:
        raise RuntimeError(f"expected one completed trace for {layout}/{density}/{seed}, found {completed}")
    return completed[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-root", type=Path, required=True)
    parser.add_argument("--b1-decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    b1_all = pd.read_csv(args.b1_decisions)
    rows = []
    new_fps = []
    transitions = []
    for layout in ("C1", "C3"):
        for density, seed in CELLS:
            b1 = b1_all.loc[
                b1_all.architecture.eq(f"{layout}_B1")
                & b1_all.vehicle_count.eq(density)
                & b1_all.seed.eq(seed)
            ].copy()
            trace_dir = completed_trace_dir(args.trace_root, layout, density, seed)
            b0_path = trace_dir / f"{layout}_B0_decisions.csv"
            b0 = pd.read_csv(b0_path)
            if len(b0) != len(b1):
                raise AssertionError(f"case population mismatch at {layout}/{density}/{seed}: {len(b0)} vs {len(b1)}")
            joined = b0.merge(b1, on="case_id", suffixes=("_B0", "_B1"), validate="one_to_one")
            if not (joined.ground_truth_malicious_B0 == joined.ground_truth_malicious_B1).all():
                raise AssertionError("ground truth differs between B0 and B1")
            left_meta = joined.metadata_json_B0.map(json.loads)
            right_meta = joined.metadata_json_B1.map(json.loads)
            for field in ("arrived_attestations", "attempted_attestations"):
                equal = [a.get(field) == b.get(field) for a, b in zip(left_meta, right_meta)]
                if not all(equal):
                    raise AssertionError(f"input/delivery provenance changed at {layout}/{density}/{seed}: {field}")
            active_rows = [not bool(meta.get("excluded_post_revocation", False)) for meta in right_meta]
            for field in ("evidence_observed_at", "evidence_arrival_times"):
                equal = [
                    a.get(field) == b.get(field)
                    for a, b, active in zip(left_meta, right_meta, active_rows)
                    if active
                ]
                if not all(equal):
                    raise AssertionError(f"pre-terminal evidence timing differs at {layout}/{density}/{seed}: {field}")
            malicious = joined.ground_truth_malicious_B0.eq(1)
            benign = ~malicious
            old_tp = malicious & joined.predicted_revoked_B0.eq(1)
            new_tp = malicious & joined.predicted_revoked_B1.eq(1)
            old_fp = benign & joined.predicted_revoked_B0.eq(1)
            new_fp_mask = benign & joined.predicted_revoked_B1.eq(1)
            for index, item in joined.iterrows():
                was_revoked = bool(item.predicted_revoked_B0)
                is_revoked = bool(item.predicted_revoked_B1)
                truth = int(item.ground_truth_malicious_B0)
                if was_revoked != is_revoked:
                    before, after = left_meta.iloc[index], right_meta.iloc[index]
                    transitions.append({
                        "layout": layout, "density": density, "seed": seed,
                        "case_id": item.case_id, "vehicle_id": item.vehicle_id_B1,
                        "ground_truth_malicious": truth,
                        "B0_revoked": int(was_revoked), "B1_revoked": int(is_revoked),
                        "B0_qualified": int(bool(before.get("qualification_outcome", False))),
                        "B1_qualified": int(bool(after.get("qualification_outcome", False))),
                        "B0_margin": before.get("qualification_margin"),
                        "B1_margin": after.get("qualification_margin"),
                        "B0_roots": before.get("independent_roots"), "B1_roots": after.get("independent_roots"),
                        "B0_sources": before.get("distinct_sources"), "B1_sources": after.get("distinct_sources"),
                        "B0_zones": before.get("distinct_zones"), "B1_zones": after.get("distinct_zones"),
                    })
            for case_id, vehicle_id in joined.loc[new_fp_mask & ~old_fp, ["case_id", "vehicle_id_B1"]].itertuples(index=False, name=None):
                new_fps.append({"layout": layout, "density": density, "seed": seed, "case_id": case_id, "vehicle_id": vehicle_id})
            def mean_meta(mask, field):
                selected = [meta.get(field, 0.0) for meta, keep in zip(right_meta, mask) if keep]
                return sum(float(v or 0.0) for v in selected) / max(1, len(selected))
            def mean_b0_meta(mask, field):
                selected = [meta.get(field, 0.0) for meta, keep in zip(left_meta, mask) if keep]
                return sum(float(v or 0.0) for v in selected) / max(1, len(selected))
            def count_ge2(mask, field, side):
                metas = left_meta if side == "B0" else right_meta
                return sum(int(meta.get(field, 0) >= 2) for meta, keep in zip(metas, mask) if keep)
            rows.append({
                "layout": layout, "density": density, "seed": seed, "cases": len(joined),
                "malicious_cases": int(malicious.sum()),
                "B0_TP": int(old_tp.sum()), "B1_TP": int(new_tp.sum()),
                "new_TP_cases": int((new_tp & ~old_tp).sum()), "lost_TP_cases": int((old_tp & ~new_tp).sum()),
                "B0_FP": int(old_fp.sum()), "B1_FP": int(new_fp_mask.sum()),
                "new_FP_cases": int((new_fp_mask & ~old_fp).sum()), "removed_FP_cases": int((old_fp & ~new_fp_mask).sum()),
                "B0_qualified": int(joined.metadata_json_B0.map(lambda s: int(bool(json.loads(s).get("qualification_outcome", False)))).sum()),
                "B1_qualified": int(joined.metadata_json_B1.map(lambda s: int(bool(json.loads(s).get("qualification_outcome", False)))).sum()),
                "new_B1_qualified_malicious": int((malicious & ~joined.metadata_json_B0.map(lambda s: bool(json.loads(s).get("qualification_outcome", False))) & joined.metadata_json_B1.map(lambda s: bool(json.loads(s).get("qualification_outcome", False)))).sum()),
                "new_B1_qualified_benign": int((benign & ~joined.metadata_json_B0.map(lambda s: bool(json.loads(s).get("qualification_outcome", False))) & joined.metadata_json_B1.map(lambda s: bool(json.loads(s).get("qualification_outcome", False)))).sum()),
                "B1_post_revocation_terminal_windows": sum(int(bool(meta.get("excluded_post_revocation", False))) for meta in right_meta),
                "B0_malicious_ge2_roots": count_ge2(malicious, "independent_roots", "B0"),
                "B1_malicious_ge2_roots": count_ge2(malicious, "independent_roots", "B1"),
                "B0_malicious_ge2_sources": count_ge2(malicious, "distinct_sources", "B0"),
                "B1_malicious_ge2_sources": count_ge2(malicious, "distinct_sources", "B1"),
                "B0_malicious_ge2_zones": count_ge2(malicious, "distinct_zones", "B0"),
                "B1_malicious_ge2_zones": count_ge2(malicious, "distinct_zones", "B1"),
                "B0_mean_support": mean_b0_meta(malicious, "supporting_strength"),
                "B1_mean_support": mean_meta(malicious, "supporting_strength"),
                "B0_mean_opposition": mean_b0_meta(malicious, "opposing_strength"),
                "B1_mean_opposition": mean_meta(malicious, "opposing_strength"),
                "same_delivered_evidence_counts_and_nonterminal_arrival_times": True,
            })
    args.output.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output / "b1_case_differences.csv", index=False)
    pd.DataFrame(new_fps, columns=["layout", "density", "seed", "case_id", "vehicle_id"]).to_csv(
        args.output / "b1_new_false_positives.csv", index=False
    )
    pd.DataFrame(transitions).to_csv(args.output / "b1_case_transitions.csv", index=False)


if __name__ == "__main__":
    main()
