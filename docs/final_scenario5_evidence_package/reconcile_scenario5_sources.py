"""Read-only reconciliation of the two saved Scenario 5 result populations."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import subprocess
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
REPO = "C:/Users/reemg/OneDrive/Desktop/master/6/v10"
A_REF = "review/scenario5-defense-report-v4"
A_BASE = "results/urban_roundabout_campaign/combined/"
B_BASE = "results/urban_roundabout_campaign_corrected_final/combined/"


def git_bytes(ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "-c", f"safe.directory={REPO}", "-C", REPO, "show", f"{ref}:{path}"])


def frame_bytes(data: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data))


def frame_file(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def confusion(frame: pd.DataFrame) -> dict[str, int]:
    truth = frame.ground_truth_malicious.astype(int).eq(1)
    pred = frame.predicted_revoked.astype(int).eq(1) & frame.committed.astype(int).eq(1)
    return {"TP": int((truth & pred).sum()), "FP": int((~truth & pred).sum()),
            "TN": int((~truth & ~pred).sum()), "FN": int((truth & ~pred).sum()), "N": int(len(frame))}


def main() -> None:
    a = frame_bytes(git_bytes(A_REF, A_BASE + "density_decisions.csv"))
    am = frame_bytes(git_bytes(A_REF, A_BASE + "density_metrics_by_seed.csv"))
    at = frame_bytes(git_bytes(A_REF, A_BASE + "density_trace_audit.csv"))
    b = frame_file(ROOT / B_BASE / "density_decisions.csv")
    bm = frame_file(ROOT / B_BASE / "density_metrics_by_seed.csv")
    bt = frame_file(ROOT / B_BASE / "density_trace_audit.csv")
    key = ["topology", "vehicle_count", "seed", "case_id"]

    def pair(frame: pd.DataFrame, arch_a: str, arch_b: str) -> dict:
        x = frame.loc[frame.architecture.eq(arch_a)].copy()
        y = frame.loc[frame.architecture.eq(arch_b)].copy()
        sx = set(map(tuple, x[key].astype(str).to_numpy()))
        sy = set(map(tuple, y[key].astype(str).to_numpy()))
        z = x.merge(y, on=key, suffixes=("_a", "_b"))
        da = z.predicted_revoked_a.astype(int).eq(1) & z.committed_a.astype(int).eq(1)
        db = z.predicted_revoked_b.astype(int).eq(1) & z.committed_b.astype(int).eq(1)
        return {"A_rows": len(x), "A_unique_case_ids": int(x.case_id.nunique()), "B_rows": len(y),
                "B_unique_case_ids": int(y.case_id.nunique()), "intersection": len(sx & sy),
                "unmatched_A": len(sx - sy), "unmatched_B": len(sy - sx),
                "shared_decision_agreements": int((da == db).sum()), "shared_decision_disagreements": int((da != db).sum()),
                "excluded_A_terminal_reason": int(x.reason.eq("already_revoked_terminal_state").sum()),
                "excluded_B_terminal_reason": int(y.reason.eq("already_revoked_terminal_state").sum()),
                "B_reason_terminal_total": int(y.reason.eq("already_revoked_terminal_state").sum())}

    def by_density(frame: pd.DataFrame, is_metrics: bool) -> list[dict]:
        out = []
        for density in sorted(frame.vehicle_count.unique()):
            row = {"density": int(density)}
            for arch in ("centralized_remote_100ms", "distributed_density_honest"):
                x = frame.loc[frame.vehicle_count.eq(density) & frame.architecture.eq(arch)]
                has_terminal_metrics = "security_cases_evaluated" in x.columns
                terminal = int(x.excluded_post_revocation_cases.sum()) if has_terminal_metrics else int(x.reason.eq("already_revoked_terminal_state").sum()) if "reason" in x.columns else 0
                evaluated = int(x.security_cases_evaluated.sum()) if has_terminal_metrics else int(len(x))
                total = evaluated + terminal if has_terminal_metrics else int(len(x))
                row[arch] = {
                    "rows": total,
                    "evaluated": evaluated,
                    "excluded_terminal": terminal,
                    "TP": int(x.TP.sum()) if is_metrics else None,
                    "FP": int(x.FP.sum()) if is_metrics else None,
                    "TN": int(x.TN.sum()) if is_metrics else None,
                    "FN": int(x.FN.sum()) if is_metrics else None,
                }
            out.append(row)
        return out

    result = {
        "A": {"ref": A_REF, "commit": "638a6d7909aefa192d532932ab1095111475021c",
              "decisions_sha256": sha(git_bytes(A_REF, A_BASE+"density_decisions.csv")),
              "metrics_sha256": sha(git_bytes(A_REF, A_BASE+"density_metrics_by_seed.csv")),
              "manifest_sha256": sha(git_bytes(A_REF, A_BASE+"density_campaign_manifest.json")),
              "decisions_rows": len(a), "per_architecture": a.groupby("architecture").size().to_dict(),
              "distinct_all_pair_keys_per_arch": {k: int(v) for k, v in a.groupby("architecture").apply(lambda g: g[key].astype(str).drop_duplicates().shape[0], include_groups=False).to_dict().items()},
              "C100_vs_D": pair(a, "centralized_remote_100ms", "distributed_density_honest"),
              "density_trace_audit": at.groupby("vehicle_count")["cases"].sum().astype(int).to_dict(),
              "settings": json.loads(git_bytes(A_REF, A_BASE+"density_campaign_manifest.json")),
              "direct_confusion_all_rows": {arch: confusion(g.loc[g.architecture.eq(arch)]) for arch, g in a.groupby("architecture")},
              "metrics_by_density_arch": by_density(am, True)},
        "B": {"ref": "main", "commit": "0c0c10b3d6cbb2075e430a299e3c18cdf382320a",
              "decisions_sha256_worktree": sha((ROOT/B_BASE/"density_decisions.csv").read_bytes()),
              "metrics_sha256_worktree": sha((ROOT/B_BASE/"density_metrics_by_seed.csv").read_bytes()),
              "manifest_sha256_worktree": sha((ROOT/B_BASE/"density_campaign_manifest.json").read_bytes()),
              "effective_config_sha256_worktree": sha((ROOT/"results/urban_roundabout_campaign_corrected_final/effective_config.json").read_bytes()),
              "trace_audit_sha256_worktree": sha((ROOT/B_BASE/"density_trace_audit.csv").read_bytes()),
              "decisions_rows": len(b), "per_architecture": b.groupby("architecture").size().to_dict(),
              "C100_vs_D": pair(b, "centralized_remote_100ms", "distributed_density_honest"),
              "density_trace_audit": bt.groupby("vehicle_count")["cases"].sum().astype(int).to_dict(),
              "settings": json.loads((ROOT/B_BASE/"density_campaign_manifest.json").read_text(encoding="utf-8")),
              "direct_confusion_all_rows": {arch: confusion(g.loc[~g.reason.eq("already_revoked_terminal_state")]) for arch, g in b.groupby("architecture")},
              "metrics_by_density_arch": by_density(bm, True)},
    }
    cross_key_a = set(map(tuple, a.loc[a.architecture.eq("distributed_density_honest"), key].astype(str).to_numpy()))
    cross_key_b = set(map(tuple, b.loc[b.architecture.eq("distributed_density_honest"), key].astype(str).to_numpy()))
    result["A_vs_B_distributed_case_universe"] = {
        "A_canonical_keys": len(cross_key_a), "B_canonical_keys": len(cross_key_b),
        "intersection": len(cross_key_a & cross_key_b), "A_only": len(cross_key_a-cross_key_b), "B_only": len(cross_key_b-cross_key_a),
        "A_unique_case_id_tokens": int(a.loc[a.architecture.eq("distributed_density_honest"), "case_id"].nunique()),
        "B_unique_case_id_tokens": int(b.loc[b.architecture.eq("distributed_density_honest"), "case_id"].nunique()),
        "A_by_density_rows": a[a.architecture.eq("distributed_density_honest")].groupby("vehicle_count").size().astype(int).to_dict(),
        "B_by_density_rows": b[b.architecture.eq("distributed_density_honest")].groupby("vehicle_count").size().astype(int).to_dict(),
        "A_window_index_max": int(a.loc[a.architecture.eq("distributed_density_honest"), "case_id"].str.extract(r"-w(\d+)$")[0].astype(int).max()),
        "B_window_index_max": int(b.loc[b.architecture.eq("distributed_density_honest"), "case_id"].str.extract(r"-w(\d+)$")[0].astype(int).max()),
    }
    da = a.loc[a.architecture.eq("distributed_density_honest"), key+["ground_truth_malicious", "attack_type", "predicted_revoked", "committed"]]
    db = b.loc[b.architecture.eq("distributed_density_honest"), key+["ground_truth_malicious", "attack_type", "predicted_revoked", "committed"]]
    common = da.merge(db, on=key, suffixes=("_A", "_B"))
    result["cross_dataset_shared_key_audit"] = {
        "shared_key_count": len(common),
        "ground_truth_mismatches": int((common.ground_truth_malicious_A.astype(str) != common.ground_truth_malicious_B.astype(str)).sum()),
        "attack_type_mismatches": int((common.attack_type_A.astype(str) != common.attack_type_B.astype(str)).sum()),
        "decision_mismatches": int(((common.predicted_revoked_A.astype(int) & common.committed_A.astype(int)) != (common.predicted_revoked_B.astype(int) & common.committed_B.astype(int))).sum()),
    }
    b_pair = b[b.architecture.eq("centralized_remote_100ms")].merge(
        b[b.architecture.eq("distributed_density_honest")], on=key, suffixes=("_central", "_distributed"))
    ca = b_pair.predicted_revoked_central.astype(int).eq(1) & b_pair.committed_central.astype(int).eq(1)
    cb = b_pair.predicted_revoked_distributed.astype(int).eq(1) & b_pair.committed_distributed.astype(int).eq(1)
    result["B_C100_vs_D_disagreement_ids"] = b_pair.loc[ca != cb, key+[
        "vehicle_id_central", "attack_type_central", "ground_truth_malicious_central",
        "predicted_revoked_central", "committed_central", "reason_central",
        "predicted_revoked_distributed", "committed_distributed", "reason_distributed"]].to_dict(orient="records")
    concise = {
        "A_confusion_direct": result["A"]["direct_confusion_all_rows"],
        "B_confusion_method_b_direct": result["B"]["direct_confusion_all_rows"],
        "A_to_B_universe": result["A_vs_B_distributed_case_universe"],
        "cross_dataset_shared_key_audit": result["cross_dataset_shared_key_audit"],
        "B_C100_vs_D_disagreement_ids": result["B_C100_vs_D_disagreement_ids"],
        "hashes": {"A_decisions": result["A"]["decisions_sha256"], "A_metrics": result["A"]["metrics_sha256"],
                   "A_manifest": result["A"]["manifest_sha256"], "B_decisions": result["B"]["decisions_sha256_worktree"],
                   "B_metrics": result["B"]["metrics_sha256_worktree"], "B_manifest": result["B"]["manifest_sha256_worktree"],
                   "B_effective_config": result["B"]["effective_config_sha256_worktree"], "B_trace_audit": result["B"]["trace_audit_sha256_worktree"]},
    }
    print(json.dumps(concise, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
