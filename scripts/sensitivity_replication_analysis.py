"""Validate and summarize the bounded Scenario 5 sensitivity replication."""
from __future__ import annotations

import hashlib
import json
import math
import sys
import copy
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import t

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.sensitivity_opportunities import (  # noqa: E402
    build_base_emission_times,
    evaluate_attack_opportunities,
)
from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics  # noqa: E402

DEFAULT_RAW = Path(r"C:\Users\reemg\AppData\Local\VPUFT-Preservation-2026-11-15\sensitivity_replication_2026-11-16")
DEFAULT_OUT = ROOT / "results/final_scenario5_sensitivity/replication_2026-11-16"
DENSITIES = (20, 100)
SEEDS = (7003, 7004, 7005, 7006, 7007, 7008)
ARCHITECTURES = ("C100", "Distributed")
VARIANTS = ("baseline", "freshness_12s", "freshness_30s", "position_sources_1", "position_sources_3")
METRICS = (
    "TP", "FP", "TN", "FN", "excluded_post_revocation_cases",
    "malicious_revocation_recall", "trust_precision", "false_revocation_rate",
    "trust_f1", "mcc", "opportunity_detection_recall",
    "protected_opportunity_fraction", "cpu_time_seconds", "latency_p95_ms",
    "messages_per_decision", "bytes_per_decision", "packet_delivery_ratio",
    "ledger_consistency_delay_p95_ms", "consensus_latency_p95_ms",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def expected_cell_keys() -> list[tuple[str, int, int, str]]:
    return [
        (variant, density, seed, architecture)
        for density in DENSITIES
        for seed in SEEDS
        for variant in VARIANTS
        for architecture in ARCHITECTURES
    ]


def paired_t_summary(values) -> dict[str, float | int]:
    x = np.asarray(list(values), dtype=float)
    x = x[np.isfinite(x)]
    n = int(x.size)
    mean = float(np.mean(x)) if n else math.nan
    median = float(np.median(x)) if n else math.nan
    sd = float(np.std(x, ddof=1)) if n >= 2 else math.nan
    if n >= 2:
        half_width = float(t.ppf(0.975, n - 1) * sd / math.sqrt(n))
        low, high = mean - half_width, mean + half_width
        dz = mean / sd if sd > 0 else (0.0 if mean == 0 else math.nan)
    else:
        low = high = dz = math.nan
    return {"n": n, "mean": mean, "median": median, "sd": sd,
            "ci95_low": low, "ci95_high": high, "cohens_dz": dz}


def _cell_key(row: dict) -> tuple[str, int, int, str]:
    return (str(row["variant_id"]), int(float(row["density"])),
            int(float(row["seed"])), str(row["architecture"]))


def _metric_confusion(tp: int, fp: int, tn: int, fn: int) -> tuple[float, float, float, float, float]:
    div = lambda a, b: float(a / b) if b else 0.0
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    frr = div(fp, fp + tn)
    f1 = div(2 * precision * recall, precision + recall)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = div(tp * tn - fp * fn, denominator)
    return precision, recall, frr, f1, mcc


def _assert_config_changes(configs: dict) -> None:
    baseline = configs["baseline"]["effective_config"]
    if any(float(policy["freshness_window_seconds"]) != 15.0
           for policy in baseline["policies"].values()):
        raise RuntimeError("Baseline freshness does not match the preregistered 15 seconds")
    if baseline["policies"]["position_offset"]["required_sources"] != 2:
        raise RuntimeError("Baseline position-offset source threshold is not 2")
    def differences(left, right, prefix=()):
        if isinstance(left, dict) and isinstance(right, dict):
            if set(left) != set(right):
                return [prefix + ("<keys>",)]
            out = []
            for key in left:
                out.extend(differences(left[key], right[key], prefix + (str(key),)))
            return out
        return [] if left == right else [prefix]

    for variant, expected_freshness, expected_sources in (
        ("freshness_12s", 12.0, None),
        ("freshness_30s", 30.0, None),
        ("position_sources_1", None, 1),
        ("position_sources_3", None, 3),
    ):
        candidate = configs[variant]["effective_config"]
        observed_changes = set(differences(baseline, candidate))
        if expected_freshness is not None:
            allowed = {("policies", name, "freshness_window_seconds")
                       for name in baseline["policies"]}
            if observed_changes != allowed:
                raise RuntimeError(f"Unregistered configuration differences in {variant}: {observed_changes ^ allowed}")
            if any(float(policy["freshness_window_seconds"]) != expected_freshness
                   for policy in candidate["policies"].values()):
                raise RuntimeError(f"Unexpected freshness value in {variant}")
        else:
            allowed = {("policies", "position_offset", "required_sources")}
            if observed_changes != allowed:
                raise RuntimeError(f"Unregistered configuration differences in {variant}: {observed_changes ^ allowed}")
            if candidate["policies"]["position_offset"]["required_sources"] != expected_sources:
                raise RuntimeError(f"Wrong source requirement in {variant}")


def _verify_raw(raw: Path):
    status = json.loads((raw / "replication_status.json").read_text(encoding="utf-8"))
    manifest = pd.read_csv(raw / "SENSITIVITY_RUN_MANIFEST.csv")
    metrics = pd.read_csv(raw / "SENSITIVITY_METRICS_BY_SEED.csv")
    decisions = pd.read_csv(raw / "SENSITIVITY_CASE_DECISIONS.csv")
    opportunities = pd.read_csv(raw / "SENSITIVITY_FIXED_OPPORTUNITIES.csv")
    traces_doc = json.loads((raw / "SENSITIVITY_TRACE_MANIFEST.json").read_text(encoding="utf-8"))
    context = json.loads((raw / "RUN_CONTEXT.json").read_text(encoding="utf-8"))
    frozen_hashes = json.loads((raw / "FROZEN_INPUT_HASHES.json").read_text(encoding="utf-8"))
    configs = json.loads((raw / "SENSITIVITY_EFFECTIVE_CONFIGS.json").read_text(encoding="utf-8"))

    expected = set(expected_cell_keys())
    actual_keys = [_cell_key(row) for row in manifest.to_dict("records")]
    if manifest.status.ne("completed").any():
        raise RuntimeError("The actual manifest contains a failed or non-completed attempt")
    if len(actual_keys) != len(set(actual_keys)):
        raise RuntimeError("Duplicate architecture cell in the actual manifest")
    actual = set(actual_keys)
    if not actual <= expected:
        raise RuntimeError("Unexpected architecture cell outside the preregistered design")
    if len(actual) != int(status["completed_runs"]) or len(manifest) != len(metrics):
        raise RuntimeError("Status, manifest and metrics row counts disagree")
    if status.get("status") not in {"completed", "paused_wall_cap"}:
        raise RuntimeError(f"Unexpected final runner state: {status.get('status')}")
    if len(opportunities) != len(actual) or len(metrics) != len(actual):
        raise RuntimeError("Metrics/opportunity tables do not cover every completed run")
    if set(configs) != set(VARIANTS):
        raise RuntimeError("Effective configuration set differs from preregistration")
    _assert_config_changes(configs)
    if len(traces_doc["traces"]) != 12:
        raise RuntimeError("Expected 12 shared traces")
    trace_map = {}
    trace_files = {
        "shared_detection_trace.jsonl": "trace_sha256",
        "generated_messages.csv": "generated_messages_sha256",
        "attack_ground_truth.csv": "attack_ground_truth_sha256",
        "mobility_trace.csv": "mobility_trace_sha256",
        "scenario_manifest.json": "scenario_manifest_sha256",
    }
    for trace in traces_doc["traces"]:
        key = (int(trace["density"]), int(trace["seed"]))
        if key in trace_map:
            raise RuntimeError(f"Duplicate trace key: {key}")
        trace_map[key] = trace
        trace_dir = raw / trace["trace_relative_directory"]
        for name, hash_key in trace_files.items():
            path = trace_dir / name
            if not path.is_file() or sha256(path) != trace[hash_key]:
                raise RuntimeError(f"Trace hash mismatch: {path}")
    if set(trace_map) != {(density, seed) for density in DENSITIES for seed in SEEDS}:
        raise RuntimeError("Trace manifest does not cover the preregistered density-seed pairs")

    for relative, expected_hash in context["source_and_input_sha256"].items():
        path = ROOT / relative
        if not path.is_file() or sha256(path) != expected_hash:
            raise RuntimeError(f"Execution input hash mismatch: {relative}")
    if frozen_hashes != context["source_and_input_sha256"]:
        raise RuntimeError("Frozen input hash file differs from run context")
    for name, config in configs.items():
        canonical = json.dumps(config["effective_config"], sort_keys=True, separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(canonical).hexdigest() != config["effective_config_sha256"]:
            raise RuntimeError(f"Effective config hash mismatch: {name}")

    manifest_keys = set(actual)
    for table_name, table in (("metrics", metrics), ("opportunities", opportunities)):
        keys = [_cell_key(row) for row in table.to_dict("records")]
        if len(keys) != len(set(keys)) or set(keys) != manifest_keys:
            raise RuntimeError(f"{table_name} table cell keys differ from the manifest")
    if decisions.duplicated(["variant_id", "density", "seed", "architecture", "case_id"]).any():
        raise RuntimeError("Duplicate case-level decision")
    metric_by_key = {_cell_key(row): row for row in metrics.to_dict("records")}
    opportunity_by_key = {_cell_key(row): row for row in opportunities.to_dict("records")}
    decision_groups = {key: group.copy() for key, group in decisions.groupby(
        ["variant_id", "density", "seed", "architecture"], dropna=False)}
    manifest_by_key = {_cell_key(row): row for row in manifest.to_dict("records")}
    trace_cache = {}

    for key in sorted(actual):
        metric = metric_by_key[key]
        opportunity = opportunity_by_key[key]
        run = manifest_by_key[key]
        group = decision_groups.get(key)
        if group is None or len(group) != int(float(run["case_count"])):
            raise RuntimeError(f"Case decision count mismatch for {key}")
        if int(metric["case_count"]) != len(group):
            raise RuntimeError(f"Metrics/case decision mismatch for {key}")
        expected_trace = trace_map[(key[1], key[2])]["trace_sha256"]
        if any(str(x) != expected_trace for x in (metric["trace_sha256"],
                                                    opportunity["trace_sha256"],
                                                    run["trace_sha256"])):
            raise RuntimeError(f"Trace fingerprint mismatch for {key}")
        expected_backhaul = 100.0 if key[3] == "C100" else 0.0
        if not math.isclose(float(metric["backhaul_extra_latency_ms"]), expected_backhaul,
                            rel_tol=0, abs_tol=1e-12):
            raise RuntimeError(f"Architecture backhaul setting mismatch for {key}")
        if not group.trace_sha256.eq(expected_trace).all():
            raise RuntimeError(f"Case rows have a different trace fingerprint for {key}")

        method_b_input = group[["case_id", "vehicle_id", "seed", "architecture",
                                "ground_truth_malicious", "committed", "new_state"]].copy()
        method_b = state_aware_first_revocation_metrics(method_b_input, window_seconds=15.0)
        if len(method_b) != 1:
            raise RuntimeError(f"Method B produced no unique row for {key}")
        verified = method_b.iloc[0]
        for column in ("TP", "FP", "TN", "FN"):
            if int(verified[column]) != int(metric[column]):
                raise RuntimeError(f"Method B {column} mismatch for {key}")
        if int(verified["excluded_post_revocation_windows"]) != int(metric["excluded_post_revocation_cases"]):
            raise RuntimeError(f"Method B terminal exclusion mismatch for {key}")

        trace = trace_map[(key[1], key[2])]
        trace_dir = raw / trace["trace_relative_directory"]
        if (key[1], key[2]) not in trace_cache:
            generated = pd.read_csv(trace_dir / "generated_messages.csv")
            attacks = generated[generated.ground_truth_malicious.astype(str).str.lower().isin(["true", "1"])]
            mobility = pd.read_csv(trace_dir / "mobility_trace.csv")
            events = pd.read_json(trace_dir / "shared_detection_trace.jsonl", lines=True)
            trace_cache[(key[1], key[2])] = {
                "attacks": attacks.to_dict("records"),
                "base_emission_times": build_base_emission_times(mobility.to_dict("records"), seed=key[2]),
                "events": events.to_dict("records"),
            }
        data = trace_cache[(key[1], key[2])]
        recalculated = evaluate_attack_opportunities(
            data["attacks"], data["events"], group.to_dict("records"),
            data["base_emission_times"], seed=key[2], window_seconds=15.0)
        for column, value in recalculated.items():
            stored = opportunity[column]
            if isinstance(value, float):
                if not math.isclose(float(stored), value, rel_tol=0, abs_tol=1e-12):
                    raise RuntimeError(f"Opportunity {column} mismatch for {key}")
            elif int(float(stored)) != int(value):
                raise RuntimeError(f"Opportunity {column} mismatch for {key}")

    # Every available architecture/configuration cell for a seed must use the same case universe.
    for (density, seed), sub in decisions.groupby(["density", "seed"], dropna=False):
        universes = sub.groupby(["variant_id", "architecture"]).case_id.apply(set)
        if universes.empty or any(case_ids != universes.iloc[0] for case_ids in universes.iloc[1:]):
            raise RuntimeError(f"Paired case universe mismatch for {(density, seed)}")
    # Fixed opportunity denominator must be identical across all available conditions per trace.
    for key, group in opportunities.groupby(["density", "seed"], dropna=False):
        if group.attack_message_opportunities.nunique() != 1:
            raise RuntimeError(f"Attack opportunity denominator changed for {key}")

    missing = expected - actual
    return status, manifest, metrics, decisions, opportunities, traces_doc, context, configs, missing, trace_map, trace_cache


def paired_summary(metrics: pd.DataFrame, opportunities: pd.DataFrame) -> pd.DataFrame:
    metric_rows = {_cell_key(row): row for row in metrics.to_dict("records")}
    opportunity_rows = {_cell_key(row): row for row in opportunities.to_dict("records")}
    rows = []
    for density in DENSITIES:
        for architecture in ARCHITECTURES:
            common_seeds = [seed for seed in SEEDS if all(
                (variant, density, seed, architecture) in metric_rows for variant in VARIANTS
            )]
            for variant in VARIANTS:
                deltas = {name: [] for name in METRICS}
                variant_values = {name: [] for name in METRICS}
                baseline_values = {name: [] for name in METRICS}
                seeds_used = []
                for seed in common_seeds:
                    vkey = (variant, density, seed, architecture)
                    bkey = ("baseline", density, seed, architecture)
                    v, b = metric_rows[vkey], metric_rows[bkey]
                    vo, bo = opportunity_rows[vkey], opportunity_rows[bkey]
                    seeds_used.append(seed)
                    for name in METRICS:
                        vvalue = float(vo[name]) if name in vo else float(v[name])
                        bvalue = float(bo[name]) if name in bo else float(b[name])
                        variant_values[name].append(vvalue)
                        baseline_values[name].append(bvalue)
                        deltas[name].append(vvalue - bvalue)
                if not seeds_used:
                    continue
                key = (variant, density, seeds_used[0], architecture)
                selected_metrics = [metric_rows[(variant, density, seed, architecture)] for seed in seeds_used]
                selected_opps = [opportunity_rows[(variant, density, seed, architecture)] for seed in seeds_used]
                base_metrics = [metric_rows[("baseline", density, seed, architecture)] for seed in seeds_used]
                base_opps = [opportunity_rows[("baseline", density, seed, architecture)] for seed in seeds_used]
                pooled = {name: int(sum(int(row[name]) for row in selected_metrics))
                          for name in ("TP", "FP", "TN", "FN")}
                base_pooled = {name: int(sum(int(row[name]) for row in base_metrics))
                               for name in ("TP", "FP", "TN", "FN")}
                p, r, frr, f1, mcc = _metric_confusion(
                    pooled["TP"], pooled["FP"], pooled["TN"], pooled["FN"])
                bp, br, bfrr, bf1, bmcc = _metric_confusion(
                    base_pooled["TP"], base_pooled["FP"], base_pooled["TN"], base_pooled["FN"])
                row = {
                    "variant_id": variant, "density": density, "architecture": architecture,
                    "seed_n": len(seeds_used), "paired_seeds": ";".join(map(str, seeds_used)),
                    **{f"variant_pooled_{name}": value for name, value in pooled.items()},
                    **{f"baseline_paired_pooled_{name}": value for name, value in base_pooled.items()},
                    "variant_precision_pooled": p, "variant_recall_pooled": r,
                    "variant_FRR_pooled": frr, "variant_F1_pooled": f1, "variant_MCC_pooled": mcc,
                    "baseline_precision_pooled": bp, "baseline_recall_pooled": br,
                    "baseline_FRR_pooled": bfrr, "baseline_F1_pooled": bf1, "baseline_MCC_pooled": bmcc,
                    "variant_excluded_terminal_windows": int(sum(int(x["excluded_post_revocation_cases"]) for x in selected_metrics)),
                    "baseline_excluded_terminal_windows": int(sum(int(x["excluded_post_revocation_cases"]) for x in base_metrics)),
                    "variant_state_recall_macro": float(np.mean([x["malicious_revocation_recall"] for x in selected_metrics])),
                    "baseline_state_recall_macro": float(np.mean([x["malicious_revocation_recall"] for x in base_metrics])),
                    "variant_opportunity_denominator": int(sum(int(x["attack_message_opportunities"]) for x in selected_opps)),
                    "variant_detected_opportunities": int(sum(int(x["successfully_detected_attack_messages"]) for x in selected_opps)),
                    "baseline_detected_opportunities": int(sum(int(x["successfully_detected_attack_messages"]) for x in base_opps)),
                    "variant_protected_opportunities": int(sum(int(x["protected_attack_messages"]) for x in selected_opps)),
                    "baseline_protected_opportunities": int(sum(int(x["protected_attack_messages"]) for x in base_opps)),
                    "variant_opportunity_recall_pooled": (
                        sum(int(x["successfully_detected_attack_messages"]) for x in selected_opps) /
                        max(1, sum(int(x["attack_message_opportunities"]) for x in selected_opps))),
                    "baseline_opportunity_recall_pooled": (
                        sum(int(x["successfully_detected_attack_messages"]) for x in base_opps) /
                        max(1, sum(int(x["attack_message_opportunities"]) for x in base_opps))),
                    "variant_protected_fraction_pooled": (
                        sum(int(x["protected_attack_messages"]) for x in selected_opps) /
                        max(1, sum(int(x["attack_message_opportunities"]) for x in selected_opps))),
                    "baseline_protected_fraction_pooled": (
                        sum(int(x["protected_attack_messages"]) for x in base_opps) /
                        max(1, sum(int(x["attack_message_opportunities"]) for x in base_opps))),
                }
                for metric_name in METRICS:
                    vvalues = variant_values[metric_name]
                    bvalues = baseline_values[metric_name]
                    delta = deltas[metric_name]
                    summ = paired_t_summary(delta)
                    row[f"{metric_name}_variant_seed_mean"] = float(np.mean(vvalues))
                    row[f"{metric_name}_baseline_paired_seed_mean"] = float(np.mean(bvalues))
                    row[f"delta_{metric_name}_mean"] = summ["mean"]
                    row[f"delta_{metric_name}_median"] = summ["median"]
                    row[f"delta_{metric_name}_ci95_low"] = summ["ci95_low"]
                    row[f"delta_{metric_name}_ci95_high"] = summ["ci95_high"]
                    row[f"delta_{metric_name}_cohens_dz"] = summ["cohens_dz"]
                    row[f"delta_{metric_name}_positive"] = int(sum(x > 1e-12 for x in delta))
                    row[f"delta_{metric_name}_unchanged"] = int(sum(abs(x) <= 1e-12 for x in delta))
                    row[f"delta_{metric_name}_negative"] = int(sum(x < -1e-12 for x in delta))
                    row[f"delta_{metric_name}_percent_mean"] = float(np.mean([
                        100.0 * d / b if abs(b) > 1e-12 else math.nan
                        for d, b in zip(delta, bvalues)
                    ]))
                rows.append(row)
    return pd.DataFrame(rows)


def architecture_summary(metrics: pd.DataFrame, opportunities: pd.DataFrame) -> pd.DataFrame:
    metric_rows = {_cell_key(row): row for row in metrics.to_dict("records")}
    opportunity_rows = {_cell_key(row): row for row in opportunities.to_dict("records")}
    rows = []
    for variant in VARIANTS:
        for density in DENSITIES:
            seeds = [seed for seed in SEEDS if all(
                (variant, density, seed, arch) in metric_rows for arch in ARCHITECTURES
            )]
            for metric in METRICS:
                values = []
                for seed in seeds:
                    c, d = metric_rows[(variant, density, seed, "C100")], metric_rows[(variant, density, seed, "Distributed")]
                    co, do = opportunity_rows[(variant, density, seed, "C100")], opportunity_rows[(variant, density, seed, "Distributed")]
                    cv = float(co[metric]) if metric in co else float(c[metric])
                    dv = float(do[metric]) if metric in do else float(d[metric])
                    values.append(dv - cv)
                summary = paired_t_summary(values)
                rows.append({"variant_id": variant, "density": density, "metric": metric,
                             "paired_seed_n": summary["n"], "paired_seeds": ";".join(map(str, seeds)),
                             "distributed_minus_C100_mean": summary["mean"],
                             "distributed_minus_C100_median": summary["median"],
                             "ci95_low": summary["ci95_low"], "ci95_high": summary["ci95_high"],
                             "cohens_dz": summary["cohens_dz"],
                             "improved_count_positive_delta": sum(x > 1e-12 for x in values),
                             "unchanged_count": sum(abs(x) <= 1e-12 for x in values),
                             "worsened_count_negative_delta": sum(x < -1e-12 for x in values)})
    return pd.DataFrame(rows)


def case_difference_table(metrics: pd.DataFrame, decisions: pd.DataFrame) -> pd.DataFrame:
    key_cols = ["density", "seed", "architecture"]
    decision_groups = {(key[0], int(key[1]), int(key[2]), key[3]): group
                       for key, group in decisions.groupby(["variant_id", *key_cols], dropna=False)}
    rows = []
    for variant in VARIANTS[1:]:
        for density in DENSITIES:
            for architecture in ARCHITECTURES:
                seeds = [seed for seed in SEEDS if
                         (variant, density, seed, architecture) in decision_groups and
                         ("baseline", density, seed, architecture) in decision_groups]
                for seed in seeds:
                    base = decision_groups[("baseline", density, seed, architecture)].set_index("case_id")
                    candidate = decision_groups[(variant, density, seed, architecture)].set_index("case_id")
                    if set(base.index) != set(candidate.index):
                        raise RuntimeError(f"Case universe differs for {variant}/{density}/{seed}/{architecture}")
                    for case_id in sorted(base.index):
                        b, v = base.loc[case_id], candidate.loc[case_id]
                        b_eligible = str(b.reason) != "already_revoked_terminal_state"
                        v_eligible = str(v.reason) != "already_revoked_terminal_state"
                        b_pred, v_pred = int(b.predicted_revoked), int(v.predicted_revoked)
                        actual = int(b.ground_truth_malicious)
                        b_fp = b_eligible and not actual and b_pred
                        v_fp = v_eligible and not actual and v_pred
                        b_tp = b_eligible and bool(actual) and b_pred
                        v_tp = v_eligible and bool(actual) and v_pred
                        if (b_fp != v_fp or b_tp != v_tp or b_eligible != v_eligible or
                                b.new_state != v.new_state or b.committed != v.committed):
                            rows.append({"variant_id": variant, "density": density, "seed": seed,
                                         "architecture": architecture, "case_id": case_id,
                                         "vehicle_id": b.vehicle_id, "ground_truth_malicious": actual,
                                         "baseline_eligible": int(b_eligible), "variant_eligible": int(v_eligible),
                                         "baseline_state": b.new_state, "variant_state": v.new_state,
                                         "baseline_committed": int(b.committed), "variant_committed": int(v.committed),
                                         "new_false_positive": int(bool(v_fp and not b_fp)),
                                         "removed_false_positive": int(bool(b_fp and not v_fp)),
                                         "recovered_true_positive": int(bool(v_tp and not b_tp)),
                                         "lost_true_positive": int(bool(b_tp and not v_tp))})
    return pd.DataFrame(rows)


def architecture_case_difference_table(decisions: pd.DataFrame) -> pd.DataFrame:
    groups = {key: group.set_index("case_id") for key, group in decisions.groupby(
        ["variant_id", "density", "seed", "architecture"], dropna=False)}
    rows = []
    for variant in VARIANTS:
        for density in DENSITIES:
            for seed in SEEDS:
                ckey = (variant, density, seed, "C100")
                dkey = (variant, density, seed, "Distributed")
                if ckey not in groups or dkey not in groups:
                    continue
                central, distributed = groups[ckey], groups[dkey]
                if set(central.index) != set(distributed.index):
                    raise RuntimeError(f"C100/Distributed case universe differs: {variant}/{density}/{seed}")
                for case_id in sorted(central.index):
                    c, d = central.loc[case_id], distributed.loc[case_id]
                    if (int(c.predicted_revoked) != int(d.predicted_revoked) or
                            str(c.new_state) != str(d.new_state) or int(c.committed) != int(d.committed) or
                            str(c.reason) != str(d.reason)):
                        rows.append({"variant_id": variant, "density": density, "seed": seed,
                                     "case_id": case_id, "vehicle_id": c.vehicle_id,
                                     "ground_truth_malicious": int(c.ground_truth_malicious),
                                     "C100_predicted_revoked": int(c.predicted_revoked),
                                     "Distributed_predicted_revoked": int(d.predicted_revoked),
                                     "C100_state": c.new_state, "Distributed_state": d.new_state,
                                     "C100_committed": int(c.committed),
                                     "Distributed_committed": int(d.committed),
                                     "C100_reason": c.reason, "Distributed_reason": d.reason,
                                     "C100_finalized_at": c.finalized_at,
                                     "Distributed_finalized_at": d.finalized_at})
    return pd.DataFrame(rows)


def _mean_ci(values) -> tuple[float, float, float]:
    out = paired_t_summary(values)
    return out["mean"], out["ci95_low"], out["ci95_high"]


def make_figures(metrics: pd.DataFrame, opportunities: pd.DataFrame, summary: pd.DataFrame, out: Path) -> list[str]:
    figure_dir = out / "figures"
    figure_dir.mkdir(parents=True, exist_ok=True)
    all_values = metrics.merge(opportunities[["variant_id", "density", "seed", "architecture",
                                               "opportunity_detection_recall", "protected_opportunity_fraction"]],
                               on=["variant_id", "density", "seed", "architecture"], validate="one_to_one")
    labels = ["Baseline", "Fresh 12 s", "Fresh 30 s", "Sources 1*", "Sources 3"]
    figures = []

    fig, axes = plt.subplots(2, 2, figsize=(13, 8), sharex="col")
    for r, density in enumerate(DENSITIES):
        for c, (metric, title) in enumerate((("malicious_revocation_recall", "State-aware Recall"),
                                              ("opportunity_detection_recall", "Fixed-denominator opportunity Recall"))):
            ax = axes[r, c]
            for architecture in ARCHITECTURES:
                means, lows, highs = [], [], []
                for variant in VARIANTS:
                    row = summary[(summary.variant_id == variant) & (summary.density == density) &
                                  (summary.architecture == architecture)]
                    means.append(float(row[f"{metric}_variant_seed_mean"].iloc[0]))
                    selected_seeds = {int(s) for s in str(row.paired_seeds.iloc[0]).split(";") if s}
                    selected = all_values[(all_values.variant_id == variant) &
                                          (all_values.density == density) &
                                          (all_values.architecture == architecture) &
                                          (all_values.seed.astype(int).isin(selected_seeds))]
                    dci = paired_t_summary(selected[metric])
                    # Report 95% t intervals around the seed-level descriptive mean.
                    lows.append(float(dci["ci95_low"]))
                    highs.append(float(dci["ci95_high"]))
                yerr = np.array([[m - lo for m, lo in zip(means, lows)],
                                 [hi - m for m, hi in zip(means, highs)]])
                ax.errorbar(range(len(VARIANTS)), means, yerr=yerr, marker="o", capsize=3,
                            label=architecture)
            ax.set_title(f"{title} — density {density}")
            ax.set_xticks(range(len(VARIANTS)), labels, rotation=18, ha="right")
            ax.set_ylim(bottom=0)
            ax.grid(alpha=.25)
            ax.set_ylabel("Fraction")
            if r == 0 and c == 0:
                ax.legend()
    fig.suptitle("Scenario 5 sensitivity replication — per-seed means, 95% t intervals\n"
                 "density 20: n=6 paired seeds; density 100: n=4 paired seeds; *weakened-policy stress test",
                 fontsize=12)
    fig.tight_layout(rect=(0, 0, 1, .92))
    name = "RECALL_SENSITIVITY_300dpi.png"
    fig.savefig(figure_dir / name, dpi=300, bbox_inches="tight")
    plt.close(fig)
    figures.append(f"figures/{name}")

    cost_specs = (("cpu_time_seconds", "Host CPU time (s)"),
                  ("latency_p95_ms", "P95 E2E (ms)"),
                  ("messages_per_decision", "Messages per case"),
                  ("packet_delivery_ratio", "PDR (fraction)"))
    fig, axes = plt.subplots(2, 4, figsize=(19, 8), sharex="col")
    for r, density in enumerate(DENSITIES):
        for c, (metric, title) in enumerate(cost_specs):
            ax = axes[r, c]
            for architecture in ARCHITECTURES:
                means, lows, highs = [], [], []
                for variant in VARIANTS:
                    row = summary[(summary.variant_id == variant) & (summary.density == density) &
                                  (summary.architecture == architecture)]
                    selected_seeds = {int(s) for s in str(row.paired_seeds.iloc[0]).split(";") if s}
                    group = all_values[(all_values.variant_id == variant) & (all_values.density == density) &
                                       (all_values.architecture == architecture) &
                                       (all_values.seed.astype(int).isin(selected_seeds))]
                    ci = paired_t_summary(group[metric])
                    means.append(ci["mean"]); lows.append(ci["ci95_low"]); highs.append(ci["ci95_high"])
                yerr = np.array([[m - lo for m, lo in zip(means, lows)],
                                 [hi - m for m, hi in zip(means, highs)]])
                ax.errorbar(range(len(VARIANTS)), means, yerr=yerr, marker="o", capsize=3,
                            label=architecture)
            ax.set_title(f"{title} — density {density}")
            ax.set_xticks(range(len(VARIANTS)), labels, rotation=18, ha="right")
            ax.grid(alpha=.25)
            if r == 0 and c == 0:
                ax.legend()
    fig.suptitle("Scenario 5 sensitivity replication — mean per seed, 95% t intervals\n"
                 "density 20: n=6; density 100: n=4 complete paired seeds; no significance claim",
                 fontsize=12)
    fig.tight_layout(rect=(0, 0, 1, .92))
    name = "RESOURCE_SENSITIVITY_300dpi.png"
    fig.savefig(figure_dir / name, dpi=300, bbox_inches="tight")
    plt.close(fig)
    figures.append(f"figures/{name}")
    return figures


def _markdown_report(status, missing, summary, arch_summary, case_diffs, trace_count, output_bytes):
    lines = [
        "# تكرار تحليل الحساسية — نتائج وحدود التنفيذ", "",
        "## حالة الحملة", "",
        f"- الآثار المشتركة المُولّدة: **{trace_count}/12**.",
        f"- خلايا المعمارية المكتملة: **{status['completed_runs']}/120**؛ لا تُعامل الخلايا غير المنفذة كإخفاقات تجريبية.",
        f"- زمن التشغيل المسجل: **{status['active_elapsed_seconds']:.1f} ثانية** مقابل حد preregistration البالغ 3600 ثانية.",
        f"- تجاوز الحد: **{max(0.0, float(status['active_elapsed_seconds']) - 3600.0):.1f} ثانية** بسبب خلية بدأت قبل الحد وأكملت checkpoint بعدها؛ لم تبدأ خلية أخرى.",
        f"- حجم مجلد التنفيذ: **{output_bytes:,} بايت** مقابل حد 3,000,000,000 بايت.",
        f"- الخلايا الناقصة: **{len(missing)}**. لا توجد نتيجة تُنسب إليها.",
        "- وحدة التكرار الإحصائية هي seed. استخدمت المقارنات المزدوجة بذورًا مكتملة في baseline والنسخة المقابلة معًا.",
        "- استخدام المصدر الواحد (`position_offset.required_sources=1`) اختبار ضغط لسياسة أضعف، وليس توصية.", "",
        "## النتائج المزدوجة", "",
        "يعرض الجدول فروق المتوسطات على مستوى البذور بين كل إعداد وخط الأساس المطابق، مع فواصل t وصفية 95%. بسبب صغر n، لا تُفهم الفواصل أو اتجاهات البذور كاختبار دلالة أو تعميم واسع.", "",
        "| الكثافة | المعمارية | الإعداد | n | البذور | Δ Recall الحالة [95% CI] | Δ Recall فرص الهجوم [95% CI] | Δ FRR | Δ TP pooled | Δ FP pooled | Δ CPU (ث) | Δ P95 E2E (ms) | Δ رسائل/حالة |",
        "|---:|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary.to_dict("records"):
        if row["variant_id"] == "baseline":
            continue
        lines.append(
            f"| {row['density']} | {row['architecture']} | {row['variant_id']} | {row['seed_n']} | {row['paired_seeds']} | "
            f"{row['delta_malicious_revocation_recall_mean']:+.4f} [{row['delta_malicious_revocation_recall_ci95_low']:+.4f}, {row['delta_malicious_revocation_recall_ci95_high']:+.4f}] | "
            f"{row['delta_opportunity_detection_recall_mean']:+.4f} [{row['delta_opportunity_detection_recall_ci95_low']:+.4f}, {row['delta_opportunity_detection_recall_ci95_high']:+.4f}] | "
            f"{row['delta_false_revocation_rate_mean']:+.4f} | {row['variant_pooled_TP'] - row['baseline_paired_pooled_TP']:+d} | "
            f"{row['variant_pooled_FP'] - row['baseline_paired_pooled_FP']:+d} | {row['delta_cpu_time_seconds_mean']:+.3f} | "
            f"{row['delta_latency_p95_ms_mean']:+.3f} | {row['delta_messages_per_decision_mean']:+.3f} |"
        )
    lines.extend(["", "## اختلاف C100 وDistributed", "",
                  "الفروق التالية محسوبة على trace وseed نفسيهما. الفرق الإيجابي يعني Distributed − C100.",
                  "| الإعداد | الكثافة | المقياس | n | الفرق المتوسط | 95% CI |",
                  "|---|---:|---|---:|---:|---:|"])
    for row in arch_summary.to_dict("records"):
        if row["metric"] not in ("malicious_revocation_recall", "opportunity_detection_recall",
                                 "false_revocation_rate", "cpu_time_seconds", "latency_p95_ms",
                                 "messages_per_decision", "packet_delivery_ratio",
                                 "ledger_consistency_delay_p95_ms"):
            continue
        lines.append(f"| {row['variant_id']} | {row['density']} | {row['metric']} | {row['paired_seed_n']} | "
                     f"{row['distributed_minus_C100_mean']:+.4f} | [{row['ci95_low']:+.4f}, {row['ci95_high']:+.4f}] |")
    fp = case_diffs[case_diffs.new_false_positive == 1] if not case_diffs.empty else case_diffs
    lines.extend(["", f"- حالات FP جديدة مقارنة بخط الأساس في السجلات المزدوجة: **{len(fp)}**.",
                  "- `detected opportunity` تعني أن رسالة ضارة مرصودة وترتبط بنافذة حالتها النهائية REVOKED. `protected opportunity` تعني أن أول إلغاء ملتزم سبق زمن إرسال الرسالة؛ لا يُعامل الحقلان كشيء واحد.",
                  "- استُبعدت نوافذ ما بعد الإلغاء النهائي من Method B وفق `already_revoked_terminal_state`، وعُدّت واستُخرجت لكل خلية.", ""])
    if not fp.empty:
        lines.extend(["| النسخة | الكثافة | البذرة | المعمارية | case_id |",
                      "|---|---:|---:|---|---|"])
        for row in fp.to_dict("records"):
            lines.append(f"| {row['variant_id']} | {row['density']} | {row['seed']} | {row['architecture']} | `{row['case_id']}` |")
    return "\n".join(lines)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    raw, out = args.raw_dir.resolve(), args.output_dir.resolve()
    if not raw.is_dir():
        raise RuntimeError(f"Raw replication directory is missing: {raw}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "figures").mkdir(exist_ok=True)

    status, manifest, metrics, decisions, opportunities, traces_doc, context, configs, missing, trace_map, trace_cache = _verify_raw(raw)
    summary = paired_summary(metrics, opportunities)
    arch_summary = architecture_summary(metrics, opportunities)
    case_diffs = case_difference_table(metrics, decisions)
    architecture_case_diffs = architecture_case_difference_table(decisions)

    # Retain all executed cells, and explicitly mark every registered but unrun cell.
    actual = {_cell_key(row): row for row in manifest.to_dict("records")}
    full_manifest = []
    for key in expected_cell_keys():
        if key in actual:
            row = dict(actual[key])
            row["planned_status"] = "completed"
            row["not_run_reason"] = ""
        else:
            row = {"variant_id": key[0], "density": key[1], "seed": key[2],
                   "architecture": key[3], "status": "not_run_wall_cap",
                   "planned_status": "not_run_wall_cap", "case_count": 0,
                   "not_run_reason": "Wall-time cap reached before cell start"}
        full_manifest.append(row)
    pd.DataFrame(full_manifest).to_csv(out / "SENSITIVITY_RUN_MANIFEST.csv", index=False)
    metrics.to_csv(out / "SENSITIVITY_METRICS_BY_SEED.csv", index=False)
    decisions.to_csv(out / "SENSITIVITY_CASE_DECISIONS.csv", index=False)
    opportunities.to_csv(out / "SENSITIVITY_FIXED_OPPORTUNITIES.csv", index=False)
    summary.to_csv(out / "SENSITIVITY_AGGREGATED_RESULTS.csv", index=False)
    arch_summary.to_csv(out / "SENSITIVITY_ARCHITECTURE_PAIRED.csv", index=False)
    case_diffs.to_csv(out / "SENSITIVITY_CASE_DIFFERENCES.csv", index=False)
    architecture_case_diffs.to_csv(out / "SENSITIVITY_ARCHITECTURE_CASE_DIFFERENCES.csv", index=False)
    resolved_configs = {}
    for variant_id, record in configs.items():
        resolved = {}
        for architecture, backhaul in (("C100", 100.0), ("Distributed", 0.0)):
            cfg = copy.deepcopy(record["effective_config"])
            cfg["network"]["central_backhaul_extra_latency_ms"] = backhaul
            canonical = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
            resolved[architecture] = {
                "effective_config": cfg,
                "effective_config_sha256": hashlib.sha256(canonical).hexdigest(),
            }
        resolved_configs[variant_id] = {
            **record,
            "stress_test_only": variant_id == "position_sources_1",
            "effective_config_by_architecture": resolved,
        }
    (out / "SENSITIVITY_EFFECTIVE_CONFIGS.json").write_text(
        json.dumps(resolved_configs, indent=2), encoding="utf-8")
    (out / "SENSITIVITY_TRACE_MANIFEST.json").write_text(
        json.dumps(traces_doc, indent=2), encoding="utf-8")
    (out / "SENSITIVITY_RUN_CONTEXT.json").write_text(
        json.dumps(context, indent=2), encoding="utf-8")
    figures = make_figures(metrics, opportunities, summary, out)

    raw_bytes = sum(path.stat().st_size for path in raw.rglob("*") if path.is_file())
    aggregate = _markdown_report(status, missing, summary, arch_summary, case_diffs,
                                 len(traces_doc["traces"]), raw_bytes)
    (out / "SENSITIVITY_STATISTICAL_ANALYSIS.md").write_text(aggregate, encoding="utf-8")
    summary_doc = {
        "status": status,
        "actual_completed_runs": len(manifest), "planned_runs": len(expected_cell_keys()),
        "missing_cells": [list(key) for key in sorted(missing)],
        "failed_cells": [], "trace_count": len(traces_doc["traces"]),
        "figures": figures,
        "independent_method_b_recomputed_cells": len(metrics),
        "opportunity_metrics_recomputed_cells": len(opportunities),
        "fixed_opportunity_definition": "One unique emitted malicious V2X message identity; opportunity denominator is fixed within each density-seed trace.",
        "detected_opportunity_definition": "Observed malicious message mapped to a 15-second case with a committed REVOKED decision.",
        "protected_opportunity_definition": "First committed vehicle revocation finalized strictly before the message's actual emission/transmission time.",
        "statistical_unit": "seed-level paired difference",
        "confidence_interval": "two-sided 95% Student-t interval; descriptive only at n=4 or n=6",
        "resource_gates": {"runtime_seconds_registered": 3600,
                           "runtime_seconds_observed": status.get("active_elapsed_seconds"),
                           "raw_output_bytes_registered": 3000000000,
                           "raw_output_bytes_observed": raw_bytes},
    }
    (out / "SENSITIVITY_VALIDATION_SUMMARY.json").write_text(
        json.dumps(summary_doc, indent=2), encoding="utf-8")
    (out / "SENSITIVITY_OUTPUT_HASHES.json").write_text(json.dumps({
        path.relative_to(out).as_posix(): sha256(path)
        for path in sorted(out.rglob("*"))
        if path.is_file() and path.name not in {
            "SENSITIVITY_OUTPUT_HASHES.json", "SENSITIVITY_CLOSURE_HASHES.json",
            "SENSITIVITY_PILOT_VS_REPLICATION.csv", "SENSITIVITY_PILOT_VS_REPLICATION_300dpi.png",
        }
    }, indent=2), encoding="utf-8")
    print(json.dumps({"actual_cells": len(metrics), "planned_cells": len(expected_cell_keys()),
                      "missing_cells": len(missing), "method_b_recomputed": len(metrics),
                      "opportunities_recomputed": len(opportunities),
                      "paired_summary_rows": len(summary), "architecture_summary_rows": len(arch_summary),
                      "new_false_positive_rows": int(case_diffs.new_false_positive.sum()) if not case_diffs.empty else 0,
                      "output_directory": str(out)}, indent=2))


if __name__ == "__main__":
    main()
