"""Re-run B0 on the paired Scenario 5 traces and diagnose physical QE evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import xml.etree.ElementTree as ET

import matplotlib.pyplot as plt
from matplotlib.patches import Circle
import pandas as pd

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.domain import EvidenceCase
from vpuft.metrics import decision_metrics
from vpuft.qualification import VPUFTQualificationEngine
from vpuft.sumo.detector import RSU, geographic_cell
from vpuft.trace import build_trace_bundle, read_events_jsonl
from vpuft.weighting import case_evidence_masses, evidence_mass, evidence_weight


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "results/post_seminar_phase2/trace_manifest.csv"
DEFAULT_CONFIG = ROOT / "results/post_seminar_phase2/phase2_effective_baseline_config.json"
DEFAULT_OUTPUT = ROOT / "results/post_seminar_phase4/baseline_diagnostics"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def max_root_matching(reports_by_root: dict[str, list], attribute: str) -> dict[str, str]:
    """Diagnostic-only root/value matching; never changes the B0 decision."""
    value_to_root: dict[str, str] = {}

    def assign(root_id: str, visited: set[str]) -> bool:
        for value in sorted({str(getattr(report, attribute)) for report in reports_by_root[root_id]}):
            if value in visited:
                continue
            visited.add(value)
            current = value_to_root.get(value)
            if current is None or assign(current, visited):
                value_to_root[value] = root_id
                return True
        return False

    for root_id in sorted(reports_by_root):
        assign(root_id, set())
    return value_to_root


def qualified_evidence(case: EvidenceCase, now: float, config):
    policy = config.policies[case.attack_type.value]
    fresh = []
    for att in case.attestations:
        age = max(0.0, now - att.observed_at)
        if age <= policy.freshness_window_seconds:
            age_factor = max(0.0, 1.0 - age / max(policy.freshness_window_seconds, 1e-9))
            fresh.append(replace(att, freshness=min(att.freshness, age_factor)))
    _, _, roots = case_evidence_masses(fresh, config.weights)
    supporting_roots = [
        root for root in roots
        if root.direction.value == 1 and root.weight >= policy.min_representative_weight
    ]
    return policy, fresh, roots, supporting_roots


def evidence_record(att, *, stage: str, now: float, config, arrival=None) -> dict:
    policy = config.policies[att.attack_type.value]
    age = max(0.0, now - att.observed_at)
    weight = evidence_weight(att, config.weights)
    return {
        "stage": stage,
        "attestation_id": att.attestation_id,
        "case_id": att.case_id,
        "observation_root_id": att.observation_root_id,
        "source_id": att.source_id,
        "validator_rsu_id": att.validator_rsu_id,
        "geographic_cell": att.geographic_cell,
        "sensor_modality": att.sensor_modality,
        "direction": att.direction.name,
        "validity": att.validity,
        "observed_at": att.observed_at,
        "arrival_at": arrival,
        "age_at_qualification_seconds": age,
        "evidence_weight": weight,
        "fresh": int(age <= policy.freshness_window_seconds),
        "weight_eligible": int(weight >= policy.min_representative_weight),
    }


def run_cell(trace_row, config, output: Path) -> dict:
    density, seed = int(trace_row.vehicle_count), int(trace_row.seed)
    trace = Path(trace_row.trace_path)
    expected_hash = str(trace_row.sha256)
    actual_hash = sha256(trace)
    if actual_hash != expected_hash:
        raise ValueError(f"Trace hash mismatch for density={density} seed={seed}")
    cell_dir = output / f"density_{density}_seed_{seed}"
    cell_dir.mkdir(parents=True, exist_ok=True)
    if (cell_dir / "cell_complete.json").is_file():
        return json.loads((cell_dir / "summary.json").read_text(encoding="utf-8"))

    events = read_events_jsonl(trace)
    bundle = build_trace_bundle(
        events, KeyRegistry(config.security.deterministic_master_seed),
        window_seconds=config.detector.case_window_seconds,
        namespace=f"urban_roundabout-vehicles-{density}",
    )
    b0_config = replace(config, distributed_extension=replace(
        config.distributed_extension,
        coordinator_strategy="first_observer_then_hash",
        diversity_aware_root_assignment=False,
        provenance_safe_observer_diversity=False,
        cache_verified_evidence_bundle=False,
    ))
    architecture = DistributedRSUExtendedVPUFT(
        b0_config, KeyRegistry(config.security.deterministic_master_seed)
    )
    clean_cases = {case.case_id: architecture.sanitize_case(case) for case in bundle.rsu_cases}
    result = architecture.run(bundle.rsu_cases, seed)
    truth = {case.case_id: case.ground_truth_malicious for case in bundle.rsu_cases}
    opened = {case.case_id: case.opened_at for case in bundle.rsu_cases}
    metrics = decision_metrics(result, truth, opened)
    decisions = {decision.case_id: decision for decision in result.decisions}
    delivered_rows: dict[str, list[dict]] = {}
    delivered_ids: dict[str, set[str]] = {}
    for row in result.evidence_rows:
        delivered_rows.setdefault(row["case_id"], []).append(row)
        delivered_ids.setdefault(row["case_id"], set()).add(row["attestation_id"])

    b0_engine = VPUFTQualificationEngine(b0_config)
    b8_config = replace(b0_config, distributed_extension=replace(
        b0_config.distributed_extension, provenance_safe_observer_diversity=True
    ))
    b8_engine = VPUFTQualificationEngine(b8_config)
    cases = {case.case_id: case for case in bundle.rsu_cases}
    actual_fn_rows, assignment_rows = [], []
    delivered_by_case: dict[str, list] = {}
    for case_id, case in cases.items():
        clean = clean_cases[case_id]
        rows = delivered_rows.get(case_id, [])
        ids = delivered_ids.get(case_id, set())
        delivered_case = EvidenceCase(
            case.case_id, case.vehicle_id, case.pseudonym, case.attack_type,
            case.opened_at, case.ground_truth_malicious,
            [att for att in clean.attestations if att.attestation_id in ids],
        )
        delivered_by_case[case_id] = delivered_case.attestations
        decision = decisions[case_id]
        if decision.reason == "already_revoked_terminal_state":
            continue
        if not case.ground_truth_malicious or (decision.committed and decision.new_state.value == "revoked"):
            continue

        meta = dict(decision.metadata)
        now = float(meta["qualification_evaluated_at"])
        policy = b0_config.policies[case.attack_type.value]
        actual_qe = b0_engine.qualify(delivered_case, now)
        pretransport_qe = b0_engine.qualify(clean, now)
        b8_delivered = b8_engine.qualify(delivered_case, now)
        b8_pretransport = b8_engine.qualify(clean, now)
        policy, fresh, roots, support_roots = qualified_evidence(delivered_case, now, b0_config)
        fresh_by_id = {att.attestation_id: att for att in fresh}
        supporting_ids = {root.observation_root_id for root in support_roots}
        eligible_observer_reports: dict[str, list] = {}
        for att in fresh:
            if (
                att.observation_root_id in supporting_ids and att.direction.value == 1
                and att.validity == 1
                and evidence_weight(att, b0_config.weights) >= policy.min_representative_weight
            ):
                eligible_observer_reports.setdefault(att.observation_root_id, []).append(att)
        source_match = max_root_matching(eligible_observer_reports, "source_id")
        zone_match = max_root_matching(eligible_observer_reports, "geographic_cell")
        modality_match = max_root_matching(eligible_observer_reports, "sensor_modality")
        root_rows = []
        for root in roots:
            root_rows.append({
                "observation_root_id": root.observation_root_id,
                "net_direction": root.direction.name,
                "net_weight": root.weight,
                "support_weight": root.supporting_weight,
                "opposing_weight": root.opposing_weight,
                "representative_attestation_id": root.representative.attestation_id,
                "representative_source": root.representative.source_id,
                "representative_zone": root.representative.geographic_cell,
                "duplicate_count": root.duplicate_count,
            })
        observed_rsus = sorted({att.source_id for att in clean.attestations if att.source_kind == "rsu"})
        pre_supporting_root_ids = {
            root.observation_root_id for root in qualified_evidence(clean, now, b0_config)[3]
        }
        available_support = [
            att for att in clean.attestations
            if att.direction.value == 1 and att.validity == 1
            and att.observation_root_id in pre_supporting_root_ids
            and max(0.0, now - att.observed_at) <= policy.freshness_window_seconds
            and evidence_weight(att, b0_config.weights) >= policy.min_representative_weight
        ]
        available_by_root: dict[str, list] = {}
        for att in available_support:
            available_by_root.setdefault(att.observation_root_id, []).append(att)
        available_source_match = max_root_matching(available_by_root, "source_id")
        available_zone_match = max_root_matching(available_by_root, "geographic_cell")
        pre_representative_sources = {
            root.representative.source_id
            for root in qualified_evidence(clean, now, b0_config)[3]
        }
        pre_representative_zones = {
            root.representative.geographic_cell
            for root in qualified_evidence(clean, now, b0_config)[3]
        }
        failed = set(actual_qe.failed_constraints)
        root_fail = actual_qe.independent_roots < policy.required_roots
        source_fail = actual_qe.distinct_sources < policy.required_sources
        zone_fail = actual_qe.distinct_zones < policy.required_zones
        modality_fail = actual_qe.distinct_modalities < policy.required_modalities
        margin_fail = actual_qe.decision_margin < policy.margin_threshold
        all_before_q = bool(pretransport_qe.qualified)
        b8_processing_recovery = bool(b8_delivered.qualified)
        b8_ideal_transport_recovery = bool(b8_pretransport.qualified)
        physical_requirements_fail = (
            b8_pretransport.independent_roots < policy.required_roots
            or b8_pretransport.distinct_sources < policy.required_sources
            or b8_pretransport.distinct_zones < policy.required_zones
            or b8_pretransport.distinct_modalities < policy.required_modalities
        )
        same_cell_sources = any(
            len({att.source_id for root in pre_supporting_root_ids for att in clean.attestations
                 if att.observation_root_id == root and att.geographic_cell == zone
                 and att.direction.value == 1 and att.validity == 1}) >= policy.required_sources
            for zone in {att.geographic_cell for att in clean.attestations if att.direction.value == 1}
        )
        records = [
            *[evidence_record(att, stage="available_before_transport", now=now, config=b0_config)
              for att in clean.attestations],
            *[evidence_record(att, stage="delivered", now=now, config=b0_config,
                             arrival=next((r.get("evidence_arrived_at") for r in rows
                                            if r["attestation_id"] == att.attestation_id), None))
              for att in delivered_case.attestations],
            *[evidence_record(att, stage="fresh_valid_used_by_qe", now=now, config=b0_config)
              for att in fresh if att.validity == 1],
        ]
        for row in records:
            row.update({"density": density, "seed": seed, "vehicle_id": case.vehicle_id,
                        "runtime_attack_type": case.attack_type.value})
            assignment_rows.append(row)

        actual_fn_rows.append({
            "density": density, "seed": seed, "case_id": case.case_id,
            "vehicle_id": case.vehicle_id, "opened_at": case.opened_at,
            "runtime_attack_type": case.attack_type.value,
            "ground_truth_attack_type": next((str(e.payload.get("ground_truth_case_attack_type"))
                for e in bundle.events if e.case_id == case_id), "unknown"),
            "independent_roots": actual_qe.independent_roots,
            "required_roots": policy.required_roots,
            "distinct_sources": actual_qe.distinct_sources,
            "required_sources": policy.required_sources,
            "distinct_zones": actual_qe.distinct_zones,
            "required_zones": policy.required_zones,
            "distinct_modalities": actual_qe.distinct_modalities,
            "required_modalities": policy.required_modalities,
            "failed_constraints": "|".join(actual_qe.failed_constraints),
            "supporting_strength": actual_qe.supporting_strength,
            "opposing_strength": actual_qe.opposing_strength,
            "supporting_mass": evidence_mass(root.weight for root in roots if root.direction.value == 1),
            "opposing_mass": evidence_mass(root.weight for root in roots if root.direction.value == -1),
            "qualification_margin": actual_qe.decision_margin,
            "required_margin": policy.margin_threshold,
            "qualification_time": now,
            "available_before_transport": len(clean.attestations),
            "raw_detection_reports_in_trace_case": len(case.attestations),
            "delivered": len(delivered_case.attestations),
            "not_delivered": len(clean.attestations) - len(delivered_case.attestations),
            "fresh_delivered": len(fresh),
            "fresh_valid_delivered": sum(att.validity == 1 for att in fresh),
            "used_supporting_roots": len(support_roots),
            "pretransport_b0_qualified": int(all_before_q),
            "pretransport_b0_failed_constraints": "|".join(pretransport_qe.failed_constraints),
            "b8_observer_match_delivered_qualified_diagnostic_only": int(b8_processing_recovery),
            "b8_observer_match_pretransport_qualified_diagnostic_only": int(b8_ideal_transport_recovery),
            "observer_match_sources_available": len(available_source_match),
            "observer_match_zones_available": len(available_zone_match),
            "observer_match_modalities_available": len(modality_match),
            "pre_b0_representative_sources": len(pre_representative_sources),
            "pre_b0_representative_zones": len(pre_representative_zones),
            "pre_supporting_roots": len(pre_supporting_root_ids),
            "pre_distinct_supporting_sources_matching": len(available_source_match),
            "pre_distinct_supporting_zones_matching": len(available_zone_match),
            "pre_b8_roots": b8_pretransport.independent_roots,
            "pre_b8_sources": b8_pretransport.distinct_sources,
            "pre_b8_zones": b8_pretransport.distinct_zones,
            "pre_b8_modalities": b8_pretransport.distinct_modalities,
            "source_sufficient_zone_failed": int(
                actual_qe.independent_roots >= policy.required_roots
                and actual_qe.distinct_sources >= policy.required_sources and zone_fail
            ),
            "source_and_zone_same_cell": int(
                actual_qe.distinct_sources >= policy.required_sources
                and actual_qe.distinct_zones < policy.required_zones
                and same_cell_sources
            ),
            "diversity_satisfied_margin_failed": int(
                not root_fail and not source_fail and not zone_fail and not modality_fail and margin_fail
            ),
            "all_pretransport_requirements_but_margin_satisfied": int(
                pretransport_qe.independent_roots >= policy.required_roots
                and pretransport_qe.distinct_sources >= policy.required_sources
                and pretransport_qe.distinct_zones >= policy.required_zones
                and pretransport_qe.distinct_modalities >= policy.required_modalities
                and pretransport_qe.decision_margin < policy.margin_threshold
            ),
            "physical_policy_shortfall_even_with_all_current_reports": int(
                not b8_pretransport.qualified and physical_requirements_fail
            ),
            "observing_rsus": "|".join(observed_rsus),
            "observed_zones": "|".join(sorted({att.geographic_cell for att in clean.attestations})),
            "root_contributions_json": json.dumps(root_rows, sort_keys=True),
            "root_to_rsu_zones_json": json.dumps({
                root: sorted({(att.source_id, att.geographic_cell, att.direction.name)
                              for att in clean.attestations if att.observation_root_id == root})
                for root in sorted({att.observation_root_id for att in clean.attestations})
            }, sort_keys=True),
            "failed_root_constraint": int(root_fail),
            "failed_source_constraint": int(source_fail),
            "failed_zone_constraint": int(zone_fail),
            "failed_modality_constraint": int(modality_fail),
            "failed_margin_constraint": int(margin_fail),
        })

    # Temporal accumulation diagnostic is strictly causal: only evidence delivered
    # in earlier fixed windows for this vehicle and inferred attack type is eligible.
    fn_index = {(r["case_id"]): r for r in actual_fn_rows}
    ordered = sorted(cases.values(), key=lambda c: (c.opened_at, c.case_id))
    prior: dict[tuple[str, str], list] = {}
    for case in ordered:
        decision = decisions[case.case_id]
        if case.case_id in fn_index:
            row = fn_index[case.case_id]
            now = float(decision.metadata["qualification_evaluated_at"])
            policy = b0_config.policies[case.attack_type.value]
            prior_rows = prior.get((case.vehicle_id, case.attack_type.value), [])
            within_age = [att for att, _prev_opened in prior_rows
                          if 0 <= now - att.observed_at <= policy.freshness_window_seconds]
            accumulation = EvidenceCase(
                case.case_id, case.vehicle_id, case.pseudonym, case.attack_type,
                case.opened_at, case.ground_truth_malicious,
                [*delivered_by_case[case.case_id], *within_age],
            )
            temporal = b0_engine.qualify(accumulation, now)
            row["prior_window_fresh_delivered_reports"] = len(within_age)
            row["temporal_b0_qualified_diagnostic_only"] = int(temporal.qualified)
            row["temporal_b0_failed_constraints"] = "|".join(temporal.failed_constraints)
            row["temporal_supporting_roots"] = temporal.independent_roots
            row["temporal_distinct_sources"] = temporal.distinct_sources
            row["temporal_distinct_zones"] = temporal.distinct_zones
            row["temporal_margin"] = temporal.decision_margin
        key = (case.vehicle_id, case.attack_type.value)
        prior.setdefault(key, []).extend((att, case.opened_at) for att in delivered_by_case[case.case_id])

    fn_frame = pd.DataFrame(actual_fn_rows)
    evidence_frame = pd.DataFrame(assignment_rows)
    fn_frame.to_csv(cell_dir / "fn_cases.csv", index=False)
    evidence_frame.to_csv(cell_dir / "fn_evidence_assignments.csv.gz", index=False, compression="gzip")
    pd.DataFrame([{
        "density": density, "seed": seed, **metrics,
        "trace_sha256": actual_hash,
        "trace_count_match_to_frozen": int(trace_row.count_match_to_frozen),
        "trace_bytes": trace.stat().st_size,
        "diagnosed_at_risk_malicious_fns": len(fn_frame),
    }]).to_csv(cell_dir / "metrics.csv", index=False)
    summary = {
        "density": density, "seed": seed, "trace_sha256": actual_hash,
        "trace_count_match_to_frozen": int(trace_row.count_match_to_frozen),
        "trace_bytes": trace.stat().st_size, "cases": len(bundle.rsu_cases),
        "TP": int(metrics["TP"]), "FP": int(metrics["FP"]),
        "TN": int(metrics["TN"]), "FN": int(metrics["FN"]),
        "excluded_post_revocation_cases": int(metrics["excluded_post_revocation_cases"]),
        "diagnosed_at_risk_malicious_fns": len(fn_frame),
    }
    (cell_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (cell_dir / "cell_complete.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"diagnosed density={density} seed={seed} FN={len(fn_frame)}", flush=True)
    return summary


def make_coverage_map(trace_path: Path, scenario: Path, output_path: Path, fn_rows: pd.DataFrame) -> None:
    mobility = pd.read_csv(trace_path.parent / "mobility_trace.csv")
    messages = pd.read_csv(trace_path.parent / "generated_messages.csv")
    net = next(Path("results/post_seminar_phase2/baseline_regenerated/generated_scenarios/urban_roundabout")
               .glob("vehicles_100/urban_roundabout.net.xml"))
    location = ET.parse(net).getroot().find("location")
    offset_x, offset_y = map(float, location.attrib["netOffset"].split(","))
    mobility["x_local"] = mobility.x - offset_x
    mobility["y_local"] = mobility.y - offset_y
    rsu_data = json.loads((scenario / "rsus.json").read_text(encoding="utf-8"))
    rsus = [RSU(item["id"], float(item["x"]), float(item["y"]), item["domain"], float(item["reliability"]))
            for item in rsu_data]
    fig, ax = plt.subplots(figsize=(10, 9))
    # Draw the actual road edges and roundabout before trajectories.
    nodes_root = ET.parse(scenario / "urban_roundabout.nod.xml").getroot()
    nodes = {n.attrib["id"]: (float(n.attrib["x"]), float(n.attrib["y"])) for n in nodes_root.findall("node")}
    edges_root = ET.parse(scenario / "urban_roundabout.edg.xml").getroot()
    for edge in edges_root.findall("edge"):
        if "shape" in edge.attrib:
            coords = [tuple(map(float, p.split(","))) for p in edge.attrib["shape"].split()]
        else:
            coords = [nodes[edge.attrib["from"]], nodes[edge.attrib["to"]]]
        ax.plot([p[0] for p in coords], [p[1] for p in coords], color="#cbd5e1", linewidth=2, zorder=1)
    for _, group in mobility.groupby("vehicle_id"):
        group = group.sort_values("simulation_time")
        ax.plot(group.x_local, group.y_local, color="#94a3b8", alpha=0.12, linewidth=0.55, zorder=2)
    min_x, max_x = mobility.x_local.min(), mobility.x_local.max()
    min_y, max_y = mobility.y_local.min(), mobility.y_local.max()
    grid_x = range(int((min_x + offset_x) // 250) * 250 - int(offset_x),
                   int((max_x + offset_x) // 250 + 2) * 250 - int(offset_x), 250)
    grid_y = range(int((min_y + offset_y) // 250) * 250 - int(offset_y),
                   int((max_y + offset_y) // 250 + 2) * 250 - int(offset_y), 250)
    for x in grid_x:
        ax.axvline(x, color="#64748b", linestyle="--", linewidth=0.7, alpha=0.55, zorder=0)
    for y in grid_y:
        ax.axhline(y, color="#64748b", linestyle="--", linewidth=0.7, alpha=0.55, zorder=0)
    for rsu in rsus:
        ax.add_patch(Circle((rsu.x, rsu.y), 450, fill=False, linestyle=":", linewidth=0.8,
                            color="#2563eb", alpha=0.35, zorder=3))
        ax.scatter([rsu.x], [rsu.y], marker="^", s=90, color="#1d4ed8", zorder=5)
        ax.annotate(f"{rsu.rsu_id}\n{geographic_cell(rsu.x + offset_x, rsu.y + offset_y)}",
                    (rsu.x, rsu.y), xytext=(5, 6), textcoords="offset points", fontsize=8)
    # Mark up to 30 representative FN vehicle positions at the window midpoint.
    selection = fn_rows.loc[fn_rows.seed.eq(1001) & fn_rows.density.eq(100)].head(30)
    for _, fn in selection.iterrows():
        target = mobility.loc[mobility.vehicle_id.eq(fn.vehicle_id)]
        if target.empty:
            continue
        target = target.iloc[(target.simulation_time - (fn.opened_at + 7.5)).abs().argmin()]
        ax.scatter([target.x_local], [target.y_local], marker="x", s=45, color="#dc2626", zorder=6)
    ax.set_xlim(min_x - 60, max_x + 60)
    ax.set_ylim(min_y - 60, max_y + 60)
    ax.set_aspect("equal", adjustable="box")
    ax.set_xlabel("Scenario x (m), SUMO netOffset removed")
    ax.set_ylabel("Scenario y (m), SUMO netOffset removed")
    ax.set_title("Scenario 5: six RSUs, 250 m geographic cells, mobility and sample FN windows\n"
                 "Density 100, seed 1001; circles indicate 450 m configured RSU range")
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def aggregate(output: Path, manifest: pd.DataFrame) -> None:
    summaries = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(output.glob("density_*/summary.json"))]
    pd.DataFrame(summaries).to_csv(output / "baseline_metrics_by_cell.csv", index=False)
    fn_files = sorted(output.glob("density_*/fn_cases.csv"))
    evidence_files = sorted(output.glob("density_*/fn_evidence_assignments.csv.gz"))
    fn = pd.concat([pd.read_csv(p) for p in fn_files], ignore_index=True) if fn_files else pd.DataFrame()
    evidence = pd.concat([pd.read_csv(p) for p in evidence_files], ignore_index=True) if evidence_files else pd.DataFrame()
    fn.to_csv(output / "fn_cases_all_50.csv", index=False)
    evidence.to_csv(output / "fn_evidence_assignments_all_50.csv.gz", index=False, compression="gzip")
    if not fn.empty:
        failed_names = ["independent_roots", "sources", "zones", "modalities", "margin"]
        overlap_rows = []
        for density, group in fn.groupby("density"):
            for name in failed_names:
                col = "failed_" + ("root_constraint" if name == "independent_roots" else
                    "source_constraint" if name == "sources" else "zone_constraint" if name == "zones" else
                    "modality_constraint" if name == "modalities" else "margin_constraint")
                overlap_rows.append({"density": density, "attack_type": "ALL", "constraint": name,
                                     "fn_cases": int(group[col].sum())})
            for attack, subset in group.groupby("runtime_attack_type"):
                for name in failed_names:
                    col = "failed_" + ("root_constraint" if name == "independent_roots" else
                        "source_constraint" if name == "sources" else "zone_constraint" if name == "zones" else
                        "modality_constraint" if name == "modalities" else "margin_constraint")
                    overlap_rows.append({"density": density, "attack_type": attack, "constraint": name,
                                         "fn_cases": int(subset[col].sum())})
        pd.DataFrame(overlap_rows).to_csv(output / "fn_constraint_counts_by_density_attack.csv", index=False)
        # Exact failed-constraint intersection patterns, plus all pairwise intersections.
        fn["failed_constraint_pattern"] = fn.failed_constraints.fillna("").replace("", "none")
        fn.groupby(["density", "runtime_attack_type", "failed_constraint_pattern"], dropna=False).size() \
            .rename("fn_cases").reset_index().to_csv(output / "fn_constraint_overlap_patterns.csv", index=False)
        constraints = {
            "roots": "failed_root_constraint", "sources": "failed_source_constraint",
            "zones": "failed_zone_constraint", "modalities": "failed_modality_constraint",
            "margin": "failed_margin_constraint",
        }
        pair_rows = []
        for density, group in fn.groupby("density"):
            for left, lcol in constraints.items():
                for right, rcol in constraints.items():
                    if left <= right:
                        pair_rows.append({"density": density, "constraint_a": left, "constraint_b": right,
                                          "overlap_fn_cases": int((group[lcol].astype(bool) & group[rcol].astype(bool)).sum())})
        pd.DataFrame(pair_rows).to_csv(output / "fn_constraint_overlap_matrix.csv", index=False)
        fn.groupby(["density", "runtime_attack_type"], dropna=False).agg(
            at_risk_fn_cases=("case_id", "count"),
            b0_pretransport_qualifies=("pretransport_b0_qualified", "sum"),
            b8_delivered_diagnostic_qualifies=("b8_observer_match_delivered_qualified_diagnostic_only", "sum"),
            b8_ideal_transport_diagnostic_qualifies=("b8_observer_match_pretransport_qualified_diagnostic_only", "sum"),
            temporal_diagnostic_qualifies=("temporal_b0_qualified_diagnostic_only", "sum"),
            same_source_zone_shortfall=("source_sufficient_zone_failed", "sum"),
            physical_policy_shortfall=("physical_policy_shortfall_even_with_all_current_reports", "sum"),
            margin_only_after_diversity=("diversity_satisfied_margin_failed", "sum"),
        ).reset_index().to_csv(output / "fn_recoverability_by_density_attack.csv", index=False)
        fn.groupby(["density", "runtime_attack_type", "distinct_sources", "distinct_zones"], dropna=False) \
            .size().rename("fn_cases").reset_index().to_csv(output / "fn_source_zone_overlap_table.csv", index=False)
        if not fn.empty:
            seed1001 = fn.loc[fn.density.eq(100) & fn.seed.eq(1001)]
            trace = manifest.loc[manifest.density.eq(100) & manifest.seed.eq(1001)].iloc[0]
            scenario = ROOT / "sumo/urban_roundabout"
            make_coverage_map(Path(trace.trace_path), scenario, output / "scenario5_coverage_fn_map.png", fn)
    manifest.to_csv(output / "trace_manifest_verified.csv", index=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = pd.read_csv(args.manifest)
    manifest = manifest.rename(columns={"density": "vehicle_count"})
    if len(manifest) != 50 or manifest[["vehicle_count", "seed"]].drop_duplicates().shape[0] != 50:
        raise ValueError(f"Expected exactly 50 unique density/seed traces, found {len(manifest)}")
    config = load_config(args.config)
    if config.distributed_extension.provenance_safe_observer_diversity:
        raise ValueError("B0 diagnostic config unexpectedly enables provenance-safe diversity")
    if config.distributed_extension.diversity_aware_root_assignment:
        raise ValueError("B0 diagnostic config unexpectedly enables B1 root reassignment")
    verified = []
    for row in manifest.itertuples(index=False):
        path = Path(row.trace_path)
        digest = sha256(path)
        if digest != str(row.sha256):
            raise ValueError(f"Hash mismatch: {path}")
        verified.append({"density": int(row.vehicle_count), "seed": int(row.seed),
                         "trace_path": str(path), "sha256": digest, "bytes": path.stat().st_size,
                         "count_match_to_frozen": int(row.count_match_to_frozen)})
    verified_manifest = pd.DataFrame(verified)
    verified_manifest.to_csv(args.output / "trace_manifest_verified.csv", index=False)
    summaries = []
    for row in manifest.sort_values(["vehicle_count", "seed"]).itertuples(index=False):
        summaries.append(run_cell(row, config, args.output))
    aggregate(args.output, verified_manifest)
    print(f"completed baseline diagnostic cells={len(summaries)} fn={sum(x['diagnosed_at_risk_malicious_fns'] for x in summaries)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
