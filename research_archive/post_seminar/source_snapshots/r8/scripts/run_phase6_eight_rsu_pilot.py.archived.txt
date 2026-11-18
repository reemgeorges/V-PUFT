"""Run the preregistered paired C1 (6 RSUs) vs C3 (8 sensors) pilot."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.sumo.runner import run_sumo_trace
from vpuft.trace import build_trace_bundle, read_events_jsonl
from run_phase2_ablation import decision_frame, measured_run, metric_row

from run_phase6_eight_rsu_placement import (
    DENSITIES, FROZEN, HELDOUT_SEEDS, OUT, WITNESS_POOL, digest, write_rsu_files,
)


def prepare_scenario(density: int, placement: str, rsus: list[dict]) -> Path:
    target = OUT / "scenarios" / placement / f"vehicles_{density}"
    source = FROZEN / "results/post_seminar_phase2/baseline_regenerated/generated_scenarios/urban_roundabout" / f"vehicles_{density}"
    expected = json.dumps(rsus, sort_keys=True)
    if target.exists():
        current = json.loads((target / "rsus.json").read_text(encoding="utf-8"))
        if json.dumps(current, sort_keys=True) != expected:
            raise RuntimeError(f"Scenario already exists with a different frozen placement: {target}")
    else:
        shutil.copytree(source, target)
        write_rsu_files(target, rsus)
    return target


def complete_trace(config, scenario: Path, density: int, seed: int, layout: str) -> Path:
    output = OUT / "pilot" / layout / f"vehicles_{density}" / f"seed_{seed}"
    marker = output / "run_summary.json"
    if marker.is_file():
        manifest = json.loads((output / "scenario_manifest.json").read_text())
        if manifest.get("witness_rsu_ids") != list(WITNESS_POOL):
            raise RuntimeError(f"Completed trace has unexpected witness routing: {output}")
        return output
    if output.exists() and any(output.iterdir()):
        # Interrupted outputs remain immutable. Resume in a new attempt folder.
        parent = output.parent
        attempts = sorted(parent.glob(f"seed_{seed}_retry*"))
        for attempt in attempts:
            retry_marker = attempt / "run_summary.json"
            if retry_marker.is_file():
                retry_manifest = json.loads((attempt / "scenario_manifest.json").read_text())
                if retry_manifest.get("witness_rsu_ids") != list(WITNESS_POOL):
                    raise RuntimeError(f"Retry trace has unexpected witness routing: {attempt}")
                return attempt
        number = 1
        while (parent / f"seed_{seed}_retry{number}").exists():
            number += 1
        output = parent / f"seed_{seed}_retry{number}"
    manifest = run_sumo_trace(
        config, scenario_directory=scenario, output_directory=output, seed=seed,
        witness_rsu_ids=WITNESS_POOL,
    )
    if manifest["witness_rsu_ids"] != list(WITNESS_POOL):
        raise AssertionError("Witness routing pool changed during a pilot trace")
    return output


def hash_pair(c1: Path, c3: Path, scenario_c1: Path, scenario_c3: Path, density: int, seed: int) -> dict:
    files = ("mobility_trace.csv", "generated_messages.csv", "attack_ground_truth.csv")
    hashes = {}
    for name in files:
        a, b = digest(c1 / name), digest(c3 / name)
        if a != b:
            raise AssertionError(f"Paired {name} differs density={density} seed={seed}: {a} vs {b}")
        hashes[name] = a
    for name in ("urban_roundabout.rou.xml", "attacks.json"):
        if digest(scenario_c1 / name) != digest(scenario_c3 / name):
            raise AssertionError(f"Paired scenario input {name} differs density={density}")
    return {"density": density, "seed": seed, "paired_hashes": hashes,
            "attack_schedule_sha256": digest(scenario_c1 / "attacks.json"),
            "C1_rsu_config_sha256": digest(scenario_c1 / "rsus.json"),
            "C3_rsu_config_sha256": digest(scenario_c3 / "rsus.json"),
            "mobility_identical": True, "emitted_messages_identical": True,
            "ground_truth_identical": True, "witness_routing_pool": list(WITNESS_POOL)}


def preserve_csv(frame: pd.DataFrame, path: Path) -> None:
    """Write a new result or verify a previously completed result byte-for-byte."""
    rendered = frame.to_csv(index=False)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            previous = pd.read_csv(path)
            rerendered = pd.read_csv(io.StringIO(rendered))
            if previous.equals(rerendered):
                return
            relative = path.relative_to(OUT)
            replay_root = OUT / "replay_diagnostics"
            replay = replay_root / relative
            replay_index = 1
            while replay.exists() and replay.read_text(encoding="utf-8") != rendered:
                replay_index += 1
                replay = replay_root / f"replay_{replay_index:02d}" / relative
            replay.parent.mkdir(parents=True, exist_ok=True)
            if not replay.exists():
                replay.write_text(rendered, encoding="utf-8", newline="")
            raise RuntimeError(f"Stored a different replay without touching the completed result: {path}; replay={replay}")
        return
    path.write_text(rendered, encoding="utf-8", newline="")


def rsu_observed_message_ids(trace_path: Path) -> set[str]:
    observed = set()
    with trace_path.open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("source_kind") == "rsu":
                observed.add(str(event["message_id"]))
    return observed


def attack_message_coverage(detections: pd.DataFrame, malicious_ids: set[str]) -> dict:
    rsu = detections[(detections.source_kind == "rsu") & detections.message_id.astype(str).isin(malicious_ids)]
    by_message = rsu.groupby("message_id").agg(
        sources=("detected_by", "nunique"), cells=("geographic_cell", "nunique"),
    )
    return {
        "malicious_messages_observed": int(by_message.shape[0]),
        "multi_observer_malicious_messages": int((by_message.sources >= 2).sum()),
        "multi_cell_malicious_messages": int((by_message.cells >= 2).sum()),
        "malicious_messages_with_two_source_two_cell_reports": int(((by_message.sources >= 2) & (by_message.cells >= 2)).sum()),
    }


def opportunity_rows(messages: pd.DataFrame, decisions: pd.DataFrame, trace_path: Path) -> pd.DataFrame:
    from vpuft.opportunity_evaluation import opportunity_frame
    return opportunity_frame(messages, decisions, rsu_observed_message_ids(trace_path), window_seconds=15.0)


def fixed_opportunity_summary(frame: pd.DataFrame) -> dict:
    total = len(frame)
    detected = int(frame.detected_opportunity.sum())
    terminal = int(frame.terminal_after_revocation.sum())
    return {
        "attack_opportunities": total,
        "observed_attack_opportunities": int(frame.observed_opportunity.sum()),
        "unobserved_attack_opportunities": int((~frame.observed_opportunity).sum()),
        "successfully_detected_opportunities": detected,
        "opportunity_detection_recall_fixed_denominator": detected / total if total else 0.0,
        "protected_opportunities_including_terminal": detected + terminal,
        "protected_opportunity_fraction_fixed_denominator": (detected + terminal) / total if total else 0.0,
        "terminal_opportunities": terminal,
    }


def main() -> None:
    prereg = json.loads((OUT / "placement_preregistered.json").read_text(encoding="utf-8"))
    gate = json.loads((OUT / "acceptance_gate_preregistered.json").read_text(encoding="utf-8"))
    if tuple(prereg["heldout_seeds"]) != HELDOUT_SEEDS or not gate.get("frozen_before_heldout_results"):
        raise AssertionError("Held-out seeds or acceptance gate do not match preregistration")
    config_path = FROZEN / "results/post_seminar_phase2/phase2_effective_baseline_config.json"
    base_config = load_config(config_path)
    if tuple(base_config.pbft.validators) != WITNESS_POOL[:4]:
        raise AssertionError("Four PBFT validators changed")
    c1_rsus, c3_rsus = prereg["baseline_rsus"], prereg["candidate_rsus"]
    if c3_rsus[:6] != c1_rsus or [r["id"] for r in c3_rsus[6:]] != ["rsu-7", "rsu-8"]:
        raise AssertionError("C3 must retain all six C1 RSUs and add only rsu-7/8")
    if any(r["reliability"] != 0.900 or r["domain"] != "domain-3" for r in c3_rsus[6:]):
        raise AssertionError("New RSUs must use the preregistered conservative reliability/domain")
    c1_config = replace(base_config, simulation=replace(base_config.simulation, rsu_count=6))
    c3_ext = replace(base_config.distributed_extension, sensing_only_rsu_ids=("rsu-7", "rsu-8"))
    c3_config = replace(base_config, simulation=replace(base_config.simulation, rsu_count=8),
                        distributed_extension=c3_ext)
    paired_hashes, metrics, decisions_by_layout, opportunity_records = [], [], {"C1": [], "C3": []}, []
    for density in DENSITIES:
        scenario_c1 = prepare_scenario(density, "C1", c1_rsus)
        scenario_c3 = prepare_scenario(density, "C3", c3_rsus)
        for seed in HELDOUT_SEEDS:
            trace_c1 = complete_trace(c1_config, scenario_c1, density, seed, "C1")
            trace_c3 = complete_trace(c3_config, scenario_c3, density, seed, "C3")
            paired_hashes.append(hash_pair(trace_c1, trace_c3, scenario_c1, scenario_c3, density, seed))
            metric_for_cell = {}
            opp_for_cell = {}
            for layout, config, trace in (("C1", c1_config, trace_c1), ("C3", c3_config, trace_c3)):
                events = read_events_jsonl(trace / "shared_detection_trace.jsonl")
                bundle = build_trace_bundle(events, KeyRegistry(config.security.deterministic_master_seed),
                                            window_seconds=15.0,
                                            namespace=f"urban_roundabout-vehicles-{density}")
                cases = bundle.rsu_cases
                if not cases:
                    raise RuntimeError(f"No RSU evidence cases in {layout}, density={density}, seed={seed}")
                ext = replace(config.distributed_extension,
                              coordinator_strategy="first_observer_then_hash",
                              cache_verified_evidence_bundle=False,
                              diversity_aware_root_assignment=False,
                              sensing_only_rsu_ids=("rsu-7", "rsu-8") if layout == "C3" else ())
                run_config = replace(config, distributed_extension=ext)
                result, cpu, wall, peak = measured_run(run_config, cases, seed)
                frame = decision_frame(result, cases, density=density, seed=seed, variant=f"{layout}_B0")
                preserve_csv(frame, trace / f"{layout}_B0_decisions.csv")
                decisions_by_layout[layout].append(frame)
                m = metric_row(result, cases, frame, density=density, seed=seed, variant=f"{layout}_B0",
                               cpu=cpu, wall=wall, peak=peak, acquisition={})
                m.update({"case_count": len(cases), "run_cpu_process_seconds": cpu,
                          "run_wall_seconds": wall, "cpu_per_case_ms": 1000 * cpu / max(1, len(cases))})
                metric_for_cell[layout] = m
                messages = pd.read_csv(trace / "generated_messages.csv")
                opp = opportunity_rows(messages, frame, trace / "shared_detection_trace.jsonl")
                preserve_csv(opp, trace / f"{layout}_opportunities.csv")
                opp_for_cell[layout] = opp
                det = pd.read_csv(trace / "local_detections.csv")
                truth = messages.ground_truth_malicious.astype(str).str.lower().isin(("true", "1"))
                malicious_ids = set(messages.loc[truth, "message_id"].astype(str))
                m.update(attack_message_coverage(det, malicious_ids))
                m.update(fixed_opportunity_summary(opp))
                diagnostics = []
                for decision in result.decisions:
                    meta = dict(decision.metadata)
                    case = next((c for c in cases if c.case_id == decision.case_id), None)
                    if case is None:
                        continue
                    diagnostics.append({"case_id": case.case_id, "vehicle_id": case.vehicle_id,
                                        "ground_truth_malicious": int(case.ground_truth_malicious),
                                        "independent_roots": meta.get("independent_roots", 0),
                                        "distinct_sources": meta.get("distinct_sources", 0),
                                        "distinct_zones": meta.get("distinct_zones", 0),
                                        "qualification_outcome": int(bool(meta.get("qualification_outcome", False))),
                                        "failed_constraints": "|".join(meta.get("failed_constraints", []))})
                diagnostic_frame = pd.DataFrame(diagnostics)
                preserve_csv(diagnostic_frame, trace / f"{layout}_qualification_diagnostics.csv")
                malicious_diag = diagnostic_frame[diagnostic_frame.ground_truth_malicious.eq(1)]
                m["malicious_cases_with_two_independent_roots"] = int((malicious_diag.independent_roots >= 2).sum())
                m["malicious_cases_with_two_supporting_sources"] = int((malicious_diag.distinct_sources >= 2).sum())
                m["malicious_cases_with_two_supporting_zones"] = int((malicious_diag.distinct_zones >= 2).sum())
            c1_opp, c3_opp = opp_for_cell["C1"], opp_for_cell["C3"]
            ids1, ids3 = set(c1_opp.opportunity_id), set(c3_opp.opportunity_id)
            if ids1 != ids3:
                raise AssertionError(f"Paired attack opportunity universe differs density={density} seed={seed}")
            joined = c1_opp[["opportunity_id", "detected_opportunity", "terminal_after_revocation"]].merge(
                c3_opp[["opportunity_id", "detected_opportunity", "terminal_after_revocation"]],
                on="opportunity_id", suffixes=("_C1", "_C3"), validate="one_to_one")
            recovered = joined[(~joined.detected_opportunity_C1) & joined.detected_opportunity_C3]
            record = {"density": density, "seed": seed,
                      "common_attack_opportunities": len(ids1),
                      "C1_only_protected_ids": "|".join(sorted(joined.loc[joined.detected_opportunity_C1 & ~joined.detected_opportunity_C3, "opportunity_id"])),
                      "C3_recovered_opportunity_ids": "|".join(sorted(recovered.opportunity_id)),
                      "recovered_opportunity_count": len(recovered)}
            for layout in ("C1", "C3"):
                record.update({f"{layout}_{key}": value for key, value in fixed_opportunity_summary(opp_for_cell[layout]).items()})
            opportunity_records.append(record)
            for layout in ("C1", "C3"):
                metrics.append(metric_for_cell[layout])
            print(f"paired pilot completed density={density} seed={seed} recovered_opportunities={len(recovered)}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(paired_hashes).to_json(OUT / "paired_manifests.json", orient="records", indent=2)
    pd.DataFrame(metrics).to_csv(OUT / "pilot_metrics.csv", index=False)
    pd.DataFrame(opportunity_records).to_csv(OUT / "pilot_opportunity_comparison.csv", index=False)
    for layout in ("C1", "C3"):
        pd.concat(decisions_by_layout[layout], ignore_index=True).to_csv(OUT / f"pilot_{layout}_decisions.csv.gz", index=False, compression="gzip")


if __name__ == "__main__":
    main()
