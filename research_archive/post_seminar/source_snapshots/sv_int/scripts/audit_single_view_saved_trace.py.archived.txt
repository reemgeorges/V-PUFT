from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.opportunity_evaluation import opportunity_frame
from vpuft.trace import build_trace_bundle, read_events_jsonl
from replay_coordinator_security_v5 import sha256_file
from run_phase2_ablation import decision_frame, metric_row


def main():
    repo = Path(__file__).resolve().parents[1]
    trace = Path(r"C:\Users\reemg\OneDrive\Desktop\master\6\v10-recall-70-feasibility\results\rsu8_pilot\pilot\C3\vehicles_20\seed_2101\shared_detection_trace.jsonl")
    config_path = repo / "configs/extension_v5_coordinator_security.json"
    base = load_config(config_path)
    events = read_events_jsonl(trace)
    keys = KeyRegistry(base.security.deterministic_master_seed)
    bundle = build_trace_bundle(events, keys, window_seconds=base.detector.case_window_seconds,
                                namespace="urban_roundabout-vehicles-20")
    cases = bundle.rsu_cases
    generated = pd.read_csv(trace.parent / "generated_messages.csv")
    variants = [("disabled", base), ("enabled", replace(base, pbft=replace(base.pbft, single_view_safety_mode=True)))]
    frames = {}
    rows = []
    for name, cfg in variants:
        started = time.process_time()
        result = DistributedRSUExtendedVPUFT(cfg, KeyRegistry(cfg.security.deterministic_master_seed)).run(cases, 2101)
        cpu = time.process_time() - started
        frame = decision_frame(result, cases, density=20, seed=2101, variant=name)
        frames[name] = frame.sort_values("case_id").reset_index(drop=True)
        messages = [m.message_type for m in result.messages]
        opp = opportunity_frame(generated, frame, set(
            str(json.loads(line)["message_id"]) for line in trace.open(encoding="utf-8")
            if json.loads(line).get("source_kind") == "rsu"
        ), window_seconds=15.0)
        rows.append({
            "variant": name, "cases": len(cases), "cpu_seconds": cpu,
            "attempts": len(messages), "messages_per_case": len(messages)/len(cases),
            "consensus_ok": sum(o.committed for o in result.consensus),
            "consensus_failed": sum(not o.committed for o in result.consensus),
            "view_changes": sum(o.view_changes for o in result.consensus),
            "failure_reasons": json.dumps({reason: sum(o.reason == reason for o in result.consensus)
                                            for reason in sorted({o.reason for o in result.consensus})}),
            "pdr": sum(m.delivered_at is not None for m in result.messages)/max(1,len(result.messages)),
            "opportunities": len(opp),
            "observed_opportunities": int(opp.observed_opportunity.sum()),
            "detected_opportunities": int(opp.detected_opportunity.sum()),
            "protected_opportunities": int((opp.detected_opportunity | opp.terminal_after_revocation).sum()),
            "trace_sha256": sha256_file(trace),
            "membership_digest": cfg.pbft.membership_digest,
        })
        rows[-1].update(metric_row(result, cases, frame, density=20, seed=2101, variant=name,
                                   cpu=cpu, wall=float("nan"), peak=float("nan"), acquisition={}))
        print(json.dumps(rows[-1], default=str, sort_keys=True))
    pd.testing.assert_frame_equal(
        frames["disabled"][["case_id", "new_state", "committed"]],
        frames["enabled"][["case_id", "new_state", "committed"]], check_dtype=False,
    )
    changed = frames["disabled"].merge(frames["enabled"], on="case_id", suffixes=("_off", "_on"))
    finalized_equal = (
        changed.finalized_at_off.fillna(-1).astype(float)
        == changed.finalized_at_on.fillna(-1).astype(float)
    )
    changed = changed[(changed.new_state_off != changed.new_state_on)
                      | (changed.committed_off != changed.committed_on)
                      | ~finalized_equal]
    print("case_level_changes=" + json.dumps(changed[["case_id", "new_state_off", "new_state_on",
          "committed_off", "committed_on", "finalized_at_off", "finalized_at_on"]].to_dict("records"), default=str))


if __name__ == "__main__":
    main()
