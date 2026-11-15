"""Bounded fault injection against one qualifying case from the saved C3 trace.

This is not a SUMO runner and writes no result artifacts. It prints a JSON
record per scenario so the fault path and message costs can be reviewed.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry, digest_hex
from vpuft.trace import build_trace_bundle, read_events_jsonl


TRACE_DIR = Path(
    r"C:\Users\reemg\OneDrive\Desktop\master\6\v10-recall-70-feasibility"
    r"\results\rsu8_pilot\pilot\C3\vehicles_20\seed_2101"
)
CASE_ID = "case-urban_roundabout-2101-veh_000-w0001"


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    base = load_config(repo / "configs/extension_v5_coordinator_security.json")
    events = read_events_jsonl(TRACE_DIR / "shared_detection_trace.jsonl")
    bundle = build_trace_bundle(
        events,
        KeyRegistry(base.security.deterministic_master_seed),
        window_seconds=base.detector.case_window_seconds,
        namespace="urban_roundabout-vehicles-20",
    )
    target = next(case for case in bundle.rsu_cases if case.case_id == CASE_ID)
    selector = DistributedRSUExtendedVPUFT(base, KeyRegistry(base.security.deterministic_master_seed))
    coordinator = selector._select_coordinator(target)
    reliable_network = replace(base.network, packet_delivery_ratio=1.0, jitter_ms=0.0)

    scenarios: list[tuple[str, bool, dict[str, str]]] = [
        ("normal_guarded", True, {}),
        ("normal_legacy", False, {}),
        ("one_nonleader_validator_offline", True, {
            next(v for v in base.pbft.validators if v != coordinator): "offline"
        }),
        ("two_nonleader_validators_offline", True, {
            v: "offline" for v in [x for x in base.pbft.validators if x != coordinator][:2]
        }),
        ("leader_invalid_guarded", True, {coordinator: "propose_invalid"}),
        ("leader_invalid_legacy", False, {coordinator: "propose_invalid"}),
        ("coordinator_offline", True, {coordinator: "offline"}),
    ]
    for name, guarded, behaviors in scenarios:
        config = replace(
            base,
            network=reliable_network,
            pbft=replace(
                base.pbft,
                single_view_safety_mode=guarded,
                validator_behaviors=behaviors,
            ),
        )
        started = time.process_time()
        architecture = DistributedRSUExtendedVPUFT(
            config, KeyRegistry(config.security.deterministic_master_seed)
        )
        result = architecture.run([target], seed=2101)
        cpu = time.process_time() - started
        decision = result.decisions[0]
        outcome = result.consensus[0] if result.consensus else None
        decision_digest = None
        if decision.metadata.get("qualification_outcome") is not None:
            qualified = architecture.engine.qualify(
                architecture.sanitize_case(target),
                decision.metadata["qualification_evaluated_at"],
            )
            decision_payload = {
                "vehicle_id": target.vehicle_id,
                "case_id": target.case_id,
                "attack_type": target.attack_type.value,
                "requested_state": "revoked",
                "qualification": asdict(qualified),
                "coordinator": coordinator,
            }
            decision_digest = digest_hex(decision_payload)
        message_counts = Counter(message.message_type for message in result.messages)
        row = {
            "scenario": name,
            "case_id": CASE_ID,
            "vehicle_id": target.vehicle_id,
            "attack_type": target.attack_type.value,
            "ground_truth_malicious": target.ground_truth_malicious,
            "evidence_coordinator": coordinator,
            "configured_faults": behaviors,
            "single_view_safety_mode": guarded,
            "decision_committed": decision.committed,
            "decision_reason": decision.reason,
            "new_state": decision.new_state.value,
            "qualified": decision.metadata.get("qualification_outcome"),
            "consensus_present": outcome is not None,
            "consensus_committed": outcome.committed if outcome else False,
            "view": outcome.view if outcome else None,
            "leader": outcome.leader if outcome else None,
            "prepare_votes": outcome.prepare_votes if outcome else 0,
            "commit_votes": outcome.commit_votes if outcome else 0,
            "view_changes": outcome.view_changes if outcome else 0,
            "reason": outcome.reason if outcome else decision.reason,
            "proposed_digest": decision_digest if outcome is not None else None,
            "committed_decision_digest": decision_digest if outcome and outcome.committed else None,
            "invalid_proposal_attempted": outcome.invalid_proposal_attempted if outcome else False,
            "message_count": len(result.messages),
            "message_types": dict(sorted(message_counts.items())),
            "pdr": sum(message.delivered_at is not None for message in result.messages)
            / max(1, len(result.messages)),
            "simulated_e2e_ms": (
                1000 * (decision.finalized_at - decision.detected_at)
                if decision.finalized_at is not None and decision.detected_at is not None
                else None
            ),
            "ledger_blocks": result.ledger_blocks,
            "ledger_consistent": result.ledger_consistent,
            "host_cpu_seconds_single_run_descriptive_only": cpu,
        }
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
