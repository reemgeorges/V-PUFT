from vpuft.crypto import KeyRegistry
from vpuft.evidence_acquisition import merge_existing_witness_evidence
from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import NetworkConfig, ResearchConfig
from dataclasses import replace
from vpuft.trace import build_trace_bundle, read_events_jsonl


def test_merge_uses_only_existing_signed_witness_attestations():
    trace = (
        "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout/"
        "vehicles_20/seed_1001/shared_detection_trace.jsonl"
    )
    keys = KeyRegistry()
    bundle = build_trace_bundle(
        read_events_jsonl(trace), keys, window_seconds=15.0,
        namespace="urban_roundabout-vehicles-20",
    )

    merged, audit = merge_existing_witness_evidence(bundle.rsu_cases, bundle.witness_cases)

    original_ids = {a.attestation_id for c in bundle.rsu_cases + bundle.witness_cases for a in c.attestations}
    merged_ids = {a.attestation_id for c in merged for a in c.attestations}
    assert merged_ids <= original_ids
    assert audit["invented_attestations"] == 0
    assert audit["witness_attestations_added"] > 0
    assert len(merged) == len(bundle.rsu_cases)


def test_merge_never_duplicates_an_attestation_or_rebinds_case_identity():
    trace = (
        "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout/"
        "vehicles_20/seed_1001/shared_detection_trace.jsonl"
    )
    keys = KeyRegistry()
    bundle = build_trace_bundle(
        read_events_jsonl(trace), keys, window_seconds=15.0,
        namespace="urban_roundabout-vehicles-20",
    )
    merged, _ = merge_existing_witness_evidence(bundle.rsu_cases, bundle.witness_cases)
    for case in merged:
        ids = [a.attestation_id for a in case.attestations]
        assert len(ids) == len(set(ids))
        assert all(a.case_id == case.case_id for a in case.attestations)


def test_forwarded_witness_evidence_has_an_accounted_uplink_message():
    trace = (
        "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout/"
        "vehicles_20/seed_1001/shared_detection_trace.jsonl"
    )
    keys = KeyRegistry()
    bundle = build_trace_bundle(
        read_events_jsonl(trace), keys, window_seconds=15.0,
        namespace="urban_roundabout-vehicles-20",
    )
    merged, _ = merge_existing_witness_evidence(bundle.rsu_cases, bundle.witness_cases)
    selected = next(case for case in merged if any(a.source_kind == "vehicle_witness" for a in case.attestations))
    config = ResearchConfig(network=NetworkConfig(packet_delivery_ratio=1.0))

    result = DistributedRSUExtendedVPUFT(config, keys).run([selected], 1001)

    uplinks = [m for m in result.messages if m.message_type == "WITNESS_EVIDENCE_UPLINK"]
    expected = sum(a.source_kind == "vehicle_witness" for a in selected.attestations)
    assert len(uplinks) == expected
