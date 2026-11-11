from dataclasses import replace

import pytest

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.qualification import VPUFTQualificationEngine


def _report(keys, *, root, source, zone, direction=EvidenceDirection.SUPPORTS,
            at=1.0, confidence=0.98, validity=1, signed=True, modality="cam", suffix=""):
    value = EvidenceAttestation(
        f"att-{root}-{source}-{suffix or zone}", "case-p3", root, source, "rsu", source,
        f"domain-{source}", modality, zone, AttackType.POSITION_OFFSET, direction,
        confidence, 0.99, 0.99, 0.99, 0.99, at, f"hash-{root}-{source}-{zone}-{suffix}", "", "",
        validity=validity,
    )
    return sign_attestation(value, keys, source) if signed else replace(value, signature="invalid")


def _qualify(reports, *, enabled=True, now=2.0):
    config = ResearchConfig()
    config = replace(config, distributed_extension=replace(
        config.distributed_extension, provenance_safe_observer_diversity=enabled
    ))
    case = EvidenceCase("case-p3", "veh-1", "p-1", AttackType.POSITION_OFFSET, 0.0, True, reports)
    return VPUFTQualificationEngine(config).qualify(case, now)


def test_three_rsus_observing_one_cam_remain_one_root_and_one_diversity_credit():
    keys = KeyRegistry()
    reports = [_report(keys, root="cam-root", source=f"rsu-{i}", zone=f"zone-{i}") for i in range(3)]
    result = _qualify(reports)
    assert result.independent_roots == 1
    assert result.distinct_sources == 1
    assert result.distinct_zones == 1
    assert not result.qualified
    assert "independent_roots" in result.failed_constraints


def test_two_independent_roots_can_match_distinct_sources_and_zones():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="root-a", source="rsu-1", zone="zone-a"),
        _report(keys, root="root-a", source="rsu-2", zone="zone-b", confidence=0.95),
        _report(keys, root="root-b", source="rsu-1", zone="zone-a", suffix="b1"),
        _report(keys, root="root-b", source="rsu-2", zone="zone-b", confidence=0.95, suffix="b2"),
    ]
    result = _qualify(reports)
    assert result.independent_roots == 2
    assert result.distinct_sources == 2
    assert result.distinct_zones == 2
    policy = ResearchConfig().policies[AttackType.POSITION_OFFSET.value]
    assert result.required_roots == policy.required_roots
    assert result.required_sources == policy.required_sources
    assert result.required_zones == policy.required_zones
    assert result.qualified


def test_same_root_extra_observers_do_not_replace_required_independent_message():
    keys = KeyRegistry()
    reports = [_report(keys, root="root-a", source=f"rsu-{i}", zone=f"zone-{i}") for i in range(4)]
    result = _qualify(reports)
    assert result.independent_roots == 1
    assert result.distinct_sources == 1
    assert result.distinct_zones == 1


def test_opposing_report_cannot_earn_supporting_diversity_credit():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="root-a", source="rsu-1", zone="zone-a"),
        _report(keys, root="root-a", source="rsu-2", zone="zone-b", direction=EvidenceDirection.OPPOSES),
        _report(keys, root="root-b", source="rsu-1", zone="zone-a", suffix="b"),
    ]
    result = _qualify(reports)
    assert result.distinct_sources == 1
    assert result.distinct_zones == 1


def test_expired_invalid_and_below_weight_reports_are_ineligible_for_matching():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="root-a", source="rsu-1", zone="zone-a"),
        _report(keys, root="root-a", source="rsu-2", zone="zone-b", at=-20, suffix="expired"),
        _report(keys, root="root-a", source="rsu-3", zone="zone-c", validity=0, suffix="invalid"),
        _report(keys, root="root-b", source="rsu-1", zone="zone-a", suffix="b"),
        _report(keys, root="root-b", source="rsu-4", zone="zone-d", confidence=1e-30, suffix="weak"),
    ]
    result = _qualify(reports)
    assert result.independent_roots == 2
    assert result.distinct_sources == 1
    assert result.distinct_zones == 1


def test_invalid_signature_is_removed_by_architecture_sanitization():
    from vpuft.architectures.base import Architecture

    keys = KeyRegistry()
    good = _report(keys, root="root-a", source="rsu-1", zone="zone-a")
    bad = _report(keys, root="root-b", source="rsu-2", zone="zone-b", signed=False)
    case = EvidenceCase("case-p3", "veh-1", "p-1", AttackType.POSITION_OFFSET, 0.0, True, [good, bad])

    class Sanitizer(Architecture):
        name = "test"
        def run(self, cases, seed):
            raise NotImplementedError

    clean = Sanitizer(ResearchConfig(), keys).sanitize_case(case)
    assert [item.observation_root_id for item in clean.attestations if item.validity == 1] == ["root-a"]
    assert all(item.validity == 0 for item in clean.attestations if item.observation_root_id == "root-b")


@pytest.mark.parametrize("attack", [AttackType.REPLAY, AttackType.FLOOD])
def test_replay_and_flood_copies_do_not_increase_root_count(attack):
    keys = KeyRegistry()
    reports = [_report(keys, root="same-original-root", source=f"rsu-{i}", zone=f"zone-{i}") for i in range(5)]
    result = _qualify(reports)
    assert result.independent_roots == 1


def test_compromised_signed_source_cannot_gain_more_than_one_root_credit():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="root-a", source="compromised-rsu", zone="zone-a"),
        _report(keys, root="root-a", source="compromised-rsu", zone="zone-b", suffix="a2"),
        _report(keys, root="root-b", source="rsu-2", zone="zone-c", suffix="b"),
    ]
    result = _qualify(reports)
    assert result.independent_roots == 2
    assert result.distinct_sources == 2
    assert result.distinct_zones == 2


def test_disabled_option_preserves_frozen_representative_based_result():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="root-a", source="rsu-1", zone="zone-a"),
        _report(keys, root="root-a", source="rsu-2", zone="zone-b", confidence=0.95),
        _report(keys, root="root-b", source="rsu-1", zone="zone-a", suffix="b1"),
        _report(keys, root="root-b", source="rsu-2", zone="zone-b", confidence=0.95, suffix="b2"),
    ]
    assert _qualify(reports, enabled=False).distinct_sources == 1
    assert _qualify(reports, enabled=True).distinct_sources == 2


def test_compromised_single_source_cannot_multiply_source_or_zone_credits_per_root():
    keys = KeyRegistry()
    reports = [
        _report(keys, root="cam-a", source="compromised-rsu", zone=f"lie-{i}", suffix=str(i))
        for i in range(5)
    ]
    result = _qualify(reports)
    assert result.independent_roots == 1
    assert result.distinct_sources == 1
    assert result.distinct_zones == 1
    assert not result.qualified
