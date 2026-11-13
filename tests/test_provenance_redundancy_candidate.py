from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation, verify_attestation
from vpuft.qualification import VPUFTQualificationEngine
from vpuft.weighting import evidence_weight


def _att(keys, *, case_id, root, source, zone, direction=EvidenceDirection.SUPPORTS,
         at=1.0, confidence=0.95, suffix="report"):
    raw = EvidenceAttestation(
        f"att-{root}-{source}-{suffix}", case_id, root, source, "rsu", source,
        f"domain-{source}", "cam", zone, AttackType.POSITION_OFFSET, direction,
        confidence, 0.99, 0.99, 0.99, 0.99, at, f"hash-{root}-{source}-{suffix}", "", "",
    )
    return sign_attestation(raw, keys, source)


def _config():
    base = ResearchConfig()
    policies = dict(base.policies)
    policies[AttackType.POSITION_OFFSET.value] = replace(
        policies[AttackType.POSITION_OFFSET.value],
        required_roots=2,
        required_sources=2,
        required_zones=2,
        required_modalities=1,
        margin_threshold=0.30,
        min_representative_weight=0.05,
        freshness_window_seconds=15.0,
    )
    return replace(base, policies=policies, distributed_extension=replace(
        base.distributed_extension, diversity_aware_root_assignment=True
    ))


def _case(case_id, reports):
    return EvidenceCase(case_id, "vehicle-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True, list(reports))


def test_pre_delivery_max_weight_collapse_can_discard_the_only_fresh_report():
    keys = KeyRegistry()
    old = _att(keys, case_id="freshness", root="root-a", source="rsu-1", zone="zone-a",
               at=0.0, confidence=0.99, suffix="old")
    recent = _att(keys, case_id="freshness", root="root-a", source="rsu-1", zone="zone-a",
                  at=10.0, confidence=0.80, suffix="recent")
    second_root = _att(keys, case_id="freshness", root="root-b", source="rsu-2", zone="zone-b",
                       at=10.0, confidence=0.95, suffix="other")
    assert verify_attestation(old, keys) and verify_attestation(recent, keys)
    assert old.attestation_id != recent.attestation_id and old.signature != recent.signature
    assert evidence_weight(old, _config().weights) > evidence_weight(recent, _config().weights)

    complete = _case("freshness", [old, recent, second_root])
    collapsed = _case("freshness", [old, second_root])  # naive max-at-ingress choice
    engine = VPUFTQualificationEngine(_config())
    full = engine.qualify(complete, now=16.0)
    reduced = engine.qualify(collapsed, now=16.0)

    assert full.qualified
    assert not reduced.qualified
    assert full.expired_evidence == 1 and reduced.expired_evidence == 1
    assert full.independent_roots == 2 and reduced.independent_roots == 1


def test_grouping_without_geographic_cell_can_remove_b1s_only_diverse_representative():
    keys = KeyRegistry()
    first_root = _att(keys, case_id="zone-choice", root="root-a", source="rsu-3", zone="zone-a",
                      confidence=0.95, suffix="first")
    high_weight_same_group = _att(keys, case_id="zone-choice", root="root-b", source="rsu-1", zone="zone-a",
                                  confidence=0.99, suffix="zone-a")
    alternate_zone = _att(keys, case_id="zone-choice", root="root-b", source="rsu-1", zone="zone-b",
                          confidence=0.90, suffix="zone-b")
    assert all(verify_attestation(item, keys) for item in (first_root, high_weight_same_group, alternate_zone))

    engine = VPUFTQualificationEngine(_config())
    full = engine.qualify(_case("zone-choice", [first_root, high_weight_same_group, alternate_zone]), now=2.0)
    # A proposed (case, root, source, direction) max-weight collapse omits zone-b.
    collapsed = engine.qualify(_case("zone-choice", [first_root, high_weight_same_group]), now=2.0)

    assert full.qualified
    assert full.independent_roots == collapsed.independent_roots == 2
    assert full.distinct_sources == collapsed.distinct_sources == 2
    assert full.distinct_zones == 2
    assert collapsed.distinct_zones == 1
    assert not collapsed.qualified


def test_root_aggregation_preserves_opposing_direction_instead_of_counting_report_rows():
    keys = KeyRegistry()
    support = _att(keys, case_id="conflict", root="same-root", source="rsu-1", zone="zone-a",
                   direction=EvidenceDirection.SUPPORTS, confidence=0.92, suffix="support")
    oppose = _att(keys, case_id="conflict", root="same-root", source="rsu-1", zone="zone-a",
                  direction=EvidenceDirection.OPPOSES, confidence=0.98, suffix="oppose")
    engine = VPUFTQualificationEngine(_config())
    both = engine.qualify(_case("conflict", [support, oppose]), now=2.0)
    support_only = engine.qualify(_case("conflict", [support]), now=2.0)

    assert both.opposing_strength > 0.0
    assert both.independent_roots == 0
    assert support_only.independent_roots == 1
    assert support_only.opposing_strength == 0.0
    assert not both.qualified and not support_only.qualified


def test_arrival_order_does_not_change_root_level_qualification_result():
    keys = KeyRegistry()
    reports = [
        _att(keys, case_id="order", root="root-a", source="rsu-1", zone="zone-a", suffix="a1"),
        _att(keys, case_id="order", root="root-a", source="rsu-2", zone="zone-b", confidence=0.90, suffix="a2"),
        _att(keys, case_id="order", root="root-b", source="rsu-3", zone="zone-c", suffix="b1"),
    ]
    engine = VPUFTQualificationEngine(_config())
    forward = engine.qualify(_case("order", reports), now=2.0)
    reverse = engine.qualify(_case("order", list(reversed(reports))), now=2.0)
    assert forward == reverse
