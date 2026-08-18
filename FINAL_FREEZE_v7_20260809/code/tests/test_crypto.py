from dataclasses import replace

from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceDirection
from vpuft.evidence import sign_attestation, verify_attestation


def test_tampered_attestation_signature_fails():
    keys = KeyRegistry()
    att = EvidenceAttestation(
        attestation_id="a1", case_id="c1", observation_root_id="r1",
        source_id="rsu-1", source_kind="rsu", validator_rsu_id="rsu-1",
        administrative_domain_id="d1", sensor_modality="cam", geographic_cell="z1",
        attack_type=AttackType.REPLAY, direction=EvidenceDirection.SUPPORTS,
        detector_confidence=0.9, source_reliability=0.9, freshness=0.9,
        verifiability=0.99, independence=0.9, observed_at=1.0,
        evidence_hash="h1", signature="", public_key_id="",
    )
    signed = sign_attestation(att, keys, "rsu-1")
    assert verify_attestation(signed, keys)
    assert not verify_attestation(replace(signed, evidence_hash="tampered"), keys)
