from __future__ import annotations

from dataclasses import asdict, replace

from .crypto import KeyRegistry
from .domain import EvidenceAttestation


_SIGNATURE_FIELDS = {"signature", "public_key_id"}


def signing_payload(attestation: EvidenceAttestation) -> dict:
    data = asdict(attestation)
    for field in _SIGNATURE_FIELDS:
        data.pop(field, None)
    return data


def sign_attestation(attestation: EvidenceAttestation, keys: KeyRegistry, identity: str) -> EvidenceAttestation:
    payload = signing_payload(attestation)
    signature = keys.sign(identity, payload)
    return replace(attestation, signature=signature, public_key_id=identity)


def verify_attestation(attestation: EvidenceAttestation, keys: KeyRegistry) -> bool:
    return keys.verify(attestation.public_key_id, signing_payload(attestation), attestation.signature)
