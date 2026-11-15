from dataclasses import replace
from pathlib import Path

from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.evidence_announcement import EvidenceVerificationCache


ROOT = Path(__file__).resolve().parents[1]


class CountingKeyRegistry(KeyRegistry):
    def __init__(self, seed):
        super().__init__(seed)
        self.verify_calls = 0

    def verify(self, identity, payload, signature):
        self.verify_calls += 1
        return super().verify(identity, payload, signature)


def _attestation(keys, evidence_hash="signed-payload"):
    item = EvidenceAttestation(
        "cache-att", "cache-case", "cache-root", "rsu-7", "rsu", "rsu-7",
        "domain-7", "cam", "cell-a", AttackType.POSITION_OFFSET,
        EvidenceDirection.OPPOSES, .99, .95, .98, 1.0, 1.0, 10.0,
        evidence_hash, "", "",
    )
    return sign_attestation(item, keys, "rsu-7")


def test_cache_reuses_only_exact_immutable_attestation_verifications():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = CountingKeyRegistry(config.security.deterministic_master_seed)
    cache = EvidenceVerificationCache(keys)
    signed = _attestation(keys)

    assert cache.verify_attestation(signed)
    calls_after_first = keys.verify_calls
    assert cache.verify_attestation(signed)
    assert keys.verify_calls == calls_after_first
    assert not cache.verify_attestation(replace(signed, evidence_hash="tampered"))
    assert keys.verify_calls == calls_after_first + 1
