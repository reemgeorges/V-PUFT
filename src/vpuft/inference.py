from __future__ import annotations

from collections.abc import Iterable

from .domain import AttackType

# Reason codes that identify an observed attack family. These are produced by
# local plausibility/security checks, not by the injected ground-truth label.
PRIMARY_REASON_TO_ATTACK: dict[str, AttackType] = {
    "position_inconsistency": AttackType.POSITION_OFFSET,
    "speed_inconsistency": AttackType.SPEED_OFFSET,
    "certificate_tamper": AttackType.CERTIFICATE_TAMPER,
    "flood_rate": AttackType.FLOOD,
    "false_denm_physical_mismatch": AttackType.FALSE_DENM,
    # replay_age is a primary replay signal. replay_nonce alone is intentionally
    # treated as corroborating because flood/mixed bursts can reuse a nonce.
    "replay_age": AttackType.REPLAY,
}

NON_ATTACK_REASON_CODES = {
    "clean_observation",
    "not_applicable_observation",
    "compromised_rsu_false_attestation",
    "compromised_witness_false_report",
}



def _families_from_reasons(
    reason_codes: Iterable[str],
    *,
    suppress_replay_kinematic_artifacts: bool = False,
) -> set[AttackType]:
    # Return attack families represented by one observable reason set.
    reasons = {str(reason) for reason in reason_codes if str(reason)}
    families = {
        attack
        for reason, attack in PRIMARY_REASON_TO_ATTACK.items()
        if reason in reasons
    }

    if "replay_nonce" in reasons and "flood_rate" not in reasons:
        families.add(AttackType.REPLAY)

    # Root-local suppression only: replayed stale kinematics can naturally
    # trigger position/speed inconsistencies on the same observation root.
    if suppress_replay_kinematic_artifacts and "replay_age" in reasons:
        families.discard(AttackType.POSITION_OFFSET)
        families.discard(AttackType.SPEED_OFFSET)
        families.add(AttackType.REPLAY)

    return families


def infer_attack_type_from_root_reasons(
    root_reason_groups: Iterable[Iterable[str]],
) -> AttackType:
    # Infer a case family while preserving observation-root provenance.
    case_families: set[AttackType] = set()
    for reason_codes in root_reason_groups:
        case_families.update(
            _families_from_reasons(
                reason_codes,
                suppress_replay_kinematic_artifacts=True,
            )
        )

    if len(case_families) >= 2:
        return AttackType.MIXED
    if len(case_families) == 1:
        return next(iter(case_families))
    return AttackType.BENIGN

def infer_attack_type_from_reasons(reason_codes: Iterable[str]) -> AttackType:
    """Infer an attack family only from observed detector reason codes.

    ``replay_nonce`` by itself is accepted as replay only when no flood-rate
    signal is present. This prevents duplicate nonces created by a flood burst
    from being misclassified as a replay attack. If two or more independent
    primary families are present, the case is classified as ``mixed``.
    """
    families = _families_from_reasons(reason_codes)

    if len(families) >= 2:
        return AttackType.MIXED
    if len(families) == 1:
        return next(iter(families))
    return AttackType.BENIGN
