from __future__ import annotations

from dataclasses import replace

from .domain import EvidenceCase


def merge_existing_witness_evidence(
    rsu_cases: list[EvidenceCase],
    witness_cases: list[EvidenceCase],
) -> tuple[list[EvidenceCase], dict[str, int]]:
    """Attach already-recorded witness attestations to matching RSU cases.

    This is an acquisition/forwarding variant, not sensor expansion. It never
    creates or rebinds an attestation and deliberately excludes witness-only
    cases so the baseline case population and window semantics stay unchanged.
    """
    witness_by_case = {case.case_id: case for case in witness_cases}
    merged: list[EvidenceCase] = []
    added = duplicate_ids = incompatible = 0
    for rsu_case in rsu_cases:
        existing_ids = {attestation.attestation_id for attestation in rsu_case.attestations}
        additions = []
        witness_case = witness_by_case.get(rsu_case.case_id)
        if witness_case is not None:
            if (
                witness_case.vehicle_id != rsu_case.vehicle_id
                or witness_case.attack_type != rsu_case.attack_type
                or witness_case.ground_truth_malicious != rsu_case.ground_truth_malicious
            ):
                incompatible += len(witness_case.attestations)
            else:
                for attestation in witness_case.attestations:
                    if attestation.attestation_id in existing_ids:
                        duplicate_ids += 1
                        continue
                    if attestation.case_id != rsu_case.case_id:
                        incompatible += 1
                        continue
                    additions.append(attestation)
                    existing_ids.add(attestation.attestation_id)
        added += len(additions)
        merged.append(replace(rsu_case, attestations=[*rsu_case.attestations, *additions]))

    rsu_case_ids = {case.case_id for case in rsu_cases}
    unmatched = sum(
        len(case.attestations) for case in witness_cases if case.case_id not in rsu_case_ids
    )
    return merged, {
        "rsu_cases": len(rsu_cases),
        "witness_attestations_added": added,
        "duplicate_attestation_ids_skipped": duplicate_ids,
        "incompatible_attestations_skipped": incompatible,
        "unmatched_witness_attestations_excluded": unmatched,
        "invented_attestations": 0,
    }
