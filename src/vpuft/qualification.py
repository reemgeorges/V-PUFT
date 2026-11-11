from __future__ import annotations

from dataclasses import replace

from .config import ResearchConfig
from .domain import EvidenceCase, EvidenceDirection, QualificationResult
from .weighting import case_evidence_masses, evidence_mass, evidence_weight, regularized_strengths


class VPUFTQualificationEngine:
    def __init__(self, config: ResearchConfig) -> None:
        self.config = config

    def qualify(self, case: EvidenceCase, now: float) -> QualificationResult:
        policy = self.config.policies[case.attack_type.value]
        fresh_attestations = []
        expired = 0
        for attestation in case.attestations:
            age = max(0.0, now - attestation.observed_at)
            if age > policy.freshness_window_seconds:
                expired += 1
                continue
            # Freshness is both supplied by the detector and bounded by actual age.
            age_freshness = max(0.0, 1.0 - age / max(policy.freshness_window_seconds, 1e-9))
            fresh_attestations.append(replace(attestation, freshness=min(attestation.freshness, age_freshness)))

        positive_mass, negative_mass, roots = case_evidence_masses(fresh_attestations, self.config.weights)
        if self.config.distributed_extension.diversity_aware_root_assignment:
            used_sources: set[str] = set()
            used_zones: set[str] = set()
            used_modalities: set[str] = set()
            reassigned = []
            for root in roots:
                if root.direction != EvidenceDirection.SUPPORTS:
                    reassigned.append(root)
                    continue
                candidates = []
                for attestation in fresh_attestations:
                    if (
                        attestation.observation_root_id == root.observation_root_id
                        and attestation.direction == EvidenceDirection.SUPPORTS
                        and attestation.validity == 1
                    ):
                        weight = evidence_weight(attestation, self.config.weights)
                        if weight - root.opposing_weight > 1e-12:
                            candidates.append((weight, attestation))
                if not candidates:
                    reassigned.append(root)
                    continue
                weight, representative = max(
                    candidates,
                    key=lambda pair: (
                        int(pair[1].source_id not in used_sources)
                        + int(pair[1].geographic_cell not in used_zones)
                        + int(pair[1].sensor_modality not in used_modalities),
                        pair[0],
                        pair[1].attestation_id,
                    ),
                )
                used_sources.add(representative.source_id)
                used_zones.add(representative.geographic_cell)
                used_modalities.add(representative.sensor_modality)
                reassigned.append(replace(
                    root,
                    representative=representative,
                    supporting_weight=weight,
                    weight=weight - root.opposing_weight,
                ))
            roots = sorted(reassigned, key=lambda item: item.observation_root_id)
            positive_mass = evidence_mass(
                root.weight for root in roots if root.direction == EvidenceDirection.SUPPORTS
            )
            negative_mass = evidence_mass(
                root.weight for root in roots if root.direction == EvidenceDirection.OPPOSES
            )
        supporting, opposing, margin = regularized_strengths(
            positive_mass, negative_mass, policy.opposition_lambda
        )
        supporters = [
            root for root in roots
            if root.direction == EvidenceDirection.SUPPORTS and root.weight >= policy.min_representative_weight
        ]
        independent_roots = len({root.observation_root_id for root in supporters})
        if self.config.distributed_extension.provenance_safe_observer_diversity:
            # A root can provide at most one diversity credit in each dimension.
            # This prevents three RSUs observing one CAM from satisfying a
            # two-source/two-zone requirement by themselves. Different roots
            # may select different signed observers for source and zone credit.
            eligible_by_root: dict[str, list] = {}
            supporting_root_ids = {root.observation_root_id for root in supporters}
            for attestation in fresh_attestations:
                if (
                    attestation.observation_root_id in supporting_root_ids
                    and attestation.direction == EvidenceDirection.SUPPORTS
                    and attestation.validity == 1
                    and evidence_weight(attestation, self.config.weights) >= policy.min_representative_weight
                ):
                    eligible_by_root.setdefault(attestation.observation_root_id, []).append(attestation)
            distinct_sources = len(self._distinct_root_matching(eligible_by_root, "source_id"))
            distinct_zones = len(self._distinct_root_matching(eligible_by_root, "geographic_cell"))
            distinct_modalities = len(self._distinct_root_matching(eligible_by_root, "sensor_modality"))
        else:
            distinct_sources = len({root.representative.source_id for root in supporters})
            distinct_zones = len({root.representative.geographic_cell for root in supporters})
            distinct_modalities = len({root.representative.sensor_modality for root in supporters})
        correlated_suppressed = sum(root.duplicate_count for root in roots)

        cryptographic_decisive = False
        if policy.cryptographic_decisive:
            cryptographic_decisive = any(
                root.weight >= policy.margin_threshold
                and root.representative.verifiability >= 0.95
                and root.representative.validity == 1
                for root in supporters
            )

        diversity_ok = (
            independent_roots >= policy.required_roots
            and distinct_sources >= policy.required_sources
            and distinct_zones >= policy.required_zones
            and distinct_modalities >= policy.required_modalities
        )
        qualified = cryptographic_decisive or (diversity_ok and margin >= policy.margin_threshold)

        failed_constraints = []
        if independent_roots < policy.required_roots:
            failed_constraints.append("independent_roots")
        if distinct_sources < policy.required_sources:
            failed_constraints.append("sources")
        if distinct_zones < policy.required_zones:
            failed_constraints.append("zones")
        if distinct_modalities < policy.required_modalities:
            failed_constraints.append("modalities")
        if margin < policy.margin_threshold:
            failed_constraints.append("margin")

        if cryptographic_decisive:
            reason = "cryptographic_decisive_evidence"
        elif not fresh_attestations:
            reason = "no_fresh_valid_evidence"
        elif not diversity_ok:
            reason = "insufficient_independent_evidence_diversity"
        elif margin < policy.margin_threshold:
            reason = "insufficient_weighted_margin"
        else:
            reason = "evidence_qualified"

        return QualificationResult(
            case_id=case.case_id,
            qualified=qualified,
            supporting_strength=supporting,
            opposing_strength=opposing,
            decision_margin=margin,
            independent_roots=independent_roots,
            distinct_sources=distinct_sources,
            distinct_zones=distinct_zones,
            distinct_modalities=distinct_modalities,
            correlated_suppressed=correlated_suppressed,
            expired_evidence=expired,
            reason=reason,
            cryptographic_decisive=cryptographic_decisive,
            required_roots=policy.required_roots,
            required_sources=policy.required_sources,
            required_zones=policy.required_zones,
            required_modalities=policy.required_modalities,
            required_margin=policy.margin_threshold,
            failed_constraints=tuple(failed_constraints),
            evidence_observed_at=tuple(
                sorted(float(attestation.observed_at) for attestation in fresh_attestations)
            ),
            evidence_ages_seconds=tuple(
                sorted(max(0.0, now - float(attestation.observed_at)) for attestation in fresh_attestations)
            ),
            excluded_duplicate_roots=correlated_suppressed,
        )

    @staticmethod
    def _distinct_root_matching(reports_by_root: dict[str, list], attribute: str) -> dict[str, str]:
        """Maximum one-to-one matching from supporting roots to diversity values."""
        value_to_root: dict[str, str] = {}

        def assign(root_id: str, visited: set[str]) -> bool:
            values = sorted({str(getattr(report, attribute)) for report in reports_by_root[root_id]})
            for value in values:
                if value in visited:
                    continue
                visited.add(value)
                current = value_to_root.get(value)
                if current is None or assign(current, visited):
                    value_to_root[value] = root_id
                    return True
            return False

        for root_id in sorted(reports_by_root):
            assign(root_id, set())
        return value_to_root
