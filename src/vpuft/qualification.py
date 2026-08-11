from __future__ import annotations

from dataclasses import replace

from .config import ResearchConfig
from .domain import EvidenceCase, EvidenceDirection, QualificationResult
from .weighting import case_evidence_masses, regularized_strengths


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
        supporting, opposing, margin = regularized_strengths(
            positive_mass, negative_mass, policy.opposition_lambda
        )
        supporters = [
            root for root in roots
            if root.direction == EvidenceDirection.SUPPORTS and root.weight >= policy.min_representative_weight
        ]
        independent_roots = len({root.observation_root_id for root in supporters})
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
        )
