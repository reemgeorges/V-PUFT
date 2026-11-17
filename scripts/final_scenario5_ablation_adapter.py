"""Experimental-only qualification adapters for the bounded Scenario 5 ablation.

Nothing in this module is imported by production V-PUFT code. The runner injects
one adapter into an already constructed architecture instance for that run.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace

from vpuft.config import ResearchConfig
from vpuft.domain import EvidenceDirection, QualificationResult
from vpuft.qualification import VPUFTQualificationEngine
from vpuft.weighting import (
    aggregate_by_root,
    evidence_mass,
    evidence_weight,
    regularized_strengths,
)


VARIANTS = ("baseline", "A_report_mass", "C_no_diversity_gates")
SECURITY_STATUS = "insecure_counterfactual_not_for_deployment"


class AblationQualificationAdapter:
    """Delegate baseline or apply one explicitly named counterfactual."""

    def __init__(self, config: ResearchConfig, variant_id: str) -> None:
        if variant_id not in VARIANTS:
            raise ValueError(f"Unknown ablation variant: {variant_id}")
        self.config = config
        self.variant_id = variant_id
        self._production = VPUFTQualificationEngine(config)

    def qualify(self, case, now: float) -> QualificationResult:
        if self.variant_id == "baseline":
            return self._production.qualify(case, now)
        if self.variant_id == "C_no_diversity_gates":
            return self._qualify_without_diversity_gates(case, now)
        return self._qualify_report_level_mass(case, now)

    def _qualify_without_diversity_gates(self, case, now: float) -> QualificationResult:
        result = self._production.qualify(case, now)
        policy = self.config.policies[case.attack_type.value]
        if result.cryptographic_decisive or result.decision_margin >= policy.margin_threshold:
            if not result.qualified:
                return replace(
                    result,
                    qualified=True,
                    reason="ablation_diversity_gates_bypassed",
                )
        return result

    def _qualify_report_level_mass(self, case, now: float) -> QualificationResult:
        """Use each valid fresh report in mass while retaining real root gates.

        This deliberately removes correlation suppression from the *mass*
        calculation only. Root/source/zone/modality counts and the
        cryptographic-decisive rule still come from production root aggregation.
        """
        policy = self.config.policies[case.attack_type.value]
        fresh = []
        expired = 0
        for attestation in case.attestations:
            age = max(0.0, now - attestation.observed_at)
            if age > policy.freshness_window_seconds:
                expired += 1
                continue
            age_freshness = max(
                0.0,
                1.0 - age / max(policy.freshness_window_seconds, 1e-9),
            )
            fresh.append(
                replace(
                    attestation,
                    freshness=min(attestation.freshness, age_freshness),
                )
            )

        roots = aggregate_by_root(fresh, self.config.weights)
        positive_mass = evidence_mass(
            evidence_weight(att, self.config.weights)
            for att in fresh
            if att.direction == EvidenceDirection.SUPPORTS
        )
        negative_mass = evidence_mass(
            evidence_weight(att, self.config.weights)
            for att in fresh
            if att.direction == EvidenceDirection.OPPOSES
        )
        supporting, opposing, margin = regularized_strengths(
            positive_mass,
            negative_mass,
            policy.opposition_lambda,
        )
        supporters = [
            root
            for root in roots
            if root.direction == EvidenceDirection.SUPPORTS
            and root.weight >= policy.min_representative_weight
        ]
        independent_roots = len({root.observation_root_id for root in supporters})
        distinct_sources = len({root.representative.source_id for root in supporters})
        distinct_zones = len({root.representative.geographic_cell for root in supporters})
        distinct_modalities = len({root.representative.sensor_modality for root in supporters})
        cryptographic_decisive = bool(
            policy.cryptographic_decisive
            and any(
                root.weight >= policy.margin_threshold
                and root.representative.verifiability >= 0.95
                and root.representative.validity == 1
                for root in supporters
            )
        )
        diversity_ok = (
            independent_roots >= policy.required_roots
            and distinct_sources >= policy.required_sources
            and distinct_zones >= policy.required_zones
            and distinct_modalities >= policy.required_modalities
        )
        qualified = cryptographic_decisive or (
            diversity_ok and margin >= policy.margin_threshold
        )
        if cryptographic_decisive:
            reason = "cryptographic_decisive_evidence"
        elif not fresh:
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
            correlated_suppressed=sum(root.duplicate_count for root in roots),
            expired_evidence=expired,
            reason=reason,
            cryptographic_decisive=cryptographic_decisive,
        )


def effective_variant_record(config: ResearchConfig, variant_id: str) -> dict:
    if variant_id not in VARIANTS:
        raise ValueError(f"Unknown ablation variant: {variant_id}")
    effective = asdict(config)
    canonical = json.dumps(effective, sort_keys=True, separators=(",", ":"))
    descriptions = {
        "baseline": "Unwrapped production VPUFTQualificationEngine; no ablation.",
        "A_report_mass": (
            "Counterfactual: mass each fresh valid signed report separately; retain true root IDs "
            "and all diversity gates. Correlation suppression is weakened."
        ),
        "C_no_diversity_gates": (
            "Counterfactual: bypass roots/sources/zones/modalities gate only; preserve evidence "
            "aggregation, signatures, validity, freshness, weights, opposition, margin, and crypto rule."
        ),
    }
    return {
        "variant_id": variant_id,
        "effective_config": effective,
        "effective_config_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "adapter": "production_engine" if variant_id == "baseline" else "AblationQualificationAdapter",
        "adapter_mode": variant_id,
        "description": descriptions[variant_id],
        "security_status": (
            "production_baseline" if variant_id == "baseline" else SECURITY_STATUS
        ),
        "production_configuration_unchanged": True,
    }
