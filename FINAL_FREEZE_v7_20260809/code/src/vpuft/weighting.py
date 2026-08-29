from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .config import WeightConfig
from .domain import EvidenceAttestation, EvidenceDirection


@dataclass(frozen=True)
class RootContribution:
    observation_root_id: str
    direction: EvidenceDirection
    weight: float
    supporting_weight: float
    opposing_weight: float
    representative: EvidenceAttestation
    duplicate_count: int


def _clip01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def evidence_weight(attestation: EvidenceAttestation, weights: WeightConfig, eps: float = 1e-12) -> float:
    """Weighted geometric mean. Attestation validity is a hard security gate."""
    if attestation.validity != 1:
        return 0.0
    factors = attestation.factors()
    exponents = {
        "C": weights.C,
        "rho": weights.rho,
        "F": weights.F,
        "Q": weights.Q,
        "eta": weights.eta,
    }
    log_weight = 0.0
    for name, exponent in exponents.items():
        factor = max(eps, _clip01(factors[name]))
        log_weight += exponent * math.log(factor)
    return float(math.exp(log_weight))


def aggregate_by_root(
    attestations: Iterable[EvidenceAttestation],
    weights: WeightConfig,
) -> list[RootContribution]:
    """
    Collapse all derived reports of one observation root into one net contribution.

    A root cannot be counted simultaneously as an independent supporting root and an
    independent opposing root. The strongest valid report in each direction is used,
    then the root contributes the absolute directional difference.
    """
    grouped: dict[str, list[EvidenceAttestation]] = defaultdict(list)
    for attestation in attestations:
        grouped[attestation.observation_root_id].append(attestation)

    result: list[RootContribution] = []
    for root_id, group in grouped.items():
        weighted = [(evidence_weight(item, weights), item) for item in group]
        support = [(weight, item) for weight, item in weighted if item.direction == EvidenceDirection.SUPPORTS]
        oppose = [(weight, item) for weight, item in weighted if item.direction == EvidenceDirection.OPPOSES]
        neutral = [(weight, item) for weight, item in weighted if item.direction == EvidenceDirection.NEUTRAL]
        best_support = max(support, default=(0.0, None), key=lambda pair: (pair[0], pair[1].attestation_id if pair[1] else ""))
        best_oppose = max(oppose, default=(0.0, None), key=lambda pair: (pair[0], pair[1].attestation_id if pair[1] else ""))
        support_weight, support_item = best_support
        oppose_weight, oppose_item = best_oppose
        net = support_weight - oppose_weight
        if net > 1e-12:
            direction = EvidenceDirection.SUPPORTS
            representative = support_item
        elif net < -1e-12:
            direction = EvidenceDirection.OPPOSES
            representative = oppose_item
        else:
            direction = EvidenceDirection.NEUTRAL
            candidates = [pair for pair in weighted if pair[1] is not None]
            representative = max(candidates, key=lambda pair: (pair[0], pair[1].attestation_id))[1] if candidates else neutral[0][1]
        if representative is None:
            continue
        result.append(
            RootContribution(
                observation_root_id=root_id,
                direction=direction,
                weight=abs(net),
                supporting_weight=support_weight,
                opposing_weight=oppose_weight,
                representative=representative,
                duplicate_count=max(0, len(group) - 1),
            )
        )
    return sorted(result, key=lambda item: item.observation_root_id)


def noisy_or(values: Iterable[float]) -> float:
    product = 1.0
    any_value = False
    for value in values:
        any_value = True
        product *= 1.0 - _clip01(value)
    return 0.0 if not any_value else 1.0 - product


def evidence_mass(values: Iterable[float], eps: float = 1e-12) -> float:
    """Additive log-evidence mass that does not saturate at one.

    Each bounded root weight w contributes -log(1-w). This is the additive
    quantity hidden underneath noisy-OR and therefore preserves the relative
    amount of supporting versus opposing evidence when many roots are present.
    """
    total = 0.0
    for value in values:
        clipped = min(1.0 - eps, max(0.0, float(value)))
        total += -math.log1p(-clipped)
    return total


def case_evidence_masses(
    attestations: Iterable[EvidenceAttestation],
    weights: WeightConfig,
) -> tuple[float, float, list[RootContribution]]:
    roots = aggregate_by_root(attestations, weights)
    positive_mass = evidence_mass(root.weight for root in roots if root.direction == EvidenceDirection.SUPPORTS)
    negative_mass = evidence_mass(root.weight for root in roots if root.direction == EvidenceDirection.OPPOSES)
    return positive_mass, negative_mass, roots


def regularized_strengths(positive_mass: float, negative_mass: float, opposition_lambda: float = 1.0) -> tuple[float, float, float]:
    """Return bounded support/opposition strengths and their signed margin.

    The +1 regularizer prevents a single weak root from looking maximally
    decisive, while the mass ratio prevents the independent support and
    opposition channels from both saturating to 1.
    """
    lam = max(0.0, float(opposition_lambda))
    denom = 1.0 + positive_mass + lam * negative_mass
    supporting = positive_mass / denom
    opposing = negative_mass / denom
    margin = supporting - lam * opposing
    return supporting, opposing, margin


def case_strengths(
    attestations: Iterable[EvidenceAttestation],
    weights: WeightConfig,
) -> tuple[float, float, list[RootContribution]]:
    positive_mass, negative_mass, roots = case_evidence_masses(attestations, weights)
    positive, negative, _ = regularized_strengths(positive_mass, negative_mass, 1.0)
    return positive, negative, roots
