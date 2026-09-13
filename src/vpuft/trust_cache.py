from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from math import hypot
from typing import Mapping

import numpy as np

from .config import ResearchConfig
from .crypto import KeyRegistry
from .domain import TrustDecision, TrustState
from .network import SimulatedTransport


@dataclass(frozen=True, slots=True)
class QuorumTrustToken:
    subject_pseudonym: str
    trust_state: TrustState
    issued_at: float
    expires_at: float
    ledger_height: int
    checkpoint_hash: str
    decision_id: str
    signatures: Mapping[str, str] = field(default_factory=dict)


def token_payload(token: QuorumTrustToken) -> dict:
    data = asdict(token)
    data.pop("signatures", None)
    data["trust_state"] = token.trust_state.value
    return data


class QuorumTrustTokenService:
    def __init__(self, config: ResearchConfig, keys: KeyRegistry) -> None:
        self.config = config
        self.keys = keys

    @property
    def quorum(self) -> int:
        return 2 * self.config.pbft.max_byzantine + 1

    def issue(
        self,
        *,
        subject_pseudonym: str,
        state: TrustState,
        issued_at: float,
        ttl_seconds: float,
        ledger_height: int,
        checkpoint_hash: str,
        decision_id: str,
    ) -> QuorumTrustToken:
        unsigned = QuorumTrustToken(
            subject_pseudonym=subject_pseudonym,
            trust_state=state,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            ledger_height=ledger_height,
            checkpoint_hash=checkpoint_hash,
            decision_id=decision_id,
        )
        payload = token_payload(unsigned)
        signatures = {
            validator: self.keys.sign(validator, payload)
            for validator in self.config.pbft.validators[: self.quorum]
        }
        return QuorumTrustToken(**{**payload, "trust_state": state, "signatures": signatures})

    def verify(self, token: QuorumTrustToken, *, now: float, minimum_ledger_height: int) -> bool:
        if now > token.expires_at or token.ledger_height < minimum_ledger_height:
            return False
        payload = token_payload(token)
        valid_signers = {
            signer for signer, signature in token.signatures.items()
            if signer in self.config.pbft.validators and self.keys.verify(signer, payload, signature)
        }
        return len(valid_signers) >= self.quorum


class VehicleTrustCache:
    def __init__(self) -> None:
        self._tokens: dict[str, QuorumTrustToken] = {}

    def get(self, subject_pseudonym: str) -> QuorumTrustToken | None:
        return self._tokens.get(subject_pseudonym)

    def put(self, token: QuorumTrustToken) -> None:
        self._tokens[token.subject_pseudonym] = token

    def invalidate(self, subject_pseudonym: str) -> None:
        self._tokens.pop(subject_pseudonym, None)

    def __len__(self) -> int:
        return len(self._tokens)


def _checkpoint(height: int) -> str:
    return sha256(f"extension-ledger-height:{height}".encode("utf-8")).hexdigest()


def simulate_v2v_trust_cache(
    config: ResearchConfig,
    *,
    seed: int,
    vehicle_count: int,
    ttl_seconds: float,
) -> dict[str, float | int]:
    """Controlled V2V authorization experiment.

    This measures the light-cache layer only.  It deliberately does not claim
    radio-accurate V2V mobility or replace semantic anomaly detection.
    """

    rng = random.Random(seed * 1009 + vehicle_count * 17 + int(ttl_seconds * 1000))
    keys = KeyRegistry(config.security.deterministic_master_seed)
    service = QuorumTrustTokenService(config, keys)
    transport = SimulatedTransport(config.network, seed + 991)
    vehicles = [f"veh-{index:04d}" for index in range(vehicle_count)]
    pseudonyms = {vehicle: f"ps-{sha256(vehicle.encode()).hexdigest()[:20]}" for vehicle in vehicles}
    caches = {vehicle: VehicleTrustCache() for vehicle in vehicles}
    revocation_count = max(1, round(vehicle_count * config.trust_cache.revocation_ratio))
    revoked_subjects = set(rng.sample(vehicles, revocation_count))
    total_interactions = vehicle_count * config.trust_cache.interactions_per_vehicle
    revocation_time = total_interactions * config.trust_cache.interaction_interval_seconds / 2.0
    ledger_height = 0
    cache_hits = cache_misses = queries = query_failures = 0
    stale_accepts = accepted = rejected = escalations = 0
    auth_latencies_ms: list[float] = []
    peak_cache_entries = 0

    for index in range(total_interactions):
        now = index * config.trust_cache.interaction_interval_seconds
        requester_index = rng.randrange(vehicle_count)
        requester = vehicles[requester_index]
        # Vehicles remain near a small moving neighbourhood for several
        # interactions, which creates repeat V2V contacts without claiming an
        # exact radio/mobility trace.
        neighbour_offset = 1 + rng.randrange(min(3, vehicle_count - 1))
        subject = vehicles[(requester_index + neighbour_offset) % vehicle_count]
        subject_revoked = subject in revoked_subjects and now >= revocation_time
        current_state = TrustState.REVOKED if subject_revoked else TrustState.TRUSTED
        current_height = 1 if now >= revocation_time else 0
        ledger_height = max(ledger_height, current_height)
        anomaly = rng.random() < config.trust_cache.anomaly_ratio
        token = caches[requester].get(pseudonyms[subject])
        cache_valid = token is not None and service.verify(
            token,
            now=now,
            # A vehicle may not yet know the newest ledger height. TTL bounds
            # this deliberate stale-state window; anomaly signals force refresh.
            minimum_ledger_height=token.ledger_height,
        )

        if cache_valid and not anomaly:
            cache_hits += 1
            auth_latencies_ms.append(config.trust_cache.local_verification_ms)
            if token.trust_state == TrustState.TRUSTED:
                accepted += 1
                if subject_revoked:
                    stale_accepts += 1
            else:
                rejected += 1
            continue

        cache_misses += 1
        if anomaly:
            escalations += 1
            caches[requester].invalidate(pseudonyms[subject])
        queries += 1
        # Any of the six roadside units can answer from its read-only ledger
        # cache. The token itself still carries a PBFT validator quorum, so a
        # non-validator RSU cannot manufacture trust.
        rsu_nodes = tuple(f"rsu-{i}" for i in range(1, config.simulation.rsu_count + 1))
        rsu = rsu_nodes[index % len(rsu_nodes)]
        request = transport.send(
            message_type="V2I_TRUST_QUERY",
            sender=requester,
            receiver=rsu,
            case_id=f"v2v-{seed}-{vehicle_count}-{index}",
            sent_at=now,
            size_bytes=config.trust_cache.query_bytes,
        )
        if request.delivered_at is None:
            query_failures += 1
            rejected += 1
            continue
        issued = service.issue(
            subject_pseudonym=pseudonyms[subject],
            state=current_state,
            issued_at=request.delivered_at,
            ttl_seconds=ttl_seconds,
            ledger_height=ledger_height,
            checkpoint_hash=_checkpoint(ledger_height),
            decision_id=f"trust-status-{subject}-{ledger_height}",
        )
        response = transport.send(
            message_type="V2I_QUORUM_TRUST_TOKEN",
            sender=rsu,
            receiver=requester,
            case_id=f"v2v-{seed}-{vehicle_count}-{index}",
            sent_at=request.delivered_at,
            size_bytes=config.trust_cache.token_response_bytes,
        )
        if response.delivered_at is None:
            query_failures += 1
            rejected += 1
            continue
        caches[requester].put(issued)
        peak_cache_entries = max(peak_cache_entries, sum(len(cache) for cache in caches.values()))
        auth_latencies_ms.append((response.delivered_at - now) * 1000.0)
        if anomaly:
            rejected += 1
        elif issued.trust_state == TrustState.TRUSTED:
            accepted += 1
        else:
            rejected += 1

    percentile = lambda values, q: float(np.percentile(values, q)) if values else float("nan")
    total_bytes = sum(message.size_bytes for message in transport.messages)
    return {
        "seed": seed,
        "vehicle_count": vehicle_count,
        "ttl_seconds": ttl_seconds,
        "interactions": total_interactions,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_hit_rate": cache_hits / total_interactions,
        "v2i_queries": queries,
        "v2i_queries_avoided": cache_hits,
        "query_failures": query_failures,
        "accepted": accepted,
        "rejected": rejected,
        "anomaly_escalations": escalations,
        "stale_trust_acceptances": stale_accepts,
        "stale_acceptance_rate": stale_accepts / max(1, total_interactions),
        "authorization_latency_mean_ms": float(np.mean(auth_latencies_ms)) if auth_latencies_ms else float("nan"),
        "authorization_latency_p95_ms": percentile(auth_latencies_ms, 95),
        "messages_total": len(transport.messages),
        "bytes_total": sum(message.size_bytes for message in transport.messages),
        "cache_entries_final": sum(len(cache) for cache in caches.values()),
        "cache_entries_peak": peak_cache_entries,
    }


def simulate_topology_v2v_trust_cache(
    config: ResearchConfig,
    *,
    seed: int,
    topology: str,
    requested_vehicle_count: int,
    ttl_seconds: float,
    mobility_rows: list[Mapping[str, object]],
    decisions: list[TrustDecision],
    rsus: list[Mapping[str, object]],
) -> dict[str, float | int | str]:
    """Replay light-client authorization over contacts observed by SUMO.

    One nearest in-range neighbour is selected per requester and sampled SUMO
    instant.  Trust state comes from decisions already committed by the honest
    distributed run, so density, topology and revocation timing are no longer
    synthetic labels detached from the mobility trace.
    """

    grouped: dict[float, list[Mapping[str, object]]] = defaultdict(list)
    period = config.density_campaign.v2v_sample_period_seconds
    for row in mobility_rows:
        timestamp = float(row["simulation_time"])
        bucket = round(timestamp / period) * period
        if abs(timestamp - bucket) <= 1e-6:
            grouped[timestamp].append(row)

    vehicle_ids = sorted({str(row["vehicle_id"]) for row in mobility_rows})
    pseudonyms = {
        vehicle: f"ps-{sha256(f'{topology}|{vehicle}'.encode()).hexdigest()[:20]}"
        for vehicle in vehicle_ids
    }
    caches = {vehicle: VehicleTrustCache() for vehicle in vehicle_ids}
    service = QuorumTrustTokenService(
        config, KeyRegistry(config.security.deterministic_master_seed)
    )
    transport = SimulatedTransport(config.network, seed + 19091 + int(ttl_seconds * 1000))
    rng = random.Random(
        seed * 1009
        + requested_vehicle_count * 17
        + int(ttl_seconds * 1000)
        + int(sha256(topology.encode()).hexdigest()[:8], 16)
    )

    committed = sorted(
        (
            decision for decision in decisions
            if decision.committed and decision.finalized_at is not None
        ),
        key=lambda decision: (float(decision.finalized_at), decision.case_id),
    )
    decision_cursor = 0
    ledger_height = 0
    states: dict[str, TrustState] = {}
    cache_hits = cache_misses = queries = query_failures = 0
    stale_accepts = accepted = rejected = escalations = 0
    auth_latencies_ms: list[float] = []
    peak_cache_entries = 0
    interactions = 0
    active_counts: list[int] = []

    def nearest_rsu_id(row: Mapping[str, object]) -> str:
        if not rsus:
            return "rsu-1"
        x, y = float(row["x"]), float(row["y"])
        nearest = min(
            rsus,
            key=lambda rsu: (
                hypot(x - float(rsu["x"]), y - float(rsu["y"])),
                str(rsu["id"]),
            ),
        )
        return str(nearest["id"])

    for now, snapshots in sorted(grouped.items()):
        active_counts.append(len(snapshots))
        while decision_cursor < len(committed) and float(committed[decision_cursor].finalized_at) <= now:
            decision = committed[decision_cursor]
            ledger_height += 1
            states[decision.vehicle_id] = decision.new_state
            decision_cursor += 1

        ordered = sorted(snapshots, key=lambda row: str(row["vehicle_id"]))
        for requester_row in ordered:
            requester = str(requester_row["vehicle_id"])
            candidates = []
            for subject_row in ordered:
                subject = str(subject_row["vehicle_id"])
                if subject == requester:
                    continue
                distance = hypot(
                    float(requester_row["x"]) - float(subject_row["x"]),
                    float(requester_row["y"]) - float(subject_row["y"]),
                )
                if distance <= config.density_campaign.v2v_range_m:
                    candidates.append((distance, subject, subject_row))
            if not candidates:
                continue
            _, subject, _subject_row = min(candidates, key=lambda item: (item[0], item[1]))
            interactions += 1
            subject_state = states.get(subject, TrustState.TRUSTED)
            anomaly = rng.random() < config.trust_cache.anomaly_ratio
            token = caches[requester].get(pseudonyms[subject])
            cache_valid = token is not None and service.verify(
                token,
                now=now,
                # The vehicle knows the checkpoint carried by its token. TTL
                # bounds the period before it must refresh from an RSU.
                minimum_ledger_height=token.ledger_height,
            )
            if cache_valid and not anomaly:
                cache_hits += 1
                auth_latencies_ms.append(config.trust_cache.local_verification_ms)
                if token.trust_state == TrustState.TRUSTED:
                    accepted += 1
                    if subject_state == TrustState.REVOKED:
                        stale_accepts += 1
                else:
                    rejected += 1
                continue

            cache_misses += 1
            if anomaly:
                escalations += 1
                caches[requester].invalidate(pseudonyms[subject])
            queries += 1
            case_id = f"density-v2v-{topology}-{seed}-{requested_vehicle_count}-{interactions}"
            rsu_id = nearest_rsu_id(requester_row)
            request = transport.send(
                message_type="V2I_TRUST_QUERY",
                sender=requester,
                receiver=rsu_id,
                case_id=case_id,
                sent_at=now,
                size_bytes=config.trust_cache.query_bytes,
            )
            if request.delivered_at is None:
                query_failures += 1
                rejected += 1
                continue
            issued = service.issue(
                subject_pseudonym=pseudonyms[subject],
                state=subject_state,
                issued_at=request.delivered_at,
                ttl_seconds=ttl_seconds,
                ledger_height=ledger_height,
                checkpoint_hash=_checkpoint(ledger_height),
                decision_id=f"density-trust-{subject}-{ledger_height}",
            )
            response = transport.send(
                message_type="V2I_QUORUM_TRUST_TOKEN",
                sender=rsu_id,
                receiver=requester,
                case_id=case_id,
                sent_at=request.delivered_at,
                size_bytes=config.trust_cache.token_response_bytes,
            )
            if response.delivered_at is None:
                query_failures += 1
                rejected += 1
                continue
            caches[requester].put(issued)
            peak_cache_entries = max(
                peak_cache_entries, sum(len(cache) for cache in caches.values())
            )
            auth_latencies_ms.append((response.delivered_at - now) * 1000.0)
            if anomaly:
                rejected += 1
            elif issued.trust_state == TrustState.TRUSTED:
                accepted += 1
            else:
                rejected += 1

    percentile = lambda values, q: float(np.percentile(values, q)) if values else float("nan")
    total_bytes = sum(message.size_bytes for message in transport.messages)
    return {
        "topology": topology,
        "seed": seed,
        "requested_vehicle_count": requested_vehicle_count,
        "observed_vehicle_count": len(vehicle_ids),
        "ttl_seconds": ttl_seconds,
        "interactions": interactions,
        "mean_active_vehicles": float(np.mean(active_counts)) if active_counts else 0.0,
        "peak_active_vehicles": max(active_counts, default=0),
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_hit_rate": cache_hits / max(1, interactions),
        "v2i_queries": queries,
        "v2i_queries_avoided": cache_hits,
        "query_failures": query_failures,
        "accepted": accepted,
        "rejected": rejected,
        "anomaly_escalations": escalations,
        "stale_trust_acceptances": stale_accepts,
        "stale_acceptance_rate": stale_accepts / max(1, interactions),
        "authorization_latency_mean_ms": (
            float(np.mean(auth_latencies_ms)) if auth_latencies_ms else float("nan")
        ),
        "authorization_latency_p95_ms": percentile(auth_latencies_ms, 95),
        "messages_total": len(transport.messages),
        "messages_per_interaction": len(transport.messages) / max(1, interactions),
        "bytes_total": total_bytes,
        "bytes_per_interaction": total_bytes / max(1, interactions),
        "cache_entries_final": sum(len(cache) for cache in caches.values()),
        "cache_entries_peak": peak_cache_entries,
    }
