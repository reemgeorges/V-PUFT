from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WeightConfig:
    C: float = 0.20
    rho: float = 0.15
    F: float = 0.15
    Q: float = 0.20
    eta: float = 0.30

    def validate(self) -> None:
        values = asdict(self)
        if any(not 0.0 <= float(v) <= 1.0 for v in values.values()):
            raise ValueError("All V-PUFT exponents must be within [0, 1]")
        if abs(sum(values.values()) - 1.0) > 1e-9:
            raise ValueError("V-PUFT exponents must sum to 1")


@dataclass(frozen=True)
class AttackPolicy:
    required_roots: int
    required_sources: int
    required_zones: int
    required_modalities: int
    margin_threshold: float
    opposition_lambda: float = 1.0
    cryptographic_decisive: bool = False
    freshness_window_seconds: float = 15.0
    min_representative_weight: float = 0.05


@dataclass(frozen=True)
class NetworkConfig:
    base_latency_ms: float = 8.0
    jitter_ms: float = 3.0
    central_backhaul_extra_latency_ms: float = 0.0
    packet_delivery_ratio: float = 0.98
    max_retries: int = 2
    retry_backoff_ms: float = 5.0
    queue_rate_bytes_per_second: float = 2_000_000.0


@dataclass(frozen=True)
class PBFTConfig:
    validators: tuple[str, ...] = ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
    max_byzantine: int = 1
    timeout_ms: float = 120.0
    max_views: int = 4
    validator_behaviors: dict[str, str] = field(default_factory=dict)
    state_recovery_enabled: bool = True


@dataclass(frozen=True)
class CentralServerConfig:
    workers: int = 4
    service_time_ms: float = 12.0
    queue_capacity: int = 500
    availability: float = 0.995
    compromised: bool = False
    compromise_mode: str = "false_revocation"
    audit_replica_enabled: bool = True


@dataclass(frozen=True)
class DetectorConfig:
    rsu_range_m: float = 450.0
    witness_range_m: float = 180.0
    position_error_threshold_m: float = 20.0
    speed_error_threshold_mps: float = 5.0
    replay_max_age_seconds: float = 2.5
    flood_messages_per_second: int = 3
    false_denm_deceleration_threshold_mps2: float = -3.0
    benign_clean_confidence: float = 0.78
    freshness_tau_seconds: float = 12.0
    # Ground-truth-free runtime evidence-case window. This is deliberately
    # independent of attack schedules and defaults to the 15 s evidence freshness horizon.
    case_window_seconds: float = 15.0
    # Independent-observer sensor model used by the SUMO research harness.
    # SUMO truth is consumed only by the sensor-emulation layer to generate
    # noisy measurements; the detector never compares reports to oracle truth.
    rsu_position_sigma_m: float = 3.0
    witness_position_sigma_m: float = 5.0
    rsu_speed_sigma_mps: float = 0.6
    witness_speed_sigma_mps: float = 1.0
    rsu_acceleration_sigma_mps2: float = 0.4
    witness_acceleration_sigma_mps2: float = 0.8


@dataclass(frozen=True)
class SumoConfig:
    step_length_seconds: float = 1.0
    end_time_seconds: float = 95.0
    use_gui: bool = False
    sumo_binary: str | None = None
    netconvert_binary: str | None = None
    scenario_directory: str = "sumo/smoke"
    rsu_file: str = "rsus.json"
    attack_file: str = "attacks.json"
    deterministic_seed: int = 1001
    keep_sumo_output: bool = True


@dataclass(frozen=True)
class SecurityConfig:
    deterministic_master_seed: str = "vpuft-thesis-reproducible-keys-v1"
    compromised_rsus: tuple[str, ...] = ()
    compromised_witness_ratio: float = 0.10


@dataclass(frozen=True)
class SimulationConfig:
    seeds: tuple[int, ...] = tuple(range(1000, 1010))
    cases_per_seed: int = 60
    malicious_ratio: float = 0.30
    witness_count_mean: float = 4.0
    rsu_count: int = 6
    source: str = "synthetic"


@dataclass(frozen=True)
class ResearchConfig:
    weights: WeightConfig = field(default_factory=WeightConfig)
    policies: dict[str, AttackPolicy] = field(default_factory=lambda: {
        "position_offset": AttackPolicy(2, 2, 2, 1, 0.45),
        "speed_offset": AttackPolicy(2, 2, 1, 1, 0.45),
        "replay": AttackPolicy(1, 1, 1, 1, 0.35, cryptographic_decisive=True),
        "certificate_tamper": AttackPolicy(1, 1, 1, 1, 0.25, cryptographic_decisive=True),
        "flood": AttackPolicy(2, 2, 1, 1, 0.50),
        "false_denm": AttackPolicy(2, 2, 2, 1, 0.50),
        "mixed": AttackPolicy(2, 2, 2, 2, 0.55),
        "benign": AttackPolicy(2, 2, 1, 1, 0.50),
    })
    network: NetworkConfig = field(default_factory=NetworkConfig)
    pbft: PBFTConfig = field(default_factory=PBFTConfig)
    central: CentralServerConfig = field(default_factory=CentralServerConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    sumo: SumoConfig = field(default_factory=SumoConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)

    def validate(self) -> None:
        self.weights.validate()
        n = len(self.pbft.validators)
        f = self.pbft.max_byzantine
        if n < 3 * f + 1:
            raise ValueError(f"PBFT requires n >= 3f+1; got n={n}, f={f}")
        if len(set(self.pbft.validators)) != n:
            raise ValueError("PBFT validator identities must be unique")
        if not 0 < self.network.packet_delivery_ratio <= 1:
            raise ValueError("PDR must be in (0, 1]")
        if self.network.central_backhaul_extra_latency_ms < 0:
            raise ValueError("central_backhaul_extra_latency_ms cannot be negative")
        if self.network.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.central.workers < 1 or self.central.queue_capacity < 1:
            raise ValueError("Central workers and queue capacity must be positive")
        if not 0 <= self.simulation.malicious_ratio <= 1:
            raise ValueError("malicious_ratio must be within [0, 1]")
        if not 0 <= self.security.compromised_witness_ratio <= 1:
            raise ValueError("compromised_witness_ratio must be within [0, 1]")
        if self.sumo.step_length_seconds <= 0 or self.sumo.end_time_seconds <= 0:
            raise ValueError("SUMO step and end time must be positive")
        if self.detector.case_window_seconds <= 0:
            raise ValueError("Detector case_window_seconds must be positive")
        sensor_sigmas = (
            self.detector.rsu_position_sigma_m,
            self.detector.witness_position_sigma_m,
            self.detector.rsu_speed_sigma_mps,
            self.detector.witness_speed_sigma_mps,
            self.detector.rsu_acceleration_sigma_mps2,
            self.detector.witness_acceleration_sigma_mps2,
        )
        if any(value < 0 for value in sensor_sigmas):
            raise ValueError("Detector sensor-noise sigmas cannot be negative")
        for name, policy in self.policies.items():
            if min(policy.required_roots, policy.required_sources, policy.required_zones, policy.required_modalities) < 0:
                raise ValueError(f"Policy counts cannot be negative: {name}")
            if not 0 <= policy.margin_threshold <= 1:
                raise ValueError(f"Policy margin threshold must be within [0,1]: {name}")


def _coerce_attack_policy(raw: dict[str, Any]) -> AttackPolicy:
    return AttackPolicy(**raw)


def _section(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"Configuration section '{key}' must be an object")
    return value


def load_config(path: str | Path | None = None) -> ResearchConfig:
    if path is None:
        cfg = ResearchConfig()
        cfg.validate()
        return cfg

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    pbft_raw = _section(raw, "pbft")
    sim_raw = _section(raw, "simulation")
    sec_raw = _section(raw, "security")
    cfg = ResearchConfig(
        weights=WeightConfig(**_section(raw, "weights")),
        policies={k: _coerce_attack_policy(v) for k, v in _section(raw, "policies").items()} or ResearchConfig().policies,
        network=NetworkConfig(**_section(raw, "network")),
        pbft=PBFTConfig(
            validators=tuple(pbft_raw.get("validators", PBFTConfig().validators)),
            max_byzantine=pbft_raw.get("max_byzantine", PBFTConfig().max_byzantine),
            timeout_ms=pbft_raw.get("timeout_ms", PBFTConfig().timeout_ms),
            max_views=pbft_raw.get("max_views", PBFTConfig().max_views),
            validator_behaviors=pbft_raw.get("validator_behaviors", {}),
            state_recovery_enabled=pbft_raw.get("state_recovery_enabled", True),
        ),
        central=CentralServerConfig(**_section(raw, "central")),
        detector=DetectorConfig(**_section(raw, "detector")),
        sumo=SumoConfig(**_section(raw, "sumo")),
        security=SecurityConfig(
            deterministic_master_seed=sec_raw.get("deterministic_master_seed", SecurityConfig().deterministic_master_seed),
            compromised_rsus=tuple(sec_raw.get("compromised_rsus", [])),
            compromised_witness_ratio=sec_raw.get("compromised_witness_ratio", SecurityConfig().compromised_witness_ratio),
        ),
        simulation=SimulationConfig(
            seeds=tuple(sim_raw.get("seeds", SimulationConfig().seeds)),
            cases_per_seed=sim_raw.get("cases_per_seed", SimulationConfig().cases_per_seed),
            malicious_ratio=sim_raw.get("malicious_ratio", SimulationConfig().malicious_ratio),
            witness_count_mean=sim_raw.get("witness_count_mean", SimulationConfig().witness_count_mean),
            rsu_count=sim_raw.get("rsu_count", SimulationConfig().rsu_count),
            source=sim_raw.get("source", SimulationConfig().source),
        ),
    )
    cfg.validate()
    return cfg


def save_config(config: ResearchConfig, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
