from dataclasses import asdict, replace

from vpuft.architectures.centralized import CentralizedVPUFT
from vpuft.architectures.distributed_extension import DistributedRSUExtendedVPUFT
from vpuft.config import CentralServerConfig, NetworkConfig, ResearchConfig, WeightConfig
from vpuft.crypto import KeyRegistry
from vpuft.des import Scheduler
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.network import SimulatedTransport, audit_link_order


FROZEN = WeightConfig(
    C=0.3652673861753211,
    rho=0.16195260151983162,
    F=0.06370517641034751,
    Q=0.40608957775126925,
    eta=0.0029852581432305157,
)


def _config(**network_overrides):
    network = NetworkConfig(
        packet_delivery_ratio=1.0,
        jitter_ms=0.0,
        max_retries=0,
        **network_overrides,
    )
    return ResearchConfig(
        weights=FROZEN,
        network=network,
        central=CentralServerConfig(availability=1.0, queue_capacity=1000),
    )


def _attestation(keys, case_id, root, rsu, t, confidence=0.95):
    unsigned = EvidenceAttestation(
        attestation_id=f"att-{case_id}-{root}-{rsu}",
        case_id=case_id,
        observation_root_id=root,
        source_id=rsu,
        source_kind="rsu",
        validator_rsu_id=rsu,
        administrative_domain_id=f"domain-{rsu}",
        sensor_modality="rsu_cam_plausibility",
        geographic_cell=f"cell-{rsu}",
        attack_type=AttackType.SPEED_OFFSET,
        direction=EvidenceDirection.SUPPORTS,
        detector_confidence=confidence,
        source_reliability=0.95,
        freshness=1.0,
        verifiability=0.86,
        independence=0.9,
        observed_at=float(t),
        evidence_hash=f"hash-{root}",
        signature="",
        public_key_id="",
        validity=1,
        reason_codes=("speed_inconsistency",),
    )
    return sign_attestation(unsigned, keys, rsu)


def _case(keys, vehicle, plan, confidence=0.95):
    case_id = f"case-demo-1-{vehicle}-w0000"
    case = EvidenceCase(
        case_id=case_id,
        vehicle_id=vehicle,
        pseudonym=vehicle,
        attack_type=AttackType.SPEED_OFFSET,
        opened_at=0.0,
        ground_truth_malicious=True,
    )
    for index, (t, rsu) in enumerate(plan):
        case.add(_attestation(keys, case_id, f"root-{vehicle}-{index}", rsu, t, confidence))
    return case


def test_async_transport_orders_requests_by_simulation_time_not_call_order():
    scheduler = Scheduler()
    transport = SimulatedTransport(_config().network, 1, scheduler=scheduler)
    done = []
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="future",
        sent_at=14.0, size_bytes=704, random_key="future", on_complete=lambda m, t: done.append((m, t)),
    )
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="early",
        sent_at=0.0, size_bytes=704, random_key="early", on_complete=lambda m, t: done.append((m, t)),
    )
    scheduler.run()
    assert [m.sent_at for m in transport.messages] == [0.0, 14.0]
    assert all(m.queue_delay_ms == 0.0 for m in transport.messages)
    assert audit_link_order(transport.messages)["temporal_inversions"] == 0


def test_async_transport_serializes_only_true_same_link_overlap():
    scheduler = Scheduler()
    config = _config().network
    transport = SimulatedTransport(config, 1, scheduler=scheduler)
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="1",
        sent_at=0.0, size_bytes=704, random_key="1", on_complete=lambda _m, _t: None,
    )
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="2",
        sent_at=0.0001, size_bytes=704, random_key="2", on_complete=lambda _m, _t: None,
    )
    transport.send_async(
        message_type="X", sender="a", receiver="c", case_id="3",
        sent_at=0.0001, size_bytes=704, random_key="3", on_complete=lambda _m, _t: None,
    )
    scheduler.run()
    by_case = {m.case_id: m for m in transport.messages}
    serialization = 704 / config.queue_rate_bytes_per_second
    assert abs(by_case["2"].queue_delay_ms / 1000.0 - (serialization - 0.0001)) < 1e-12
    assert by_case["3"].queue_delay_ms == 0.0
    audit = audit_link_order(transport.messages, config.queue_rate_bytes_per_second)
    assert audit["temporal_inversions"] == 0
    assert audit["serialization_overlaps"] == 0


def test_async_retry_does_not_reserve_future_link_capacity_eagerly():
    class Draw:
        def __init__(self, value):
            self.value = value
        def random(self):
            return self.value
        def gauss(self, mu, sigma):
            return mu

    class ScriptedTransport(SimulatedTransport):
        def _keyed_rng(self, *, random_key, attempt, random_stream_seed=None):
            if random_key == "first" and attempt == 0:
                return Draw(0.999)
            return Draw(0.0)

    scheduler = Scheduler()
    cfg = NetworkConfig(packet_delivery_ratio=0.98, jitter_ms=0.0, max_retries=1)
    transport = ScriptedTransport(cfg, 1, scheduler=scheduler)
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="1",
        sent_at=14.0, size_bytes=704, random_key="first", on_complete=lambda _m, _t: None,
    )
    transport.send_async(
        message_type="X", sender="a", receiver="b", case_id="2",
        sent_at=14.001, size_bytes=704, random_key="second", on_complete=lambda _m, _t: None,
    )
    scheduler.run()
    assert [(m.case_id, m.retransmission) for m in transport.messages] == [("1", 0), ("2", 0), ("1", 1)]
    assert transport.messages[1].queue_delay_ms == 0.0
    assert audit_link_order(transport.messages, cfg.queue_rate_bytes_per_second)["temporal_inversions"] == 0


def test_keyed_async_draws_do_not_depend_on_submission_order():
    cfg = NetworkConfig(packet_delivery_ratio=0.73, max_retries=2)

    def run(order):
        scheduler = Scheduler()
        transport = SimulatedTransport(cfg, 99, scheduler=scheduler)
        for name in order:
            transport.send_async(
                message_type="X", sender="a", receiver=f"r-{name}", case_id=name,
                sent_at=0.0, size_bytes=704, random_key=f"logical-{name}", random_stream_seed=1001,
                on_complete=lambda _m, _t: None,
            )
        scheduler.run()
        out = {}
        for name in ("m1", "m2", "m3"):
            attempts = [m for m in transport.messages if m.case_id == name]
            final = attempts[-1]
            if final.delivered_at is None:
                propagation = None
            else:
                start = final.sent_at + final.queue_delay_ms / 1000.0
                serialization = final.size_bytes / cfg.queue_rate_bytes_per_second
                propagation = round(final.delivered_at - start - serialization, 12)
            out[name] = (final.dropped, final.retransmission, propagation)
        return out

    assert run(["m1", "m2", "m3"]) == run(["m3", "m2", "m1"])


def test_overlapping_unrelated_cases_do_not_expire_target_evidence():
    keys = KeyRegistry()
    cfg = _config()
    heavy = [
        _case(keys, f"veh_a{i:02d}", [(round(0.1 * k, 1), "rsu-1" if k % 2 == 0 else "rsu-3") for k in range(140)], 0.9)
        for i in range(25)
    ]
    target = _case(keys, "veh_zz", [(0.0, "rsu-2"), (2.0, "rsu-1")], 0.95)
    alone = DistributedRSUExtendedVPUFT(cfg, keys).run([target], 1)
    crowded = DistributedRSUExtendedVPUFT(cfg, keys).run([*heavy, target], 1)
    da = next(d for d in alone.decisions if d.vehicle_id == "veh_zz")
    dc = next(d for d in crowded.decisions if d.vehicle_id == "veh_zz")
    assert (da.committed, da.new_state, da.reason) == (dc.committed, dc.new_state, dc.reason)
    assert da.committed is True
    assert dc.metadata["expired_evidence"] == 0
    audit = crowded.extension_metrics["transport_audit"]
    assert audit["temporal_inversions"] == 0


def test_central_worker_pool_uses_case_ready_time_not_python_case_order():
    keys = KeyRegistry()
    cfg = _config()
    cases = [
        _case(keys, f"veh_{v}", [(t, "rsu-1" if t % 2 else "rsu-2") for t in range(15)], 0.8)
        for v in "abcd"
    ]
    cases.append(_case(keys, "veh_e", [(0, "rsu-2"), (1, "rsu-1")], 0.8))
    result = CentralizedVPUFT(cfg, keys).run(cases, 1)
    decision = next(d for d in result.decisions if d.vehicle_id == "veh_e")
    assert decision.reason != "central_queue_overflow"
    assert decision.metadata["queue_wait_ms"] == 0.0
    assert result.extension_metrics["transport_audit"]["temporal_inversions"] == 0


def test_c100_adds_exactly_100ms_to_c0_on_fixed_case():
    keys = KeyRegistry()
    case = _case(keys, "veh", [(0.0, "rsu-1"), (2.0, "rsu-2")])
    c0 = CentralizedVPUFT(_config(central_backhaul_extra_latency_ms=0.0), keys).run([case], 1001)
    c100 = CentralizedVPUFT(_config(central_backhaul_extra_latency_ms=100.0), keys).run([case], 1001)
    d0, d100 = c0.decisions[0], c100.decisions[0]
    assert d0.committed == d100.committed
    assert abs((d100.finalized_at - d0.finalized_at) - 0.100) < 1e-12


def test_pbft_phases_are_causally_ordered_and_run_is_deterministic():
    keys = KeyRegistry()
    cfg = _config()
    case = _case(keys, "veh", [(0.0, "rsu-1"), (2.0, "rsu-2"), (2.1, "rsu-3")])
    first = DistributedRSUExtendedVPUFT(cfg, keys).run([case], 1001)
    second = DistributedRSUExtendedVPUFT(cfg, keys).run([case], 1001)

    pbft_messages = [m for m in first.messages if m.message_type in {"PRE_PREPARE", "PREPARE", "COMMIT"}]
    pre = [m for m in pbft_messages if m.message_type == "PRE_PREPARE"]
    prepare = [m for m in pbft_messages if m.message_type == "PREPARE"]
    commit = [m for m in pbft_messages if m.message_type == "COMMIT"]
    assert pre and prepare and commit
    assert min(m.sent_at for m in prepare) >= max(m.delivered_at for m in pre if m.delivered_at is not None)
    assert min(m.sent_at for m in commit) >= max(m.delivered_at for m in prepare if m.delivered_at is not None)
    assert first.ledger_consistent
    assert first.extension_metrics["transport_audit"]["temporal_inversions"] == 0

    assert [asdict(m) for m in first.messages] == [asdict(m) for m in second.messages]
    assert [asdict(d) for d in first.decisions] == [asdict(d) for d in second.decisions]
    assert [asdict(o) for o in first.consensus] == [asdict(o) for o in second.consensus]
