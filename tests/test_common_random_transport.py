from dataclasses import replace

from vpuft.config import NetworkConfig
from vpuft.network import SimulatedTransport


def _signature(message):
    return (
        message.dropped,
        None if message.delivered_at is None else round(message.delivered_at - message.sent_at, 9),
        message.retransmission,
    )


def test_keyed_evidence_draw_is_independent_of_unrelated_send_order():
    config = NetworkConfig(
        packet_delivery_ratio=0.73,
        max_retries=2,
        evidence_crn_seed=1001,
    )
    first = SimulatedTransport(config, seed=11)
    expected = first.send(
        message_type="ATTESTATION_TO_SERVER",
        sender="rsu-2",
        receiver="central-server",
        case_id="case-1",
        sent_at=2.0,
        size_bytes=704,
        random_key="evidence-attestation:att-9",
    )

    second = SimulatedTransport(config, seed=99)
    second.send(
        message_type="UNRELATED",
        sender="rsu-4",
        receiver="rsu-3",
        case_id="other",
        sent_at=0.0,
        size_bytes=352,
    )
    observed = second.send(
        message_type="RSU_EVIDENCE_EXCHANGE",
        sender="rsu-2",
        receiver="rsu-1",
        case_id="case-1",
        sent_at=2.0,
        size_bytes=704,
        random_key="evidence-attestation:att-9",
    )

    # Loss, jitter and retry count are paired. Queueing and receiver-specific
    # backhaul remain architectural properties and are intentionally not paired.
    assert expected.dropped == observed.dropped
    assert expected.retransmission == observed.retransmission
    if expected.delivered_at is not None:
        central_backhaul = config.central_backhaul_extra_latency_ms / 1000.0
        expected_network = expected.delivered_at - expected.sent_at - central_backhaul
        observed_network = observed.delivered_at - observed.sent_at
        assert round(expected_network, 9) == round(observed_network, 9)


def test_keyed_draw_is_opt_in_and_default_config_is_unchanged():
    base = NetworkConfig(packet_delivery_ratio=0.98)
    assert base.evidence_crn_seed is None
    paired = replace(base, evidence_crn_seed=7)
    assert paired.evidence_crn_seed == 7
