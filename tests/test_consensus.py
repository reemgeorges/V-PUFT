from vpuft.config import NetworkConfig, PBFTConfig
from vpuft.consensus import PBFTConsensus
from vpuft.crypto import KeyRegistry
from vpuft.network import SimulatedTransport


def test_pbft_commits_with_four_validators_and_f_one():
    keys = KeyRegistry()
    transport = SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), seed=1)
    pbft = PBFTConsensus(PBFTConfig(), transport, keys)
    outcome = pbft.finalize(case_id="c1", payload={"decision": "revoke"}, started_at=0.0)
    assert outcome.committed
    assert outcome.commit_votes >= 3


def test_pbft_view_change_when_first_leader_offline():
    keys = KeyRegistry()
    transport = SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), seed=2)
    cfg = PBFTConfig(validator_behaviors={"rsu-1": "offline"})
    outcome = PBFTConsensus(cfg, transport, keys).finalize(
        case_id="c2", payload={"decision": "revoke"}, started_at=0.0
    )
    assert outcome.committed
    assert outcome.view_changes >= 1
