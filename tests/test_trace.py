from pathlib import Path

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.simulation import generate_scenario
from vpuft.trace import build_trace_bundle, read_events_jsonl, write_events_jsonl


def test_trace_round_trip_is_deterministic(tmp_path: Path):
    cfg = ResearchConfig()
    keys = KeyRegistry(cfg.security.deterministic_master_seed)
    bundle = generate_scenario(cfg, keys, 1001)
    path = write_events_jsonl(bundle.events, tmp_path / "trace.jsonl")
    loaded = read_events_jsonl(path)
    assert loaded == bundle.events
    replay = build_trace_bundle(loaded, KeyRegistry(cfg.security.deterministic_master_seed))
    assert len(replay.rsu_cases) == len(bundle.rsu_cases)
    assert len(replay.witness_cases) == len(bundle.witness_cases)
