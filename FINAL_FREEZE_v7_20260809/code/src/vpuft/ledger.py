from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(frozen=True)
class Block:
    index: int
    previous_hash: str
    timestamp: float
    case_id: str
    payload: dict[str, Any]
    block_hash: str


class Ledger:
    def __init__(self) -> None:
        self.blocks: list[Block] = []

    @staticmethod
    def _hash(index: int, previous_hash: str, timestamp: float, case_id: str, payload: dict[str, Any]) -> str:
        raw = json.dumps(
            {"index": index, "previous_hash": previous_hash, "timestamp": timestamp, "case_id": case_id, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return sha256(raw).hexdigest()

    def append(self, case_id: str, payload: dict[str, Any], timestamp: float) -> Block:
        index = len(self.blocks)
        previous_hash = self.blocks[-1].block_hash if self.blocks else "GENESIS"
        block_hash = self._hash(index, previous_hash, timestamp, case_id, payload)
        block = Block(index, previous_hash, timestamp, case_id, payload, block_hash)
        self.blocks.append(block)
        return block

    def validate(self) -> bool:
        for idx, block in enumerate(self.blocks):
            expected_prev = self.blocks[idx - 1].block_hash if idx > 0 else "GENESIS"
            if block.index != idx or block.previous_hash != expected_prev:
                return False
            if block.block_hash != self._hash(block.index, block.previous_hash, block.timestamp, block.case_id, block.payload):
                return False
        return True

    def copy_from(self, other: "Ledger") -> None:
        candidate = Ledger()
        candidate.blocks = list(other.blocks)
        if not candidate.validate():
            raise ValueError("Refusing to copy invalid ledger")
        self.blocks = list(candidate.blocks)

    def recover_from(self, peers: list["Ledger"]) -> bool:
        valid = [peer for peer in peers if peer.validate()]
        if not valid:
            return False
        best = max(valid, key=lambda ledger: len(ledger.blocks))
        self.copy_from(best)
        return True

    def estimated_storage_bytes(self) -> int:
        return sum(len(json.dumps(asdict(block), sort_keys=True, default=str).encode("utf-8")) for block in self.blocks)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [asdict(block) for block in self.blocks]
