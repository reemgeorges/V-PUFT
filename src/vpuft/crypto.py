from __future__ import annotations

import base64
import json
from dataclasses import asdict, is_dataclass
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical_json(value: Any) -> bytes:
    if is_dataclass(value):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def digest_hex(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


class KeyRegistry:
    """Deterministic Ed25519 registry for reproducible experiments and trace replay."""

    def __init__(self, master_seed: str = "vpuft-thesis-reproducible-keys-v1") -> None:
        self.master_seed = master_seed
        self._private: dict[str, Ed25519PrivateKey] = {}
        self._public: dict[str, Ed25519PublicKey] = {}

    def _derive_seed(self, identity: str) -> bytes:
        return sha256(f"{self.master_seed}|{identity}".encode("utf-8")).digest()[:32]

    def ensure_identity(self, identity: str) -> str:
        if identity not in self._private:
            private = Ed25519PrivateKey.from_private_bytes(self._derive_seed(identity))
            self._private[identity] = private
            self._public[identity] = private.public_key()
        return identity

    def sign(self, identity: str, payload: Any) -> str:
        self.ensure_identity(identity)
        signature = self._private[identity].sign(canonical_json(payload))
        return base64.b64encode(signature).decode("ascii")

    def verify(self, identity: str, payload: Any, signature: str) -> bool:
        self.ensure_identity(identity)
        public = self._public.get(identity)
        if public is None:
            return False
        try:
            public.verify(base64.b64decode(signature), canonical_json(payload))
            return True
        except Exception:
            return False

    def public_key_b64(self, identity: str) -> str:
        self.ensure_identity(identity)
        raw = self._public[identity].public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def public_key_fingerprint(self, identity: str) -> str:
        return sha256(base64.b64decode(self.public_key_b64(identity))).hexdigest()[:24]
