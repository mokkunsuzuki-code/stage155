# MIT License © 2025 Motohiro Suzuki
"""
Stage149: PQC-KEM KeySource (Stub / Replaceable)

Why stub?
- Real PQC-KEM (e.g., ML-KEM) may require native build/tooling.
- Stage149's goal is correctness of HYBRID derivation and metadata wiring,
  not KEM benchmarking/build complexity.

Replace later with:
- ML-KEM (Kyber) wrapper
- BIKE/HQC, etc.
- or hybrid classical+PQC KEM
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict
import os
import secrets


@dataclass
class PQCKEMStubKeySource:
    _meta: Dict[str, Any] = field(default_factory=dict)
    _buf: bytearray = field(default_factory=bytearray)

    def last_meta(self) -> Dict[str, Any]:
        return dict(self._meta)

    def next_key(self, nbytes: int) -> bytes:
        if not isinstance(nbytes, int) or nbytes <= 0:
            raise ValueError("nbytes must be positive int")

        while len(self._buf) < nbytes:
            self._refill(min_need=nbytes - len(self._buf))

        out = bytes(self._buf[:nbytes])
        del self._buf[:nbytes]
        return out

    def _refill(self, min_need: int) -> None:
        # In real KEM, this would be derived from encapsulation shared secret.
        # Here: high-quality OS randomness.
        chunk = secrets.token_bytes(max(32, min_need))
        self._buf.extend(chunk)

        self._meta = {
            "source_type": "PQC_KEM_STUB",
            "trust_level": "stub/os-random",
            "entropy_estimate": 1.0,
            "note": "Replace with real PQC-KEM (e.g., ML-KEM) backend later",
            "env_hint": {
                "QSP_KEM_BACKEND": os.getenv("QSP_KEM_BACKEND", "stub"),
            },
        }
