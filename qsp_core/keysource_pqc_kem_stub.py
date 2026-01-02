# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict
import secrets


@dataclass
class PQCKEMStubKeySource:
    _meta: Dict[str, Any] = field(default_factory=dict)
    _buf: bytearray = field(default_factory=bytearray)

    def last_meta(self) -> Dict[str, Any]:
        return dict(self._meta)

    def next_key(self, nbytes: int) -> bytes:
        if nbytes <= 0:
            raise ValueError("nbytes must be positive")
        while len(self._buf) < nbytes:
            chunk = secrets.token_bytes(max(32, nbytes))
            self._buf.extend(chunk)
            self._meta = {
                "source_type": "PQC_KEM_STUB",
                "trust_level": "stub/os-random",
                "entropy_estimate": 1.0,
                "note": "Replace with ML-KEM/real KEM in Stage155",
            }
        out = bytes(self._buf[:nbytes])
        del self._buf[:nbytes]
        return out
