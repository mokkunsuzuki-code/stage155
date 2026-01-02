# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class KeySource(Protocol):
    """
    Stage150: key source interface.
    key_derivation.py expects `next_key(length)` to exist.
    """
    def next_key(self, n: int) -> bytes:
        ...


def _read_hex_env(name: str, default_hex: str, out_len: int) -> bytes:
    v = os.environ.get(name, "").strip()
    if not v:
        v = default_hex

    try:
        b = bytes.fromhex(v)
    except Exception as e:
        raise ValueError(f"{name} must be hex string, got {v!r}") from e

    if len(b) != out_len:
        raise ValueError(f"{name} must be {out_len} bytes, got {len(b)} bytes")
    return b


@dataclass(frozen=True)
class EnvKeySource:
    """
    Deterministic env-based KeySource with fallback (demo-grade).
    """
    env_name: str
    default_hex: str
    fixed_len: int

    def next_key(self, n: int) -> bytes:
        if not isinstance(n, int) or n <= 0:
            raise ValueError("n must be positive int")
        if n != self.fixed_len:
            # Stage150 demo: we keep length fixed to avoid accidental mismatch.
            raise ValueError(f"{self.env_name} key length must be {self.fixed_len}, requested {n}")
        return _read_hex_env(self.env_name, self.default_hex, self.fixed_len)


def qkd_source_from_env() -> KeySource:
    # 32 bytes (demo fallback deterministic)
    return EnvKeySource("QSP_QKD_KEY_HEX", "11" * 32, 32)


def kem_source_from_env() -> KeySource:
    # 32 bytes (demo fallback deterministic)
    return EnvKeySource("QSP_KEM_KEY_HEX", "22" * 32, 32)
