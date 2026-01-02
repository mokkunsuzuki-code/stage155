# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass

from qsp_core.key_source import KeySource


@dataclass(frozen=True)
class DerivedKey:
    """
    Result container (demo).
    """
    session_key: bytes


class HybridKeyDeriver:
    """
    Stage150: Hybrid Key Derivation (QKD + KEM) -> session key bytes.
    This file expects qkd/kem to be KeySource objects with next_key().
    """

    def __init__(self, *, qkd: KeySource, kem: KeySource) -> None:
        self.qkd = qkd
        self.kem = kem

    def derive_session_key(
        self,
        *,
        out_len: int,
        salt: bytes,
        info: bytes,
        qkd_len: int,
        kem_len: int,
    ) -> DerivedKey:
        if out_len not in (16, 24, 32):
            raise ValueError("out_len must be 16/24/32 bytes for AES")

        qkd_key = self.qkd.next_key(int(qkd_len))
        kem_key = self.kem.next_key(int(kem_len))

        # Minimal HKDF-style mixing (demo-grade):
        # PRK = HMAC(salt, qkd||kem)
        # OKM = HMAC(PRK, info||0x01) truncated
        import hmac
        import hashlib

        ikm = qkd_key + kem_key
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return DerivedKey(session_key=okm[:out_len])
