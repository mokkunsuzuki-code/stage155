# MIT License © 2025 Motohiro Suzuki
"""
Stage155 KEM abstraction.

IMPORTANT:
- Stage154/155 の handshake では「両者で同じ shared_secret になる」必要がある。
- 以前の stub は decapsulate がランダムで一致しないため、Stage155 では toy_kem を追加。

toy_kem:
- encapsulate(): ct = random(32), ss = SHA256(ct)
- decapsulate(ct): ss = SHA256(ct)
"""

from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class KemResult:
    shared_secret: bytes
    encapsulated: bytes


class KemBackend:
    name: str

    def encapsulate(self) -> KemResult:
        raise NotImplementedError

    def decapsulate(self, encapsulated: bytes) -> bytes:
        raise NotImplementedError


class _ToyKEM(KemBackend):
    def __init__(self) -> None:
        self.name = "toy_kem"

    def encapsulate(self) -> KemResult:
        ct = os.urandom(32)
        ss = hashlib.sha256(ct).digest()
        return KemResult(shared_secret=ss, encapsulated=ct)

    def decapsulate(self, encapsulated: bytes) -> bytes:
        ct = bytes(encapsulated)
        return hashlib.sha256(ct).digest()


class _StubKEM(KemBackend):
    """
    互換用 stub（安全ではない＆shared_secret一致保証なし）
    Stage155 handshake では使わないこと。
    """
    def __init__(self, name: str) -> None:
        self.name = name

    def encapsulate(self) -> KemResult:
        ss = os.urandom(32)
        ct = os.urandom(32)
        return KemResult(shared_secret=ss, encapsulated=ct)

    def decapsulate(self, encapsulated: bytes) -> bytes:
        return os.urandom(32)


def get_kem_backend(name: str) -> KemBackend:
    n = name.strip().lower()
    if n in ("toy_kem", "toy", "deterministic"):
        return _ToyKEM()
    return _StubKEM(n)
