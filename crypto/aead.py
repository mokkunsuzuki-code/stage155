# MIT License © 2025 Motohiro Suzuki
"""
AEAD abstraction:
- aesgcm (real if cryptography available)
- fallback (NOT secure) for runnable demo
"""

from __future__ import annotations

import os
import hmac
import hashlib


class AEAD:
    name: str

    def encrypt(self, key: bytes, epoch: int, seq: int, pt: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key: bytes, epoch: int, seq: int, ct: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


class _AESGCM(AEAD):
    def __init__(self, nonce_len: int) -> None:
        self.name = "aesgcm"
        self.nonce_len = nonce_len
        self._ok = False
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.AESGCM = AESGCM
            self._ok = True
        except Exception:
            self._ok = False

        if not self._ok:
            self._fallback = _FallbackAEAD(nonce_len)

    def _nonce(self, epoch: int, seq: int) -> bytes:
        # deterministic nonce: epoch||seq padded
        base = epoch.to_bytes(4, "big") + seq.to_bytes(8, "big")
        if len(base) == self.nonce_len:
            return base
        if len(base) > self.nonce_len:
            return base[: self.nonce_len]
        return base + b"\x00" * (self.nonce_len - len(base))

    def encrypt(self, key: bytes, epoch: int, seq: int, pt: bytes, aad: bytes) -> bytes:
        if not self._ok:
            return self._fallback.encrypt(key, epoch, seq, pt, aad)
        aesgcm = self.AESGCM(key[:32])
        nonce = self._nonce(epoch, seq)
        return aesgcm.encrypt(nonce, pt, aad)

    def decrypt(self, key: bytes, epoch: int, seq: int, ct: bytes, aad: bytes) -> bytes:
        if not self._ok:
            return self._fallback.decrypt(key, epoch, seq, ct, aad)
        aesgcm = self.AESGCM(key[:32])
        nonce = self._nonce(epoch, seq)
        return aesgcm.decrypt(nonce, ct, aad)


class _FallbackAEAD(AEAD):
    """
    NOT secure. Only for keeping stage runnable without cryptography.
    Encrypt = XOR with stream; Tag = HMAC-SHA256
    """
    def __init__(self, nonce_len: int) -> None:
        self.name = "fallback"
        self.nonce_len = nonce_len

    def _stream(self, key: bytes, epoch: int, seq: int, n: int) -> bytes:
        seed = key + epoch.to_bytes(4, "big") + seq.to_bytes(8, "big")
        out = b""
        c = 0
        while len(out) < n:
            out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
            c += 1
        return out[:n]

    def encrypt(self, key: bytes, epoch: int, seq: int, pt: bytes, aad: bytes) -> bytes:
        ks = self._stream(key, epoch, seq, len(pt))
        ct = bytes([a ^ b for a, b in zip(pt, ks)])
        tag = hmac.new(key, aad + ct, hashlib.sha256).digest()
        return ct + tag

    def decrypt(self, key: bytes, epoch: int, seq: int, ct: bytes, aad: bytes) -> bytes:
        if len(ct) < 32:
            raise ValueError("ciphertext too short")
        body, tag = ct[:-32], ct[-32:]
        exp = hmac.new(key, aad + body, hashlib.sha256).digest()
        if not hmac.compare_digest(exp, tag):
            raise ValueError("bad tag")
        ks = self._stream(key, epoch, seq, len(body))
        pt = bytes([a ^ b for a, b in zip(body, ks)])
        return pt


def get_aead(name: str, nonce_len: int = 12) -> AEAD:
    n = name.strip().lower()
    if n == "aesgcm":
        return _AESGCM(nonce_len)
    return _FallbackAEAD(nonce_len)
