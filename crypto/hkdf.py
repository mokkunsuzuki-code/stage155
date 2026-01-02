# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import hashlib
import hmac


def _u32(x: int) -> bytes:
    if x < 0 or x > 0xFFFFFFFF:
        raise ValueError("u32 out of range")
    return x.to_bytes(4, "big")


def build_ikm(qkd: bytes | None, kem: bytes | None) -> bytes:
    """
    Stage155 normalized IKM:
        IKM = len(QKD)||QKD || len(KEM)||KEM
    """
    q = qkd or b""
    k = kem or b""
    return _u32(len(q)) + q + _u32(len(k)) + k


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be > 0")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t
        c += 1
        if c > 255:
            raise ValueError("hkdf too long")
    return okm[:length]
