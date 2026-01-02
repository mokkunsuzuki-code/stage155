# MIT License © 2025 Motohiro Suzuki
"""
Stage146: HKDF-SHA256 (no external deps)
"""

from __future__ import annotations

import hmac
import hashlib


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be > 0")
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size

    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand
    out = b""
    t = b""
    c = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
        if c > 255:
            raise ValueError("hkdf expand too long")
    return out[:length]
