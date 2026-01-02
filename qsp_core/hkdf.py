# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import hmac
import hashlib


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None:
        salt = b""
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError("ikm must be bytes")
    return hmac.new(bytes(salt), bytes(ikm), hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not isinstance(prk, (bytes, bytearray)):
        raise TypeError("prk must be bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("info must be bytes")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be positive")

    prk = bytes(prk)
    info = bytes(info)

    hash_len = hashlib.sha256().digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("HKDF expand too large")

    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt=salt, ikm=ikm)
    return hkdf_expand(prk=prk, info=info, length=length)
