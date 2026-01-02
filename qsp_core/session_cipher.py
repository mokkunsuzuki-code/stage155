# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class SessionCipher:
    """
    Stage150: AES-GCM session cipher wrapper.

    - key: 16/24/32 bytes (AES-128/192/256)
    - nonce: 12 bytes recommended for AESGCM in cryptography
    """

    key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(self.key) not in (16, 24, 32):
            raise ValueError("key must be 16/24/32 bytes")

    @staticmethod
    def random_nonce(n: int = 12) -> bytes:
        """
        Generate a fresh nonce for AES-GCM.
        Default = 12 bytes (96-bit), recommended.
        """
        if n <= 0:
            raise ValueError("nonce length must be positive")
        return os.urandom(n)

    def encrypt(self, *, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError("nonce must be bytes")
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes for this protocol")
        if plaintext is None:
            plaintext = b""
        if aad is None:
            aad = b""
        aesgcm = AESGCM(bytes(self.key))
        return aesgcm.encrypt(bytes(nonce), bytes(plaintext), bytes(aad))

    def decrypt(self, *, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError("nonce must be bytes")
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes for this protocol")
        if ciphertext is None:
            ciphertext = b""
        if aad is None:
            aad = b""
        aesgcm = AESGCM(bytes(self.key))
        return aesgcm.decrypt(bytes(nonce), bytes(ciphertext), bytes(aad))
