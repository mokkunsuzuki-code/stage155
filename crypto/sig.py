# MIT License © 2025 Motohiro Suzuki
"""
Signature backends:
- ed25519 (real, if cryptography is available)
- dilithium / sphincs+ (stub interface for algorithm agility stage)
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import hmac
import hashlib


@dataclass(frozen=True)
class SigKeyPair:
    public_key: bytes
    secret_key: bytes


class SigBackend:
    name: str

    def keypair(self) -> SigKeyPair:
        raise NotImplementedError

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError


class _HmacStubSig(SigBackend):
    """
    NOTE:
    This is a *stub* to keep Stage152 runnable without external PQC libs.
    It models algorithm agility boundaries, not PQC security.

    Public key == secret key in this stub (NOT secure).
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def keypair(self) -> SigKeyPair:
        sk = os.urandom(32)
        pk = sk
        return SigKeyPair(public_key=pk, secret_key=sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return hmac.new(sk, msg, hashlib.sha256).digest()

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        exp = hmac.new(pk, msg, hashlib.sha256).digest()
        return hmac.compare_digest(exp, sig)


class _Ed25519Sig(SigBackend):
    def __init__(self) -> None:
        self.name = "ed25519"
        self._ok = False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
            self.Ed25519PrivateKey = Ed25519PrivateKey
            self.Ed25519PublicKey = Ed25519PublicKey
            self._ok = True
        except Exception:
            self._ok = False

        if not self._ok:
            # fallback stub if cryptography is missing
            self._stub = _HmacStubSig("ed25519_stub")

    def keypair(self) -> SigKeyPair:
        if not self._ok:
            return self._stub.keypair()

        sk = self.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return SigKeyPair(
            public_key=pk.public_bytes_raw(),
            secret_key=sk.private_bytes_raw(),
        )

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        if not self._ok:
            return self._stub.sign(sk, msg)

        sk_obj = self.Ed25519PrivateKey.from_private_bytes(sk)
        return sk_obj.sign(msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if not self._ok:
            return self._stub.verify(pk, msg, sig)

        try:
            pk_obj = self.Ed25519PublicKey.from_public_bytes(pk)
            pk_obj.verify(sig, msg)
            return True
        except Exception:
            return False


def get_sig_backend(name: str) -> SigBackend:
    n = name.strip().lower()
    if n == "ed25519":
        return _Ed25519Sig()
    if n in ("dilithium", "dilithium2", "dilithium3", "dilithium5"):
        return _HmacStubSig("dilithium")
    if n in ("sphincs+", "sphincs", "sphincsplus"):
        return _HmacStubSig("sphincs+")
    # default: stub
    return _HmacStubSig(n)
