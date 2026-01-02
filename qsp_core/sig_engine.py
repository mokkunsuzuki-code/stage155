# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from qsp_core.sig_backends import SignatureBackend, SignatureKeyPair, get_sig_backend


class SigEngine:
    def __init__(self, sig_alg: str) -> None:
        if not isinstance(sig_alg, str):
            raise TypeError(f"sig_alg must be str, got {type(sig_alg).__name__}")

        self.sig_alg = sig_alg.lower().strip()
        self.backend: SignatureBackend = get_sig_backend(self.sig_alg)
        self.keypair: SignatureKeyPair | None = None

    def ensure_keypair(self) -> SignatureKeyPair:
        if self.keypair is None:
            self.keypair = self.backend.keypair()
        return self.keypair

    def public_key(self) -> bytes:
        return self.ensure_keypair().public_key

    def sign(self, msg: bytes) -> bytes:
        kp = self.ensure_keypair()
        return self.backend.sign(msg, kp.secret_key)

    def verify(self, sig: bytes, msg: bytes, peer_pk: bytes) -> bool:
        return self.backend.verify(sig, msg, peer_pk)
