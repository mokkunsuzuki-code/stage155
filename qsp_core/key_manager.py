# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big", signed=False)


@dataclass
class KeyManager:
    """
    Key/Context manager for Stage150.

    IMPORTANT:
      - AAD must be derived from *header values* (seq, epoch), not from internal counters alone.
      - Signature TBS also uses header values (seq, epoch).
    """

    session_id: bytes  # 16 bytes
    epoch: int = 1
    _seq: int = 0
    sig_alg: str = "sphincs"
    rekey_every: int = 256

    @classmethod
    def create(cls) -> "KeyManager":
        # In Stage150, server creates a temporary session_id first,
        # but will align to client's session_id after HANDSHAKE.
        # The caller can replace session_id later.
        import os

        return cls(session_id=os.urandom(16), epoch=1, _seq=0, sig_alg="sphincs", rekey_every=256)

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def bump_epoch(self) -> int:
        self.epoch += 1
        return self.epoch

    def should_rekey(self) -> bool:
        return (self._seq % self.rekey_every) == 0 and self._seq != 0

    # -----------------------------
    # Context bytes
    # -----------------------------
    def salt_for_epoch(self) -> bytes:
        # Deterministic salt per session/epoch (demo-grade).
        # Real deployments should use stronger/rotating salt material.
        return b"QSP150-SALT" + self.session_id + _u32(self.epoch)

    def aad_bytes(self, *, seq: int, epoch: int) -> bytes:
        # AAD is authenticated by AES-GCM (must match exactly on both sides).
        return b"QSP150-AAD" + self.session_id + _u32(seq) + _u32(epoch)

    # -----------------------------
    # Signature TBS
    # -----------------------------
    def handshake_tbs(self, payload: bytes) -> bytes:
        return b"QSP150-HS" + self.session_id + _u32(self.epoch) + payload

    def data_tbs(self, *, seq: int, epoch: int, nonce: bytes, ciphertext: bytes) -> bytes:
        return b"QSP150-DATA" + self.session_id + _u32(seq) + _u32(epoch) + nonce + ciphertext

    def rekey_tbs(self, payload: bytes) -> bytes:
        return b"QSP150-REKEY" + self.session_id + _u32(self.epoch) + payload
