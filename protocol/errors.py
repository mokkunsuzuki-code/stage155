# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations


class QSPError(Exception):
    pass


class HandshakeError(QSPError):
    pass


class ProtocolError(QSPError):
    pass


class RekeyError(ProtocolError):
    pass


class EpochMismatchError(ProtocolError):
    pass


class CloseReason:
    """
    Stage155: close reason の規格化（最小セット）
    """
    NORMAL = 0
    PROTOCOL_ERROR = 10
    AEAD_DECRYPT_FAILED = 20
    EPOCH_MISMATCH = 30
    REKEY_FAILED = 40
    HANDSHAKE_FAILED = 50
    INTERNAL_ERROR = 90
