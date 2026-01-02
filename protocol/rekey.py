# MIT License © 2025 Motohiro Suzuki
"""
protocol/rekey.py

Stage155: Rekey の正式化（状態機械 + 形式化）
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from protocol.errors import RekeyError


def should_rekey(seq: int, threshold: int) -> bool:
    return threshold > 0 and seq > 0 and (seq % threshold == 0)


_MAGIC = b"RK55"
_T_INIT = 1
_T_ACK = 2


def _u32(x: int) -> bytes:
    return int(x & 0xFFFFFFFF).to_bytes(4, "big")


def _read_u32(b: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(b):
        raise RekeyError("rekey decode overflow u32")
    return int.from_bytes(b[off : off + 4], "big"), off + 4


def make_material(n: int = 32) -> bytes:
    return os.urandom(n)


def confirm_material(material: bytes) -> bytes:
    return hashlib.sha256(bytes(material) + b"ack").digest()


def encode_rekey_init(new_epoch: int, material: bytes) -> bytes:
    m = bytes(material)
    if len(m) != 32:
        raise RekeyError("rekey_init material must be 32 bytes")
    return _MAGIC + bytes([_T_INIT]) + _u32(new_epoch) + m


def encode_rekey_ack(new_epoch: int, confirm: bytes) -> bytes:
    c = bytes(confirm)
    if len(c) != 32:
        raise RekeyError("rekey_ack confirm must be 32 bytes")
    return _MAGIC + bytes([_T_ACK]) + _u32(new_epoch) + c


@dataclass
class RekeyInit:
    new_epoch: int
    material: bytes


@dataclass
class RekeyAck:
    new_epoch: int
    confirm: bytes


def decode_rekey_plaintext(pt: bytes) -> RekeyInit | RekeyAck:
    b = bytes(pt)
    if len(b) < 4 + 1 + 4 + 32:
        raise RekeyError("rekey plaintext too short")
    if b[:4] != _MAGIC:
        raise RekeyError("rekey bad magic")
    t = b[4]
    off = 5
    new_epoch, off = _read_u32(b, off)
    body = b[off:]
    if len(body) != 32:
        raise RekeyError("rekey body len mismatch")
    if t == _T_INIT:
        return RekeyInit(new_epoch=new_epoch, material=body)
    if t == _T_ACK:
        return RekeyAck(new_epoch=new_epoch, confirm=body)
    raise RekeyError("rekey unknown type")
