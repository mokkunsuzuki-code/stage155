# MIT License © 2025 Motohiro Suzuki
"""
protocol/handshake.py

Stage155: v1.0 dev handshake (AUTH + KEM + QKD mix)

目的（Research Gradeの“入口”として必要十分）:
- 署名で相互認証（stubでも境界が同じ）
- KEM 共有秘密（toy_kem は両者一致）
- QKD 由来の材料（dev: serverが32B送る。将来はE91差し替え）
- これらを IKM として返し、ProtocolCore が epoch1 鍵へ落とす

Wire:
CHLO payload:
  b"CH55" || client_nonce(32) || sig_alg_len(u8)||sig_alg || kem_alg_len(u8)||kem_alg || client_pk_len(u16)||client_pk
SHLO payload:
  b"SH55" || server_nonce(32) || session_id(u64) || server_pk_len(u16)||server_pk || kem_ct_len(u16)||kem_ct || qkd_len(u16)||qkd || server_sig_len(u16)||server_sig

Signature:
- server signs transcript = CHLO_payload || SHLO_without_sig
- client verifies server_sig
(最小: client側署名は “client_pk を提示” で済ませる。相互署名は Stage155-2 で強化可能)

Return:
(session_id, {"kem": kem_ss, "qkd": qkd_bytes, "ikm": ..., "transcript": ...})
"""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, Optional, Tuple

from transport.message_frame import MessageFrame, FT_HANDSHAKE
from crypto.sig_backends import get_sig_backend
from crypto.kem import get_kem_backend
from crypto.hkdf import build_ikm


_CHLO_MAGIC = b"CH55"
_SHLO_MAGIC = b"SH55"
_NONCE_LEN = 32


class _IO:
    def __init__(self, io: Any):
        wf = getattr(io, "write_frame", None)
        rf = getattr(io, "read_frame", None)
        if callable(wf) and callable(rf):
            self.write_frame = wf
            self.read_frame = rf
            return
        raise TypeError("io must provide async read_frame/write_frame")

    async def read_frame(self) -> Optional[MessageFrame]:  # pragma: no cover
        raise NotImplementedError

    async def write_frame(self, frame: MessageFrame) -> None:  # pragma: no cover
        raise NotImplementedError


def _u8(n: int) -> bytes:
    return bytes([n & 0xFF])


def _u16(n: int) -> bytes:
    return struct.pack(">H", int(n) & 0xFFFF)


def _read_u8(b: bytes, off: int) -> tuple[int, int]:
    if off + 1 > len(b):
        raise ValueError("decode overflow u8")
    return b[off], off + 1


def _read_u16(b: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(b):
        raise ValueError("decode overflow u16")
    return struct.unpack(">H", b[off : off + 2])[0], off + 2


def _read_bytes(b: bytes, off: int, n: int) -> tuple[bytes, int]:
    if off + n > len(b):
        raise ValueError("decode overflow bytes")
    return b[off : off + n], off + n


def _read_var(b: bytes, off: int) -> tuple[bytes, int]:
    ln, off = _read_u16(b, off)
    return _read_bytes(b, off, ln)


def _pack_chlo(*, client_nonce: bytes, sig_alg: str, kem_alg: str, client_pk: bytes) -> bytes:
    sa = sig_alg.encode("utf-8")
    ka = kem_alg.encode("utf-8")
    if len(client_nonce) != _NONCE_LEN:
        raise ValueError("client_nonce must be 32 bytes")
    if len(sa) > 255 or len(ka) > 255:
        raise ValueError("alg name too long")
    if len(client_pk) > 65535:
        raise ValueError("client_pk too long")

    return (
        _CHLO_MAGIC
        + bytes(client_nonce)
        + _u8(len(sa)) + sa
        + _u8(len(ka)) + ka
        + _u16(len(client_pk)) + bytes(client_pk)
    )


def _unpack_chlo(payload: bytes) -> tuple[bytes, str, str, bytes]:
    b = bytes(payload)
    off = 0
    magic, off = _read_bytes(b, off, 4)
    if magic != _CHLO_MAGIC:
        raise ValueError("bad CHLO magic")
    client_nonce, off = _read_bytes(b, off, _NONCE_LEN)

    sa_len, off = _read_u8(b, off)
    sa, off = _read_bytes(b, off, sa_len)
    ka_len, off = _read_u8(b, off)
    ka, off = _read_bytes(b, off, ka_len)

    client_pk, off = _read_var(b, off)
    return client_nonce, sa.decode("utf-8"), ka.decode("utf-8"), client_pk


def _pack_shlo_without_sig(*, server_nonce: bytes, session_id: int, server_pk: bytes, kem_ct: bytes, qkd: bytes) -> bytes:
    if len(server_nonce) != _NONCE_LEN:
        raise ValueError("server_nonce must be 32 bytes")
    if not (0 <= int(session_id) < (1 << 64)):
        raise ValueError("session_id must be u64")
    if len(server_pk) > 65535 or len(kem_ct) > 65535 or len(qkd) > 65535:
        raise ValueError("field too long")

    return (
        _SHLO_MAGIC
        + bytes(server_nonce)
        + struct.pack(">Q", int(session_id))
        + _u16(len(server_pk)) + bytes(server_pk)
        + _u16(len(kem_ct)) + bytes(kem_ct)
        + _u16(len(qkd)) + bytes(qkd)
    )


def _pack_shlo(*, shlo_wo_sig: bytes, server_sig: bytes) -> bytes:
    if len(server_sig) > 65535:
        raise ValueError("server_sig too long")
    return bytes(shlo_wo_sig) + _u16(len(server_sig)) + bytes(server_sig)


def _unpack_shlo(payload: bytes) -> tuple[bytes, int, bytes, bytes, bytes, bytes, bytes]:
    b = bytes(payload)
    off = 0
    magic, off = _read_bytes(b, off, 4)
    if magic != _SHLO_MAGIC:
        raise ValueError("bad SHLO magic")

    server_nonce, off = _read_bytes(b, off, _NONCE_LEN)
    (sid,) = struct.unpack(">Q", b[off : off + 8])
    off += 8

    server_pk, off = _read_var(b, off)
    kem_ct, off = _read_var(b, off)
    qkd, off = _read_var(b, off)
    server_sig, off = _read_var(b, off)

    # transcript parts
    shlo_wo_sig = b[: off - (2 + len(server_sig))]
    return server_nonce, sid, server_pk, kem_ct, qkd, server_sig, shlo_wo_sig


async def client_handshake(io: Any, cfg: Any = None, role: str = "client", *args: Any, **kwargs: Any) -> Tuple[int, Dict[str, bytes]]:
    aio = _IO(io)

    sig_alg = getattr(cfg, "sig_alg", "sphincs+")
    kem_alg = getattr(cfg, "kem_alg", "toy_kem")

    sig = get_sig_backend(sig_alg)
    kp = sig.keypair()

    client_nonce = os.urandom(_NONCE_LEN)
    chlo = _pack_chlo(client_nonce=client_nonce, sig_alg=sig_alg, kem_alg=kem_alg, client_pk=kp.public_key)

    await aio.write_frame(MessageFrame(frame_type=FT_HANDSHAKE, flags=0, session_id=0, epoch=0, seq=0, payload=chlo))

    fr = await aio.read_frame()
    if fr is None or fr.frame_type != FT_HANDSHAKE:
        raise RuntimeError("handshake: no SHLO from server")

    server_nonce, sid, server_pk, kem_ct, qkd, server_sig, shlo_wo_sig = _unpack_shlo(fr.payload)

    transcript = chlo + shlo_wo_sig
    if not sig.verify(server_pk, transcript, server_sig):
        raise RuntimeError("handshake: server signature verify failed")

    kem = get_kem_backend(kem_alg)
    kem_ss = kem.decapsulate(kem_ct)

    ikm = build_ikm(qkd=qkd if len(qkd) else None, kem=kem_ss)
    km = {
        "kem": kem_ss,
        "qkd": qkd,
        "ikm": ikm,
        "transcript": transcript,
    }
    return int(sid) & 0xFFFFFFFFFFFFFFFF, km


async def server_handshake(io: Any, cfg: Any = None, role: str = "server", *args: Any, **kwargs: Any) -> Tuple[int, Dict[str, bytes]]:
    aio = _IO(io)

    fr = await aio.read_frame()
    if fr is None or fr.frame_type != FT_HANDSHAKE:
        raise RuntimeError("handshake: no CHLO from client")

    client_nonce, sig_alg, kem_alg, client_pk = _unpack_chlo(fr.payload)

    sig = get_sig_backend(sig_alg)
    kp = sig.keypair()

    kem = get_kem_backend(kem_alg)
    r = kem.encapsulate()
    kem_ss = r.shared_secret
    kem_ct = r.encapsulated

    # dev QKD material (将来はE91へ差し替え)
    qkd = os.urandom(32)
    sid = int.from_bytes(os.urandom(8), "big")

    server_nonce = os.urandom(_NONCE_LEN)
    shlo_wo_sig = _pack_shlo_without_sig(server_nonce=server_nonce, session_id=sid, server_pk=kp.public_key, kem_ct=kem_ct, qkd=qkd)

    transcript = bytes(fr.payload) + shlo_wo_sig
    server_sig = sig.sign(kp.secret_key, transcript)

    shlo = _pack_shlo(shlo_wo_sig=shlo_wo_sig, server_sig=server_sig)

    await aio.write_frame(MessageFrame(frame_type=FT_HANDSHAKE, flags=0, session_id=sid, epoch=0, seq=0, payload=shlo))

    ikm = build_ikm(qkd=qkd, kem=kem_ss)
    km = {
        "kem": kem_ss,
        "qkd": qkd,
        "ikm": ikm,
        "transcript": transcript,
        "client_pk": client_pk,
    }
    return int(sid) & 0xFFFFFFFFFFFFFFFF, km


run_client_handshake = client_handshake
handshake_client = client_handshake

run_server_handshake = server_handshake
handshake_server = server_handshake
