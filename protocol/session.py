# MIT License © 2025 Motohiro Suzuki
"""
protocol/session.py

Stage155: Rekey の正式化（自動rekey + 連続性保証） + v1.0 handshake を受ける器

要点:
- nonce = f(epoch, seq)  (strict)
- control (REKEY/CLOSE) も AEAD + AAD で保護（境界維持）
- epoch mismatch を検出して close できる
- old/new 鍵の “連続性” を保つため、直近2 epoch の鍵を保持する
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Sequence, Tuple

from protocol.errors import (
    ProtocolError,
    RekeyError,
    EpochMismatchError,
    CloseReason,
)
from protocol import rekey as rk
from transport.message_frame import MessageFrame, FT_REKEY, FT_CLOSE

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover
    AESGCM = None  # type: ignore


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError("ikm must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("info must be bytes")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be positive int")

    prk = hmac.new(bytes(salt), bytes(ikm), hashlib.sha256).digest()
    t = b""
    okm = b""
    c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + bytes(info) + bytes([c]), hashlib.sha256).digest()
        okm += t
        c += 1
        if c > 255:
            raise ValueError("hkdf expand overflow")
    return okm[:length]


@dataclass(frozen=True)
class KeyMaterial:
    kem: bytes
    qkd: bytes = b""

    @property
    def key(self) -> bytes:
        return self.kem


def _coerce_key_material(x: Any) -> KeyMaterial:
    if x is None:
        raise RuntimeError("unsupported key material type: NoneType (handshake returned None)")

    if isinstance(x, KeyMaterial):
        return x

    if isinstance(x, (bytes, bytearray)):
        return KeyMaterial(kem=bytes(x), qkd=b"")

    if isinstance(x, dict):
        kem = x.get("kem", None)
        if kem is None:
            kem = x.get("key", None)
        qkd = x.get("qkd", b"")
        if kem is None:
            raise RuntimeError(f"unsupported key material dict (missing 'kem'/'key'): keys={list(x.keys())}")
        if not isinstance(kem, (bytes, bytearray)):
            raise RuntimeError(f"unsupported key material dict kem type: {type(kem).__name__}")
        if not isinstance(qkd, (bytes, bytearray)):
            raise RuntimeError(f"unsupported key material dict qkd type: {type(qkd).__name__}")
        return KeyMaterial(kem=bytes(kem), qkd=bytes(qkd))

    kem_attr = getattr(x, "kem", None)
    if isinstance(kem_attr, (bytes, bytearray)):
        qkd_attr = getattr(x, "qkd", b"")
        if not isinstance(qkd_attr, (bytes, bytearray)):
            qkd_attr = b""
        return KeyMaterial(kem=bytes(kem_attr), qkd=bytes(qkd_attr))

    key_attr = getattr(x, "key", None)
    if isinstance(key_attr, (bytes, bytearray)):
        qkd_attr = getattr(x, "qkd", b"")
        if not isinstance(qkd_attr, (bytes, bytearray)):
            qkd_attr = b""
        return KeyMaterial(kem=bytes(key_attr), qkd=bytes(qkd_attr))

    raise RuntimeError(f"unsupported key material type: {type(x).__name__}")


@dataclass(frozen=True)
class ProtocolConfig:
    # ---- agility inputs ----
    suite: Any = None
    sig_alg: str = "sphincs+"
    kem_alg: str = "toy_kem"
    qkd_policy: str = "DEGRADE_TO_KEM"  # or FAIL_CLOSED

    # ---- crypto params ----
    key_len: int = 32
    aead_nonce_len: int = 12

    # ---- rekey ----
    rekey_after: int = 50  # 0 disables


class Session:
    """
    Stage155:
    - multi-epoch keys (keep latest 2)
    - strict nonce = epoch||seq (12 bytes)
    """

    def __init__(self, key_epoch1: bytes, *, nonce_len: int = 12, session_id: int = 0) -> None:
        if AESGCM is None:
            raise RuntimeError("cryptography(AESGCM) が利用できません。`pip install cryptography` を確認してください。")
        if not isinstance(key_epoch1, (bytes, bytearray)):
            raise TypeError("session key must be bytes")
        if len(key_epoch1) not in (16, 24, 32):
            raise ValueError(f"invalid AES key length: {len(key_epoch1)} (expected 16/24/32)")
        if nonce_len != 12:
            raise ValueError("Stage155 requires nonce_len=12 (epoch(4)+seq(8))")

        self.nonce_len = 12
        self.session_id = int(session_id) & 0xFFFFFFFFFFFFFFFF

        self.epoch: int = 1
        self._tx_seq: int = 0

        self._keys: dict[int, bytes] = {1: bytes(key_epoch1)}
        self._pending: dict[int, bytes] = {}

    def next_seq(self) -> int:
        self._tx_seq = (self._tx_seq + 1) & 0xFFFFFFFF
        return self._tx_seq

    def _nonce_from_epoch_seq(self, epoch: int, seq: int) -> bytes:
        e = int(epoch) & 0xFFFFFFFF
        s = int(seq) & 0xFFFFFFFFFFFFFFFF
        return e.to_bytes(4, "big") + s.to_bytes(8, "big")

    def _aead(self, key: bytes):
        return AESGCM(key[:32])  # type: ignore[misc]

    def _get_key_for_epoch(self, epoch: int) -> bytes:
        k = self._keys.get(int(epoch))
        if k is None:
            raise EpochMismatchError(f"no key for epoch={epoch} (current={self.epoch})")
        return k

    def install_epoch_key(self, epoch: int, key: bytes, *, make_current: bool) -> None:
        ep = int(epoch)
        kb = bytes(key)
        self._keys[ep] = kb

        if len(self._keys) > 2:
            oldest = sorted(self._keys.keys())[0]
            self._keys.pop(oldest, None)

        if make_current:
            self.epoch = ep

    def derive_next_key(self, *, new_epoch: int, material: bytes) -> bytes:
        cur_key = self._get_key_for_epoch(self.epoch)
        salt = b"QSP155|" + self.session_id.to_bytes(8, "big") + int(new_epoch).to_bytes(4, "big")
        info = b"rekey|" + bytes(material)
        return hkdf_sha256(ikm=cur_key, salt=salt, info=info, length=len(cur_key))

    def set_pending(self, new_epoch: int, key: bytes) -> None:
        self._pending[int(new_epoch)] = bytes(key)

    def commit_pending(self, new_epoch: int) -> None:
        ep = int(new_epoch)
        k = self._pending.pop(ep, None)
        if k is None:
            raise RekeyError("commit_pending: no pending key")
        self.install_epoch_key(ep, k, make_current=True)

    def aead_encrypt(self, plaintext: bytes, *, aad: bytes = b"", epoch: int, seq: int, prefix_nonce: bool = True) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")
        key = self._get_key_for_epoch(epoch)
        nonce = self._nonce_from_epoch_seq(epoch, seq)
        ct = self._aead(key).encrypt(nonce, bytes(plaintext), bytes(aad))
        return nonce + ct if prefix_nonce else ct

    def aead_decrypt(self, payload: bytes, *, aad: bytes = b"", epoch: int, seq: int, payload_has_nonce: bool = True) -> bytes:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")

        data = bytes(payload)
        key = self._get_key_for_epoch(epoch)
        nonce = self._nonce_from_epoch_seq(epoch, seq)

        ct = data
        if payload_has_nonce:
            if len(data) < self.nonce_len:
                raise ValueError("payload too short (missing nonce)")
            got = data[: self.nonce_len]
            ct = data[self.nonce_len :]
            if got != nonce:
                raise ProtocolError("nonce mismatch (frame epoch/seq != payload nonce)")

        return self._aead(key).decrypt(nonce, ct, bytes(aad))


HandshakeFn = Callable[..., Awaitable[Tuple[int, Any]]]


def _find_handshake_fn(mod: Any, candidates: Sequence[str]) -> Optional[HandshakeFn]:
    for name in candidates:
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn  # type: ignore[return-value]
    return None


class ProtocolCore:
    def __init__(self, cfg: ProtocolConfig) -> None:
        if not isinstance(cfg, ProtocolConfig):
            raise TypeError("cfg must be ProtocolConfig")
        self.cfg = cfg
        self.session: Optional[Session] = None

        self._rekey_inflight: bool = False
        self._rekey_target_epoch: Optional[int] = None
        self._rekey_material: Optional[bytes] = None

    def _derive_session_key_epoch1(self, km: KeyMaterial) -> bytes:
        ikm = km.kem + (km.qkd or b"")
        salt = b"QSP-Stage155"
        info = b"QSP session key epoch1"
        return hkdf_sha256(ikm=ikm, salt=salt, info=info, length=self.cfg.key_len)

    def _install_session(self, session_id: int, km_any: Any) -> Session:
        km = _coerce_key_material(km_any)
        key1 = self._derive_session_key_epoch1(km)
        sess = Session(key1, nonce_len=self.cfg.aead_nonce_len, session_id=session_id)
        self.session = sess
        return sess

    async def client_handshake(self, io: Any) -> Session:
        session_id, km = await self._call_handshake(role="client", io=io)
        return self._install_session(session_id, km)

    async def server_handshake(self, io: Any) -> Session:
        session_id, km = await self._call_handshake(role="server", io=io)
        return self._install_session(session_id, km)

    async def _call_handshake(self, *, role: str, io: Any) -> Tuple[int, Any]:
        try:
            from protocol import handshake as handshake_mod  # type: ignore
        except Exception as e:
            raise RuntimeError("protocol/handshake.py が見つかりません。") from e

        if role == "client":
            candidates = ("client_handshake", "handshake_client", "run_client_handshake", "client")
        else:
            candidates = ("server_handshake", "handshake_server", "run_server_handshake", "server")

        fn = _find_handshake_fn(handshake_mod, candidates)
        if fn is None:
            raise RuntimeError(f"protocol.handshake に {role} 側関数が見つかりません。")

        last_err: Optional[Exception] = None
        for call in (
            lambda: fn(io=io, cfg=self.cfg, role=role),
            lambda: fn(io=io, role=role),
            lambda: fn(io, self.cfg, role),
            lambda: fn(io, role),
        ):
            try:
                res = await call()
                if not isinstance(res, tuple) or len(res) != 2:
                    raise RuntimeError("handshake must return (session_id, key_material)")
                sid, km = res
                if not isinstance(sid, int):
                    if isinstance(sid, (bytes, bytearray)) and len(sid) <= 8:
                        sid = int.from_bytes(bytes(sid), "big")
                    else:
                        raise RuntimeError(f"invalid session_id type: {type(sid).__name__}")
                return int(sid) & 0xFFFFFFFFFFFFFFFF, km
            except Exception as e:
                last_err = e

        raise RuntimeError(f"handshake call failed ({role}): {last_err}") from last_err

    def build_close_frame(self, *, reason: int, message: str, epoch: int) -> MessageFrame:
        if self.session is None:
            raise ProtocolError("no session for close")
        seq = self.session.next_seq()
        pt = reason.to_bytes(2, "big") + message.encode("utf-8")
        ct = self.session.aead_encrypt(pt, aad=b"close", epoch=epoch, seq=seq)
        return MessageFrame(frame_type=FT_CLOSE, flags=0, session_id=self.session.session_id, epoch=epoch, seq=seq, payload=ct)

    def parse_close(self, frame: MessageFrame) -> tuple[int, str]:
        if self.session is None:
            raise ProtocolError("no session for close")
        pt = self.session.aead_decrypt(frame.payload, aad=b"close", epoch=frame.epoch, seq=frame.seq)
        if len(pt) < 2:
            return CloseReason.PROTOCOL_ERROR, "close malformed"
        reason = int.from_bytes(pt[:2], "big")
        msg = pt[2:].decode("utf-8", errors="replace")
        return reason, msg

    def rekey_inflight(self) -> bool:
        return self._rekey_inflight

    def build_rekey_init_frame(self) -> MessageFrame:
        if self.session is None:
            raise ProtocolError("no session")
        if self._rekey_inflight:
            raise RekeyError("rekey already inflight")

        new_epoch = int(self.session.epoch) + 1
        material = rk.make_material(32)

        new_key = self.session.derive_next_key(new_epoch=new_epoch, material=material)
        self.session.set_pending(new_epoch, new_key)

        self._rekey_inflight = True
        self._rekey_target_epoch = new_epoch
        self._rekey_material = material

        seq = self.session.next_seq()
        pt = rk.encode_rekey_init(new_epoch, material)
        ct = self.session.aead_encrypt(pt, aad=b"rekey-init", epoch=self.session.epoch, seq=seq)

        return MessageFrame(frame_type=FT_REKEY, flags=0, session_id=self.session.session_id, epoch=self.session.epoch, seq=seq, payload=ct)

    def handle_rekey_frame(self, frame: MessageFrame) -> Optional[MessageFrame]:
        if self.session is None:
            raise ProtocolError("no session")

        last: Optional[Exception] = None
        for aad in (b"rekey-init", b"rekey-ack"):
            try:
                pt = self.session.aead_decrypt(frame.payload, aad=aad, epoch=frame.epoch, seq=frame.seq)
                msg = rk.decode_rekey_plaintext(pt)
                if isinstance(msg, rk.RekeyInit) and aad != b"rekey-init":
                    raise RekeyError("aad mismatch for rekey init")
                if isinstance(msg, rk.RekeyAck) and aad != b"rekey-ack":
                    raise RekeyError("aad mismatch for rekey ack")
                return self._handle_rekey_msg(msg, frame_epoch=frame.epoch)
            except Exception as e:
                last = e
                continue
        raise RekeyError(f"rekey decrypt/decode failed: {last!r}")

    def _handle_rekey_msg(self, msg: rk.RekeyInit | rk.RekeyAck, *, frame_epoch: int) -> Optional[MessageFrame]:
        assert self.session is not None

        if int(frame_epoch) != int(self.session.epoch):
            raise EpochMismatchError(f"rekey frame epoch mismatch: got={frame_epoch}, current={self.session.epoch}")

        if isinstance(msg, rk.RekeyInit):
            new_epoch = msg.new_epoch
            material = msg.material

            if new_epoch != int(self.session.epoch) + 1:
                raise RekeyError("rekey init new_epoch invalid")

            new_key = self.session.derive_next_key(new_epoch=new_epoch, material=material)
            self.session.set_pending(new_epoch, new_key)

            seq = self.session.next_seq()
            confirm = rk.confirm_material(material)
            pt = rk.encode_rekey_ack(new_epoch, confirm)
            ct = self.session.aead_encrypt(pt, aad=b"rekey-ack", epoch=self.session.epoch, seq=seq)
            ack = MessageFrame(frame_type=FT_REKEY, flags=0, session_id=self.session.session_id, epoch=self.session.epoch, seq=seq, payload=ct)

            self.session.commit_pending(new_epoch)
            return ack

        if isinstance(msg, rk.RekeyAck):
            if not self._rekey_inflight:
                raise RekeyError("unexpected rekey ack (no inflight)")

            target = self._rekey_target_epoch
            material = self._rekey_material
            if target is None or material is None:
                raise RekeyError("rekey inflight state broken")

            if msg.new_epoch != target:
                raise RekeyError("rekey ack new_epoch mismatch")

            if msg.confirm != rk.confirm_material(material):
                raise RekeyError("rekey ack confirm mismatch")

            self.session.commit_pending(target)

            self._rekey_inflight = False
            self._rekey_target_epoch = None
            self._rekey_material = None
            return None

        raise RekeyError("unknown rekey msg")
