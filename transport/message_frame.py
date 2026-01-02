# MIT License © 2025 Motohiro Suzuki
"""
Stage155: MessageFrame

Binary format (network order):
- type        : u8
- flags       : u8
- session_id  : u64
- epoch       : u32
- seq         : u32
- payload_len : u32
- payload     : bytes

Frame types:
- FT_HANDSHAKE = 1
- FT_APP_DATA  = 2
- FT_REKEY     = 3   (control, AEAD-protected)
- FT_CLOSE     = 4   (control, AEAD-protected)
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass


FT_HANDSHAKE = 1
FT_APP_DATA = 2
FT_REKEY = 3
FT_CLOSE = 4

_HDR = struct.Struct("!BBQIII")  # type, flags, session_id, epoch, seq, payload_len


@dataclass(frozen=True)
class MessageFrame:
    frame_type: int
    flags: int
    session_id: int
    epoch: int
    seq: int
    payload: bytes

    def to_bytes(self) -> bytes:
        p = bytes(self.payload)
        header = _HDR.pack(
            int(self.frame_type) & 0xFF,
            int(self.flags) & 0xFF,
            int(self.session_id) & 0xFFFFFFFFFFFFFFFF,
            int(self.epoch) & 0xFFFFFFFF,
            int(self.seq) & 0xFFFFFFFF,
            len(p) & 0xFFFFFFFF,
        )
        return header + p

    @staticmethod
    async def read_from(reader: asyncio.StreamReader) -> "MessageFrame | None":
        try:
            hdr = await reader.readexactly(_HDR.size)
        except asyncio.IncompleteReadError:
            return None

        frame_type, flags, session_id, epoch, seq, plen = _HDR.unpack(hdr)
        if plen < 0 or plen > (64 * 1024 * 1024):
            raise ValueError("payload too large")

        payload = await reader.readexactly(plen) if plen else b""
        return MessageFrame(
            frame_type=frame_type,
            flags=flags,
            session_id=session_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
        )
