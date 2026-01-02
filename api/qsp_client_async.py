# MIT License © 2025 Motohiro Suzuki
"""
Stage152: Async QSP client (I/O layer)
- Owns network I/O
- Calls protocol core (transport-agnostic)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from transport.io_async import AsyncFrameIO
from transport.message_frame import MessageFrame, FT_APP_DATA
from protocol.session import ProtocolCore, ProtocolConfig


@dataclass
class ClientConfig:
    host: str = "127.0.0.1"
    port: int = 5151


async def run_client(client_cfg: ClientConfig, proto_cfg: ProtocolConfig) -> None:
    reader, writer = await asyncio.open_connection(client_cfg.host, client_cfg.port)
    io = AsyncFrameIO(reader, writer)
    core = ProtocolCore(proto_cfg)

    try:
        # 1) handshake
        await core.client_handshake(io)
        print("[client] handshake OK")

        # 2) send one message (demo)
        payload = b"hello from stage152"
        f = MessageFrame(
            frame_type=FT_APP_DATA,
            flags=0,
            session_id=core.session.session_id,
            epoch=core.session.epoch,
            seq=core.session.next_seq(),
            payload=core.session.aead_encrypt(payload, aad=b"app"),
        )
        await io.write_frame(f)

        # 3) read echo
        resp = await io.read_frame()
        if resp is None:
            print("[client] server closed")
            return

        await core.on_inbound_frame(io, resp)

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
