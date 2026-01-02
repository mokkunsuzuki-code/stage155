# MIT License © 2025 Motohiro Suzuki
"""
Stage153: Async QSP server (handshake -> secure echo)

- Accept TCP
- Wrap reader/writer with transport.io_async.AsyncFrameIO
- Run ProtocolCore.server_handshake()
- Then loop:
    - receive FT_APP_DATA
    - decrypt using (epoch, seq) from MessageFrame (aad=b"app")
    - re-encrypt same plaintext and send back FT_APP_DATA (secure echo)

Fix:
- aead_decrypt() must use frame.epoch/frame.seq (nonce一致)
- aead_encrypt() must use the same seq as MessageFrame.seq (ズレ防止)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from protocol.session import ProtocolCore, ProtocolConfig
from transport.io_async import AsyncFrameIO
from transport.message_frame import FT_APP_DATA, MessageFrame


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 9000
    backlog: int = 100


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    proto_cfg: ProtocolConfig,
) -> None:
    peer = writer.get_extra_info("peername")
    io = AsyncFrameIO(reader, writer)
    core = ProtocolCore(proto_cfg)

    try:
        # -------------------------
        # Handshake
        # -------------------------
        await core.server_handshake(io)
        if core.session is None:
            raise RuntimeError("server handshake did not create session")

        print(f"[server] handshake complete from {peer} sid={core.session.session_id}")

        # -------------------------
        # Secure echo loop
        # -------------------------
        while True:
            frame = await io.read_frame()
            if frame is None:
                print(f"[server] peer closed: {peer}")
                return

            if frame.frame_type != FT_APP_DATA:
                continue

            # -------------------------
            # decrypt (重要: frame.epoch/frame.seq を使う)
            # -------------------------
            try:
                pt = core.session.aead_decrypt(
                    frame.payload,
                    epoch=frame.epoch,
                    seq=frame.seq,
                    aad=b"app",
                )
            except Exception as e:
                print(f"[server] decrypt failed from {peer}: {e}")
                return

            # -------------------------
            # encrypt (重要: 暗号化に使う seq と MessageFrame.seq を一致させる)
            # -------------------------
            out_epoch = core.session.epoch
            out_seq = core.session.next_seq()

            ct = core.session.aead_encrypt(
                pt,
                epoch=out_epoch,
                seq=out_seq,
                aad=b"app",
            )

            resp = MessageFrame(
                frame_type=FT_APP_DATA,
                flags=0,
                session_id=core.session.session_id,
                epoch=out_epoch,
                seq=out_seq,
                payload=ct,
            )
            await io.write_frame(resp)

    finally:
        try:
            await io.close()
        except Exception:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def run_server(*, server_cfg: ServerConfig, protocol_cfg: ProtocolConfig) -> None:
    async def client_cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_client(reader, writer, proto_cfg=protocol_cfg)

    srv = await asyncio.start_server(
        client_cb,
        host=server_cfg.host,
        port=server_cfg.port,
        backlog=server_cfg.backlog,
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in (srv.sockets or []))
    print(f"[server] listening on {addrs}")

    async with srv:
        await srv.serve_forever()
