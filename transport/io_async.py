# MIT License © 2025 Motohiro Suzuki
"""
Stage155: Async frame transport
"""

from __future__ import annotations

import asyncio

from transport.message_frame import MessageFrame


class AsyncFrameIO:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._r = reader
        self._w = writer

    async def read_frame(self) -> MessageFrame | None:
        return await MessageFrame.read_from(self._r)

    async def write_frame(self, frame: MessageFrame) -> None:
        self._w.write(frame.to_bytes())
        await self._w.drain()

    async def close(self) -> None:
        try:
            self._w.close()
            await self._w.wait_closed()
        except Exception:
            pass


async def open_connection(host: str, port: int) -> AsyncFrameIO:
    reader, writer = await asyncio.open_connection(host, port)
    return AsyncFrameIO(reader, writer)


async def open_client(host: str, port: int) -> AsyncFrameIO:
    return await open_connection(host, port)
