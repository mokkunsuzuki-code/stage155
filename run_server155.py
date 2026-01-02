# MIT License © 2025 Motohiro Suzuki
"""
Stage155: Async QSP server runner (server-led auto rekey)

- Handshake (AUTH + KEM + QKD mix)
- Secure echo (FT_APP_DATA)
- Every N messages (rekey_after), server initiates REKEY
- Rekey/CLOSE are AEAD-protected control frames
"""

from __future__ import annotations

import asyncio

from protocol.session import ProtocolCore, ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.io_async import AsyncFrameIO
from transport.message_frame import MessageFrame, FT_APP_DATA, FT_REKEY, FT_CLOSE
from protocol.errors import CloseReason, EpochMismatchError, RekeyError
from protocol.rekey import should_rekey


def make_algorithm_suite() -> AlgorithmSuite:
    return AlgorithmSuite(
        supported_sigs=["sphincs+", "ed25519"],
        supported_kems=["toy_kem"],
        supported_aeads=["aes-gcm"],
    )


def make_protocol_config(suite: AlgorithmSuite) -> ProtocolConfig:
    return ProtocolConfig(
        suite=suite,
        sig_alg="sphincs+",
        kem_alg="toy_kem",
        qkd_policy="DEGRADE_TO_KEM",
        key_len=32,
        aead_nonce_len=12,
        rekey_after=5,
    )


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: ProtocolConfig) -> None:
    peer = writer.get_extra_info("peername")
    print(f"[server] accepted from {peer}")

    io = AsyncFrameIO(reader, writer)
    core = ProtocolCore(cfg)

    try:
        await core.server_handshake(io)
        print(f"[server] handshake complete sid={core.session.session_id}")

        while True:
            frame = await io.read_frame()
            if frame is None:
                print("[server] connection closed by peer")
                return

            if frame.frame_type == FT_CLOSE:
                reason, msg = core.parse_close(frame)
                print(f"[server] peer closed reason={reason} msg={msg!r}")
                return

            if frame.frame_type == FT_REKEY:
                try:
                    core.handle_rekey_frame(frame)
                except EpochMismatchError as e:
                    f = core.build_close_frame(reason=CloseReason.EPOCH_MISMATCH, message=str(e), epoch=core.session.epoch)
                    await io.write_frame(f)
                    return
                except RekeyError as e:
                    f = core.build_close_frame(reason=CloseReason.REKEY_FAILED, message=str(e), epoch=core.session.epoch)
                    await io.write_frame(f)
                    return
                continue

            if frame.frame_type != FT_APP_DATA:
                continue

            try:
                pt = core.session.aead_decrypt(frame.payload, aad=b"app", epoch=frame.epoch, seq=frame.seq)
            except EpochMismatchError as e:
                f = core.build_close_frame(reason=CloseReason.EPOCH_MISMATCH, message=str(e), epoch=core.session.epoch)
                await io.write_frame(f)
                return
            except Exception as e:
                f = core.build_close_frame(reason=CloseReason.AEAD_DECRYPT_FAILED, message=repr(e), epoch=core.session.epoch)
                await io.write_frame(f)
                return

            out_epoch = core.session.epoch
            out_seq = core.session.next_seq()
            ct = core.session.aead_encrypt(pt, aad=b"app", epoch=out_epoch, seq=out_seq)

            await io.write_frame(
                MessageFrame(
                    frame_type=FT_APP_DATA,
                    flags=0,
                    session_id=core.session.session_id,
                    epoch=out_epoch,
                    seq=out_seq,
                    payload=ct,
                )
            )

            if should_rekey(out_seq, cfg.rekey_after) and (not core.rekey_inflight()):
                init = core.build_rekey_init_frame()
                await io.write_frame(init)
                print(f"[server] rekey init sent -> target_epoch={core.session.epoch + 1}")

    except Exception as e:
        print(f"[server] error: {e!r}")
        try:
            if core.session is not None:
                f = core.build_close_frame(reason=CloseReason.INTERNAL_ERROR, message=repr(e), epoch=core.session.epoch)
                await io.write_frame(f)
        except Exception:
            pass
    finally:
        await io.close()


async def main() -> None:
    suite = make_algorithm_suite()
    cfg = make_protocol_config(suite)
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, cfg), "127.0.0.1", 9000)
    print("[server] listening on 127.0.0.1:9000")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
