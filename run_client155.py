# MIT License © 2025 Motohiro Suzuki
"""
Stage155: Async QSP client runner (rekey follower)

- Handshake (AUTH + KEM + QKD mix)
- Send APP_DATA periodically
- Handle FT_REKEY (INIT) -> send ACK -> commit
- If epoch mismatch is detected -> close
"""

from __future__ import annotations

import asyncio

from protocol.session import ProtocolCore, ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.io_async import AsyncFrameIO
from transport.message_frame import MessageFrame, FT_APP_DATA, FT_REKEY, FT_CLOSE
from protocol.errors import CloseReason, EpochMismatchError, RekeyError


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
        rekey_after=0,
    )


async def main() -> None:
    suite = make_algorithm_suite()
    cfg = make_protocol_config(suite)

    reader, writer = await asyncio.open_connection("127.0.0.1", 9000)
    io = AsyncFrameIO(reader, writer)
    core = ProtocolCore(cfg)

    try:
        await core.client_handshake(io)
        sid = core.session.session_id
        print(f"[client] handshake complete sid={sid} epoch={core.session.epoch}")

        for i in range(1, 21):
            out_epoch = core.session.epoch
            out_seq = core.session.next_seq()
            msg = f"msg{i} epoch={out_epoch} seq={out_seq}".encode("utf-8")

            ct = core.session.aead_encrypt(msg, aad=b"app", epoch=out_epoch, seq=out_seq)
            await io.write_frame(MessageFrame(frame_type=FT_APP_DATA, flags=0, session_id=sid, epoch=out_epoch, seq=out_seq, payload=ct))

            while True:
                fr = await io.read_frame()
                if fr is None:
                    print("[client] server closed")
                    return

                if fr.frame_type == FT_CLOSE:
                    reason, msg2 = core.parse_close(fr)
                    print(f"[client] closed by server reason={reason} msg={msg2!r}")
                    return

                if fr.frame_type == FT_REKEY:
                    try:
                        resp = core.handle_rekey_frame(fr)
                        if resp is not None:
                            await io.write_frame(resp)
                            print(f"[client] rekey ack sent -> now epoch={core.session.epoch}")
                    except EpochMismatchError as e:
                        close = core.build_close_frame(reason=CloseReason.EPOCH_MISMATCH, message=str(e), epoch=core.session.epoch)
                        await io.write_frame(close)
                        return
                    except RekeyError as e:
                        close = core.build_close_frame(reason=CloseReason.REKEY_FAILED, message=str(e), epoch=core.session.epoch)
                        await io.write_frame(close)
                        return
                    continue

                if fr.frame_type == FT_APP_DATA:
                    pt = core.session.aead_decrypt(fr.payload, aad=b"app", epoch=fr.epoch, seq=fr.seq)
                    print("[client] echo:", pt.decode("utf-8", errors="replace"))
                    break

            await asyncio.sleep(0.05)

        close = core.build_close_frame(reason=CloseReason.NORMAL, message="done", epoch=core.session.epoch)
        await io.write_frame(close)

    finally:
        await io.close()


if __name__ == "__main__":
    asyncio.run(main())
