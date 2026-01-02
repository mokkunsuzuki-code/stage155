# MIT License © 2025 Motohiro Suzuki
"""
diagnostics/fuzz_tester.py

Stage154: lightweight fuzz (ALWAYS prints results)

Goals:
- Ensure MessageFrame parser doesn't crash on random bytes
- Ensure AEAD decrypt rejects corrupted inputs safely
- Print summary so tee output is never empty

Run:
  python3 -m diagnostics.fuzz_tester
  python3 -m diagnostics.fuzz_tester 2>&1 | tee fuzz_stage154.txt
"""

from __future__ import annotations

import asyncio
import os
import random
import traceback
from dataclasses import dataclass
from typing import Optional

from transport.message_frame import MessageFrame, FT_APP_DATA

SessionType = None
try:
    from protocol.session import Session as _Sess
    SessionType = _Sess
except Exception:
    SessionType = None

get_aead = None
try:
    from crypto.aead import get_aead as _get_aead
    get_aead = _get_aead
except Exception:
    get_aead = None


@dataclass
class FuzzStats:
    iters: int = 0
    frame_parsed_ok: int = 0
    frame_none: int = 0
    frame_exceptions: int = 0

    aead_ok: int = 0
    aead_rejected: int = 0
    aead_exceptions: int = 0

    unexpected_success: int = 0


def _rand_bytes(n: int) -> bytes:
    return os.urandom(n)


async def _try_parse_frame(data: bytes) -> Optional[MessageFrame]:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return await MessageFrame.read_from(r)


def fuzz_message_frame(stats: FuzzStats, iters: int = 2000) -> None:
    for _ in range(iters):
        stats.iters += 1
        # random size: sometimes too small, sometimes huge-ish
        n = random.randint(0, 2048)
        data = _rand_bytes(n)
        try:
            fr = asyncio.run(_try_parse_frame(data))
            if fr is None:
                stats.frame_none += 1
            else:
                stats.frame_parsed_ok += 1
        except Exception:
            stats.frame_exceptions += 1


def fuzz_aead(stats: FuzzStats, iters: int = 2000) -> None:
    # Prepare a working encrypt/decrypt pair
    aad = b"app"
    epoch = 1
    seq = 1
    pt = b"fuzz-payload-" + _rand_bytes(64)

    if SessionType is not None:
        key = _rand_bytes(32)
        sess = SessionType(key, nonce_len=12, session_id=1)
        ct = sess.aead_encrypt(pt, aad=aad, epoch=epoch, seq=seq, prefix_nonce=True)

        for _ in range(iters):
            stats.iters += 1
            # mutate ciphertext randomly
            blob = bytearray(ct)
            if len(blob) > 0:
                flips = random.randint(1, min(8, len(blob)))
                for _k in range(flips):
                    i = random.randrange(len(blob))
                    blob[i] ^= (1 << random.randrange(8))

            try:
                out = sess.aead_decrypt(bytes(blob), aad=aad, epoch=epoch, seq=seq, payload_has_nonce=True)
                # It should almost never succeed after mutation
                if out == pt:
                    stats.unexpected_success += 1
                stats.aead_ok += 1
            except Exception:
                stats.aead_rejected += 1

        return

    if get_aead is None:
        raise RuntimeError("No Session and no crypto.aead.get_aead available")

    aead = get_aead("aesgcm", nonce_len=12)
    key = _rand_bytes(32)
    ct2 = aead.encrypt(key, epoch, seq, pt, aad)

    for _ in range(iters):
        stats.iters += 1
        blob = bytearray(ct2)
        if len(blob) > 0:
            flips = random.randint(1, min(8, len(blob)))
            for _k in range(flips):
                i = random.randrange(len(blob))
                blob[i] ^= (1 << random.randrange(8))

        try:
            out = aead.decrypt(key, epoch, seq, bytes(blob), aad)
            if out == pt:
                stats.unexpected_success += 1
            stats.aead_ok += 1
        except Exception:
            stats.aead_rejected += 1


def main() -> None:
    random.seed(154)

    print("=== Stage154 Fuzz Tester ===")
    print("")

    stats_frame = FuzzStats()
    try:
        fuzz_message_frame(stats_frame, iters=2000)
        print("[FRAME] fuzz done")
        print(f"  parsed_ok={stats_frame.frame_parsed_ok}")
        print(f"  none={stats_frame.frame_none}")
        print(f"  exceptions={stats_frame.frame_exceptions}")
    except Exception as e:
        print(f"[FRAME] fuzz failed: {e!r}")
        print(traceback.format_exc())

    print("")

    stats_aead = FuzzStats()
    try:
        fuzz_aead(stats_aead, iters=2000)
        impl = "protocol.session.Session" if SessionType is not None else "crypto.aead"
        print(f"[AEAD] fuzz done impl={impl}")
        print(f"  rejected(as expected)={stats_aead.aead_rejected}")
        print(f"  ok(decrypt succeeded)={stats_aead.aead_ok}")
        print(f"  unexpected_success(pt matched)={stats_aead.unexpected_success}")
    except Exception as e:
        print(f"[AEAD] fuzz failed: {e!r}")
        print(traceback.format_exc())

    print("")
    print("=== DONE ===")


if __name__ == "__main__":
    main()
