# MIT License © 2025 Motohiro Suzuki
"""
diagnostics/bench_runner.py

Stage154: benchmark runner (ALWAYS prints results)

What it measures (safe, minimal, deterministic):
- AEAD encrypt/decrypt throughput (bytes/sec, ops/sec)
- MessageFrame encode/decode throughput

Why this file exists:
- Your current bench output is empty even though exit code is 0.
- This runner ALWAYS prints and can be piped to tee.

Run:
  python3 -m diagnostics.bench_runner
  python3 -m diagnostics.bench_runner 2>&1 | tee bench_stage154.txt
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Callable, Tuple

from transport.message_frame import MessageFrame, FT_APP_DATA

# Try to use Stage154 Session if present, else fallback to crypto.aead.get_aead
SessionType = None
try:
    from protocol.session import Session as _Sess  # Stage153/154 style
    SessionType = _Sess
except Exception:
    SessionType = None

AEADType = None
get_aead = None
try:
    from crypto.aead import get_aead as _get_aead  # fallback AEAD exists in your tree
    get_aead = _get_aead
except Exception:
    get_aead = None


@dataclass(frozen=True)
class BenchResult:
    name: str
    ops: int
    seconds: float
    bytes_total: int

    @property
    def ops_per_sec(self) -> float:
        return self.ops / self.seconds if self.seconds > 0 else 0.0

    @property
    def mb_per_sec(self) -> float:
        return (self.bytes_total / (1024 * 1024)) / self.seconds if self.seconds > 0 else 0.0


def _now() -> float:
    return time.perf_counter()


def _bench_loop(name: str, ops: int, bytes_per_op: int, fn: Callable[[], None]) -> BenchResult:
    t0 = _now()
    for _ in range(ops):
        fn()
    t1 = _now()
    return BenchResult(name=name, ops=ops, seconds=(t1 - t0), bytes_total=ops * bytes_per_op)


def _make_payload(n: int) -> bytes:
    return os.urandom(n)


def bench_message_frame(ops: int = 50_000, payload_len: int = 256) -> Tuple[BenchResult, BenchResult]:
    payload = _make_payload(payload_len)

    frame = MessageFrame(
        frame_type=FT_APP_DATA,
        flags=0,
        session_id=0x1122334455667788,
        epoch=1,
        seq=1,
        payload=payload,
    )

    # encode
    def _enc() -> None:
        _ = frame.to_bytes()

    enc = _bench_loop("MessageFrame.to_bytes", ops=ops, bytes_per_op=payload_len, fn=_enc)

    # decode (use StreamReader with preloaded bytes)
    data = frame.to_bytes()

    async def _read_once() -> None:
        r = asyncio.StreamReader()
        r.feed_data(data)
        r.feed_eof()
        fr = await MessageFrame.read_from(r)
        if fr is None:
            raise RuntimeError("read_from returned None unexpectedly")

    def _dec() -> None:
        asyncio.run(_read_once())

    dec = _bench_loop("MessageFrame.read_from", ops=max(1, ops // 200), bytes_per_op=payload_len, fn=_dec)
    return enc, dec


def bench_aead_session(ops: int = 20_000, payload_len: int = 1024) -> Tuple[BenchResult, BenchResult, str]:
    pt = _make_payload(payload_len)
    aad = b"app"
    epoch = 1

    # Prefer protocol.session.Session (AESGCM) if available.
    if SessionType is not None:
        key = os.urandom(32)
        sess = SessionType(key, nonce_len=12, session_id=1)

        # Use deterministic epoch/seq mapping like your Stage153/154 rule
        # We'll provide explicit seq to avoid any internal drift.
        seq_counter = 0

        def _enc() -> None:
            nonlocal seq_counter
            seq_counter += 1
            _ = sess.aead_encrypt(pt, aad=aad, epoch=epoch, seq=seq_counter, prefix_nonce=True)

        # Precompute one ciphertext for decrypt bench
        seq_counter += 1
        ct_one = sess.aead_encrypt(pt, aad=aad, epoch=epoch, seq=seq_counter, prefix_nonce=True)

        # For decrypt: use the SAME epoch/seq so nonce matches.
        dec_seq = seq_counter

        def _dec() -> None:
            _ = sess.aead_decrypt(ct_one, aad=aad, epoch=epoch, seq=dec_seq, payload_has_nonce=True)

        enc = _bench_loop("Session.aead_encrypt (prefix_nonce)", ops=ops, bytes_per_op=payload_len, fn=_enc)
        dec = _bench_loop("Session.aead_decrypt (checked)", ops=ops, bytes_per_op=payload_len, fn=_dec)
        return enc, dec, "protocol.session.Session"

    # Fallback to crypto.aead
    if get_aead is None:
        raise RuntimeError("No Session and no crypto.aead.get_aead available")

    aead = get_aead("aesgcm", nonce_len=12)
    key = os.urandom(32)
    seq_counter = 0

    def _enc2() -> None:
        nonlocal seq_counter
        seq_counter += 1
        _ = aead.encrypt(key, epoch, seq_counter, pt, aad)

    seq_counter += 1
    ct_one2 = aead.encrypt(key, epoch, seq_counter, pt, aad)
    dec_seq2 = seq_counter

    def _dec2() -> None:
        _ = aead.decrypt(key, epoch, dec_seq2, ct_one2, aad)

    enc2 = _bench_loop(f"AEAD.encrypt ({aead.name})", ops=ops, bytes_per_op=payload_len, fn=_enc2)
    dec2 = _bench_loop(f"AEAD.decrypt ({aead.name})", ops=ops, bytes_per_op=payload_len, fn=_dec2)
    return enc2, dec2, "crypto.aead"


def main() -> None:
    print("=== Stage154 Bench Runner ===")
    print(f"python: running")
    print("")

    # AEAD bench
    try:
        enc, dec, impl = bench_aead_session(ops=20_000, payload_len=1024)
        print(f"[AEAD] impl={impl}")
        print(f"  {enc.name}: ops={enc.ops} time={enc.seconds:.4f}s ops/s={enc.ops_per_sec:,.0f} MB/s={enc.mb_per_sec:,.2f}")
        print(f"  {dec.name}: ops={dec.ops} time={dec.seconds:.4f}s ops/s={dec.ops_per_sec:,.0f} MB/s={dec.mb_per_sec:,.2f}")
    except Exception as e:
        print(f"[AEAD] bench failed: {e!r}")

    print("")

    # MessageFrame bench
    try:
        encf, decf = bench_message_frame(ops=50_000, payload_len=256)
        print("[FRAME]")
        print(f"  {encf.name}: ops={encf.ops} time={encf.seconds:.4f}s ops/s={encf.ops_per_sec:,.0f} MB/s={encf.mb_per_sec:,.2f}")
        print(f"  {decf.name}: ops={decf.ops} time={decf.seconds:.4f}s ops/s={decf.ops_per_sec:,.0f} MB/s={decf.mb_per_sec:,.2f}")
    except Exception as e:
        print(f"[FRAME] bench failed: {e!r}")

    print("")
    print("=== DONE ===")


if __name__ == "__main__":
    main()
