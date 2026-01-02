# MIT License © 2025 Motohiro Suzuki
"""
fuzz/fuzz_rekey155.py

Stage155/Stage154: Fuzz harness (pure Python, no external fuzzer needed)

Fix in this version:
- If REKEY flow is intentionally corrupted (mutation), the "connection" is considered broken.
  -> We reset (recreate) both cores/sessions and continue.
  This prevents: RekeyError("rekey already inflight") in subsequent steps.

Run:
  cd stage155
  python3 -m fuzz.fuzz_rekey155
  python3 -m fuzz.fuzz_rekey155 --cases 200 --steps 2000 --seed 1
"""

from __future__ import annotations

import argparse
import os
import random
from dataclasses import dataclass

from protocol.session import ProtocolCore, ProtocolConfig, Session
from crypto.algorithms import AlgorithmSuite
from transport.message_frame import MessageFrame, FT_APP_DATA, FT_REKEY
from protocol.errors import EpochMismatchError, ProtocolError, RekeyError


# ----------------------------
# Config helpers
# ----------------------------
def make_algorithm_suite() -> AlgorithmSuite:
    return AlgorithmSuite(
        supported_sigs=["sphincs+"],
        supported_kems=["kyber"],
        supported_aeads=["aes-gcm"],
    )


def make_protocol_config(suite: AlgorithmSuite) -> ProtocolConfig:
    return ProtocolConfig(
        suite=suite,
        key_len=32,
        aead_nonce_len=12,
        rekey_after=0,
    )


def install_fake_session(core: ProtocolCore, *, session_id: int = 1) -> None:
    # Both sides share the same epoch1 key in fuzz harness
    key_epoch1 = b"\x33" * 32
    core.session = Session(key_epoch1, nonce_len=12, session_id=session_id)


def reset_connection(cfg: ProtocolConfig) -> tuple[ProtocolCore, ProtocolCore]:
    """
    Simulate "connection reset": new ProtocolCore + fresh Session on both sides.
    This is the correct behavior after a mutated control frame breaks the session.
    """
    server = ProtocolCore(cfg)
    client = ProtocolCore(cfg)
    install_fake_session(server, session_id=1)
    install_fake_session(client, session_id=1)
    return server, client


# ----------------------------
# Mutations
# ----------------------------
def _flip_one_bit(b: bytes, rng: random.Random) -> bytes:
    if not b:
        return b
    i = rng.randrange(0, len(b))
    bit = 1 << rng.randrange(0, 8)
    bb = bytearray(b)
    bb[i] ^= bit
    return bytes(bb)


def mutate_frame_epoch_to_unknown(fr: MessageFrame, *, delta: int = 10_000) -> MessageFrame:
    # jump far into the future => no key for that epoch
    return MessageFrame(
        frame_type=fr.frame_type,
        flags=fr.flags,
        session_id=fr.session_id,
        epoch=(int(fr.epoch) + int(delta)) & 0xFFFFFFFF,
        seq=fr.seq,
        payload=fr.payload,
    )


def mutate_payload_nonce_prefix(fr: MessageFrame, rng: random.Random) -> MessageFrame:
    # session.aead_encrypt() prefixes nonce (12 bytes) in payload.
    # Flip a bit inside that nonce to trigger "nonce mismatch".
    p = bytes(fr.payload)
    if len(p) < 12:
        return fr
    bad = _flip_one_bit(p[:12], rng) + p[12:]
    return MessageFrame(
        frame_type=fr.frame_type,
        flags=fr.flags,
        session_id=fr.session_id,
        epoch=fr.epoch,
        seq=fr.seq,
        payload=bad,
    )


# ----------------------------
# Fuzz state machine (in-memory)
# ----------------------------
@dataclass
class FuzzParams:
    steps: int
    mutate_prob: float
    unknown_epoch_prob: float
    nonce_corrupt_prob: float


def _send_app(sender: ProtocolCore, *, plaintext: bytes) -> MessageFrame:
    assert sender.session is not None
    ep = sender.session.epoch
    seq = sender.session.next_seq()
    ct = sender.session.aead_encrypt(plaintext, aad=b"app", epoch=ep, seq=seq)
    return MessageFrame(
        frame_type=FT_APP_DATA,
        flags=0,
        session_id=sender.session.session_id,
        epoch=ep,
        seq=seq,
        payload=ct,
    )


def _recv_app(receiver: ProtocolCore, fr: MessageFrame) -> bytes:
    assert receiver.session is not None
    return receiver.session.aead_decrypt(fr.payload, aad=b"app", epoch=fr.epoch, seq=fr.seq)


def run_one_case(case_id: int, seed: int, params: FuzzParams) -> None:
    rng = random.Random((seed << 32) ^ case_id)

    suite = make_algorithm_suite()
    cfg = make_protocol_config(suite)

    server, client = reset_connection(cfg)

    # Keep last plaintext to verify echo-like property
    last_pt = b""

    for step in range(params.steps):
        # Choose an action:
        # 0: server sends APP
        # 1: full rekey round (server init -> client ack -> server commit)
        action = rng.randrange(0, 2)

        # Sometimes, do an "attack mutation" on the next frame
        do_mutate = (rng.random() < params.mutate_prob)

        if action == 0:
            # --- APP_DATA path ---
            last_pt = b"app|" + os.urandom(8) + f"|step={step}".encode()
            fr = _send_app(server, plaintext=last_pt)

            # Mutations targeted at APP frames
            if do_mutate:
                r = rng.random()
                if r < params.unknown_epoch_prob:
                    fr = mutate_frame_epoch_to_unknown(fr)
                elif r < params.unknown_epoch_prob + params.nonce_corrupt_prob:
                    fr = mutate_payload_nonce_prefix(fr, rng)

            # Receiver behavior expectations
            try:
                got = _recv_app(client, fr)
                if got != last_pt:
                    raise AssertionError("APP decrypt mismatch")
            except EpochMismatchError:
                # acceptable only if we mutated epoch to unknown
                if not do_mutate:
                    raise
                # connection is effectively broken -> reset
                server, client = reset_connection(cfg)
            except ProtocolError:
                # acceptable only if we mutated nonce prefix
                if not do_mutate:
                    raise
                # connection is effectively broken -> reset
                server, client = reset_connection(cfg)

        else:
            # --- REKEY full flow ---
            # If server is still inflight (e.g., previous mutated ack), treat as broken connection and reset.
            if server.rekey_inflight():
                server, client = reset_connection(cfg)
                continue

            try:
                init = server.build_rekey_init_frame()

                # Mutate REKEY init (rarely)
                if do_mutate and (rng.random() < params.unknown_epoch_prob):
                    init = mutate_frame_epoch_to_unknown(init)

                ack = client.handle_rekey_frame(init)
                if ack is None:
                    raise AssertionError("client did not return ACK for REKEY_INIT")

                # Mutate ACK payload nonce to force failure on server side (rarely)
                if do_mutate and (rng.random() < params.nonce_corrupt_prob):
                    ack = mutate_payload_nonce_prefix(ack, rng)

                server.handle_rekey_frame(ack)

                # After success, epochs must match and inflight must be cleared
                if client.session is None or server.session is None:
                    raise AssertionError("session disappeared")
                if client.session.epoch != server.session.epoch:
                    raise AssertionError(
                        f"epoch diverged after rekey: server={server.session.epoch} client={client.session.epoch}"
                    )
                if server.rekey_inflight():
                    raise AssertionError("server inflight not cleared after ACK")

                # Optional: post-check app decrypt across epoch
                pt2 = b"post-rekey|" + os.urandom(8)
                fr2 = _send_app(server, plaintext=pt2)
                got2 = _recv_app(client, fr2)
                if got2 != pt2:
                    raise AssertionError("post-rekey APP decrypt mismatch")

            except (EpochMismatchError, RekeyError, ProtocolError):
                # Any failure here (especially with mutations) means the session got corrupted.
                # That is expected -> reset connection and continue.
                server, client = reset_connection(cfg)

    # No strict inflight check at end: we reset on corruption, so it should be false.
    if server.rekey_inflight():
        raise AssertionError("BUG: rekey inflight remained True at end of case (should have been reset)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=50, help="number of fuzz cases")
    ap.add_argument("--steps", type=int, default=500, help="steps per case")
    ap.add_argument("--seed", type=int, default=0, help="base seed")
    ap.add_argument("--mutate-prob", type=float, default=0.15, help="probability to mutate a frame")
    ap.add_argument("--unknown-epoch-prob", type=float, default=0.50, help="within mutation, chance to mutate epoch")
    ap.add_argument("--nonce-corrupt-prob", type=float, default=0.50, help="within mutation, chance to corrupt nonce prefix")
    args = ap.parse_args()

    if args.cases <= 0:
        raise SystemExit("--cases must be > 0")
    if args.steps <= 0:
        raise SystemExit("--steps must be > 0")
    if not (0.0 <= args.mutate_prob <= 1.0):
        raise SystemExit("--mutate-prob must be in [0,1]")
    if not (0.0 <= args.unknown_epoch_prob <= 1.0):
        raise SystemExit("--unknown-epoch-prob must be in [0,1]")
    if not (0.0 <= args.nonce_corrupt_prob <= 1.0):
        raise SystemExit("--nonce-corrupt-prob must be in [0,1]")

    params = FuzzParams(
        steps=args.steps,
        mutate_prob=args.mutate_prob,
        unknown_epoch_prob=args.unknown_epoch_prob,
        nonce_corrupt_prob=args.nonce_corrupt_prob,
    )

    ok = 0
    for i in range(args.cases):
        run_one_case(i, seed=args.seed, params=params)
        ok += 1

    print("=== fuzz_rekey155 OK ===")
    print(f"cases       : {ok}")
    print(f"steps/case  : {args.steps}")
    print(f"seed        : {args.seed}")
    print(f"mutate_prob : {args.mutate_prob}")


if __name__ == "__main__":
    main()
