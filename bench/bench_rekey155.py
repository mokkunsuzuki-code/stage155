# MIT License © 2025 Motohiro Suzuki
"""
bench/bench_rekey155.py

Stage155/Stage154: Rekey benchmark (FULL FLOW, Research Grade)

目的:
- 「rekey already inflight」を起こさずに、正規フローで rekey を回し続ける
- server-led rekey:
    server: build_rekey_init_frame()
    client: handle_rekey_frame(init) -> returns ACK frame
    server: handle_rekey_frame(ack)  -> commit + clear inflight
- 各ループで epoch が 1 ずつ進むことを確認する（軽い整合性チェック）

実行例:
  cd stage155
  python3 -m bench.bench_rekey155
  python3 -m bench.bench_rekey155 --n 5000
"""

from __future__ import annotations

import argparse
import time

from protocol.session import ProtocolCore, ProtocolConfig, Session
from crypto.algorithms import AlgorithmSuite


def make_algorithm_suite() -> AlgorithmSuite:
    # bench は suite を深く使わないが、構造として保持
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
        rekey_after=0,  # bench は自動ではなく明示的にrekeyを回す
    )


def install_fake_session(core: ProtocolCore, *, session_id: int = 1) -> None:
    """
    bench 用に「handshake済み状態」を作る。
    server/client が同じ epoch1 key を共有していれば rekey の挙動を測れる。
    """
    key_epoch1 = b"\x33" * 32
    core.session = Session(key_epoch1, nonce_len=12, session_id=session_id)


def run_bench(n: int, warmup: int) -> None:
    suite = make_algorithm_suite()
    cfg = make_protocol_config(suite)

    # server core / client core を分ける（実運用の関係を模擬）
    server = ProtocolCore(cfg)
    client = ProtocolCore(cfg)

    install_fake_session(server, session_id=1)
    install_fake_session(client, session_id=1)

    assert server.session is not None
    assert client.session is not None

    # --- warmup (JITは無いが、初回のimport/暗号初期化等のノイズを避ける) ---
    for _ in range(max(0, warmup)):
        init = server.build_rekey_init_frame()
        ack = client.handle_rekey_frame(init)
        if ack is None:
            raise RuntimeError("bench warmup: client did not return ACK")
        server.handle_rekey_frame(ack)

    # --- main bench ---
    t0 = time.perf_counter()

    for i in range(n):
        # 1) server -> INIT
        init = server.build_rekey_init_frame()

        # 2) client -> ACK (and client commits immediately)
        ack = client.handle_rekey_frame(init)
        if ack is None:
            raise RuntimeError("bench: client did not return ACK")

        # 3) server handles ACK (commit + inflight clear)
        server.handle_rekey_frame(ack)

        # --- minimal correctness checks ---
        if not (client.session.epoch == server.session.epoch):
            raise RuntimeError(
                f"epoch diverged at i={i}: server={server.session.epoch} client={client.session.epoch}"
            )
        if server.rekey_inflight():
            raise RuntimeError(f"inflight not cleared at i={i}")

    t1 = time.perf_counter()

    dt = max(1e-12, (t1 - t0))
    ops = n
    ops_s = ops / dt

    print("=== bench_rekey155 (FULL FLOW) ===")
    print(f"loops        : {n}")
    print(f"warmup       : {warmup}")
    print(f"elapsed_sec  : {dt:.6f}")
    print(f"ops_per_sec  : {ops_s:.1f} rekey/s")
    print(f"final_epoch  : {server.session.epoch}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000, help="number of rekey loops")
    ap.add_argument("--warmup", type=int, default=50, help="warmup loops (not counted)")
    args = ap.parse_args()

    if args.n <= 0:
        raise SystemExit("--n must be > 0")
    if args.warmup < 0:
        raise SystemExit("--warmup must be >= 0")

    run_bench(n=args.n, warmup=args.warmup)


if __name__ == "__main__":
    main()
