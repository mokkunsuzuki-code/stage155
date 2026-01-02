# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import pytest

from protocol.session import ProtocolCore, ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.message_frame import MessageFrame, FT_REKEY


def test_rekey_commit_flow() -> None:
    suite = AlgorithmSuite(["sphincs+"], ["toy_kem"], ["aes-gcm"])
    cfg = ProtocolConfig(suite=suite, rekey_after=0)
    c = ProtocolCore(cfg)
    s = ProtocolCore(cfg)

    # 手動で session を同鍵で作る（テスト簡略化）
    key = b"\x22" * 32
    c.session = __import__("protocol.session", fromlist=["Session"]).Session(key, nonce_len=12, session_id=7)
    s.session = __import__("protocol.session", fromlist=["Session"]).Session(key, nonce_len=12, session_id=7)

    init = s.build_rekey_init_frame()
    assert init.frame_type == FT_REKEY

    ack = c.handle_rekey_frame(init)
    assert isinstance(ack, MessageFrame)

    _ = s.handle_rekey_frame(ack)
    assert c.session.epoch == 2
    assert s.session.epoch == 2
