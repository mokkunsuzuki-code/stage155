# MIT License © 2025 Motohiro Suzuki
"""
Stage151 hybrid runner
- same as server/client, but explicitly uses HybridKeySource inside ProtocolConfig
"""

from __future__ import annotations

import asyncio

from api.qsp_server_async import run_server, ServerConfig
from protocol.session import ProtocolConfig


def main() -> None:
    server_cfg = ServerConfig(host="127.0.0.1", port=5151)
    proto_cfg = ProtocolConfig(
        sig_alg="ed25519",
        key_len=32,
        aead_nonce_len=12,
        rekey_after=200,
        keysources_mode="hybrid",
    )
    asyncio.run(run_server(server_cfg, proto_cfg))


if __name__ == "__main__":
    main()
