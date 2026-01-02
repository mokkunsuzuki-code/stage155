# MIT License © 2025 Motohiro Suzuki
"""
Stage146: Policy (minimal)

- sig_alg: signature algorithm name
- cipher:  "aesgcm" (preferred) or "demo-xor"
- rekey_interval: how many DATA frames between rekeys
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QSPPolicy:
    sig_alg: str = "sphincs"
    cipher: str = "aesgcm"
    rekey_interval: int = 3  # demo: every 3 DATA frames -> REKEY
