# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
from typing import List


def client_supported_sig_algs() -> List[str]:
    # Client advertises supported algorithms (ordered).
    # You can extend later.
    return ["sphincs", "dilithium", "mldsa65", "hmac"]


def server_choose_sig_alg(client_algs: List[str]) -> str:
    forced = os.getenv("QSP_FORCE_SIG_ALG", "").strip().lower()
    if forced:
        return forced if forced in [a.lower() for a in client_algs] else ""

    prefer = ["sphincs", "dilithium", "mldsa65", "hmac"]
    client_set = {str(a).lower() for a in client_algs}
    for p in prefer:
        if p in client_set:
            return p
    return ""
