# MIT License © 2025 Motohiro Suzuki
"""
Stage144(A): Signature policy

We support algorithm agility:
- SPHINCS_PQCLEAN
- DILITHIUM_PQCLEAN

Policy is chosen by environment variable:
- QSP_SIG_POLICY:
    - REAL_ONLY (default): choose any available real backend, prefer DILITHIUM then SPHINCS
    - PREFER_DILITHIUM: prefer DILITHIUM if available, else SPHINCS
    - PREFER_SPHINCS: prefer SPHINCS if available, else DILITHIUM
    - FORCE_DILITHIUM: require DILITHIUM
    - FORCE_SPHINCS: require SPHINCS
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SignaturePolicy:
    name: str

    @staticmethod
    def from_env(default: str = "REAL_ONLY") -> "SignaturePolicy":
        v = os.getenv("QSP_SIG_POLICY", default).strip().upper()
        return SignaturePolicy(name=v)

    def preferred_order(self) -> list[str]:
        # canonical names
        D = "DILITHIUM_PQCLEAN"
        S = "SPHINCS_PQCLEAN"

        if self.name in ("REAL_ONLY", "PREFER_DILITHIUM"):
            return [D, S]
        if self.name == "PREFER_SPHINCS":
            return [S, D]
        if self.name == "FORCE_DILITHIUM":
            return [D]
        if self.name == "FORCE_SPHINCS":
            return [S]
        # fallback
        return [D, S]
