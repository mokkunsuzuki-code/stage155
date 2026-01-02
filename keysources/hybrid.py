# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from keysources.base import KeySource, KeyMaterial
from keysources.qkd_e91 import QKDE91KeySource
from keysources.pqc_kem import PQCKemKeySource


class HybridKeySource(KeySource):
    """
    Stage155 Hybrid KeySource.

    policy:
    - "DEGRADE_TO_KEM" : QKD が無ければ KEM のみで進む
    - "FAIL_CLOSED"    : QKD が無ければ失敗
    """
    name = "hybrid"

    def __init__(self, kem_alg: str = "toy_kem", policy: str = "DEGRADE_TO_KEM") -> None:
        self.qkd = QKDE91KeySource()
        self.kem = PQCKemKeySource(kem_alg)
        self.policy = policy.upper()

    def provide(self, context: bytes) -> KeyMaterial:
        q = self.qkd.provide(context).qkd
        k = self.kem.provide(context).kem

        if k is None:
            raise RuntimeError("KEM unavailable")

        if q is None and self.policy == "FAIL_CLOSED":
            raise RuntimeError("QKD unavailable (FAIL_CLOSED)")

        return KeyMaterial(qkd=q, kem=k)
