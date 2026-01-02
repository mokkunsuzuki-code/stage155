# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from keysources.base import KeySource, KeyMaterial
from crypto.kem import get_kem_backend


class PQCKemKeySource(KeySource):
    """
    Stage155: PQC-KEM source (KEM is mandatory).
    """
    name = "pqc_kem"

    def __init__(self, kem_alg: str = "toy_kem") -> None:
        self.kem_alg = kem_alg

    def provide(self, context: bytes) -> KeyMaterial:
        kem = get_kem_backend(self.kem_alg)
        r = kem.encapsulate()
        return KeyMaterial(qkd=None, kem=r.shared_secret)
