# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyMaterial:
    """
    Stage155: keep QKD and KEM separated for verifiability.
    """
    qkd: bytes | None
    kem: bytes | None


class KeySource:
    name: str

    def provide(self, context: bytes) -> KeyMaterial:
        raise NotImplementedError
