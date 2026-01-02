# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
from keysources.base import KeySource, KeyMaterial


class QKDE91KeySource(KeySource):
    """
    Stage155 dev QKD source.
    NOTE: 本物の E91 は Stage148 実装（qsp_core）へ差し替える想定。
    """
    name = "qkd_e91_dev"

    def provide(self, context: bytes) -> KeyMaterial:
        raw = os.urandom(32)
        return KeyMaterial(qkd=raw, kem=None)
