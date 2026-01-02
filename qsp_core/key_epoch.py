# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class KeyEpoch:
    epoch: int = 1

    def bump(self) -> int:
        self.epoch += 1
        return self.epoch
