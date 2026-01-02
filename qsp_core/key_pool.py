# MIT License © 2025 Motohiro Suzuki
"""
Stage149: KeyPool with metadata

- Stores key material along with:
  - source_type
  - timestamp
  - trust_level
  - entropy_estimate
  - free-form metrics dict

This is intentionally simple: Stage149 focuses on correctness of hybrid derivation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class KeyRecord:
    key: bytes
    source_type: str
    timestamp_utc: str
    trust_level: str
    entropy_estimate: float
    metrics: Dict[str, Any] = field(default_factory=dict)


class KeyPool:
    def __init__(self) -> None:
        self._items: List[KeyRecord] = []

    def push(
        self,
        key: bytes,
        source_type: str,
        trust_level: str = "unknown",
        entropy_estimate: float = 0.0,
        metrics: Dict[str, Any] | None = None,
    ) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if not source_type:
            raise ValueError("source_type is empty")

        rec = KeyRecord(
            key=bytes(key),
            source_type=str(source_type),
            timestamp_utc=_utc_now_iso(),
            trust_level=str(trust_level),
            entropy_estimate=float(entropy_estimate),
            metrics=dict(metrics or {}),
        )
        self._items.append(rec)

    def pop(self) -> KeyRecord:
        if not self._items:
            raise RuntimeError("KeyPool is empty")
        return self._items.pop(0)

    def peek_all(self) -> List[KeyRecord]:
        return list(self._items)

    def __len__(self) -> int:
        return len(self._items)
