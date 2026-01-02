# MIT License © 2025 Motohiro Suzuki
"""
Stage147+148: KeyPool with KeySource metadata

- Accepts pluggable KeySource
- Tracks refill metadata:
    - source_type
    - entropy_estimate_bits
    - timestamp
    - trust_level (experimental)
    - QKD metrics (if available): qber, chsh_s, raw_bits

Compatibility:
- Keeps QKDKeyPool wrapper class (older stages)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import time

from qsp_core.key_source import KeySource, create_qkd_source, QKDKeySourceType


@dataclass
class KeyPoolStats:
    acquired_bytes: int = 0
    consumed_bytes: int = 0
    refills: int = 0

    @property
    def available_bytes(self) -> int:
        return self.acquired_bytes - self.consumed_bytes


@dataclass
class KeyRefillMeta:
    timestamp: float
    source_type: str
    entropy_estimate_bits: Optional[int]
    trust_level: Optional[str]
    extra: Dict[str, Any]


class KeyPool:
    def __init__(
        self,
        source: KeySource,
        *,
        min_bytes: int = 4096,
        refill_bytes: int = 16384,
        max_bytes: int = 1_048_576,
        keep_meta: int = 32,
    ) -> None:
        if min_bytes <= 0 or refill_bytes <= 0 or max_bytes <= 0:
            raise ValueError("min_bytes/refill_bytes/max_bytes must be positive")
        if min_bytes > max_bytes:
            raise ValueError("min_bytes must be <= max_bytes")
        if refill_bytes > max_bytes:
            raise ValueError("refill_bytes must be <= max_bytes")
        if keep_meta <= 0:
            raise ValueError("keep_meta must be positive")

        self._source = source
        self._min_bytes = int(min_bytes)
        self._refill_bytes = int(refill_bytes)
        self._max_bytes = int(max_bytes)
        self._keep_meta = int(keep_meta)

        self._buf = bytearray()
        self.stats = KeyPoolStats()
        self.refill_meta: List[KeyRefillMeta] = []

        self._ensure_min()

    def available(self) -> int:
        return len(self._buf)

    def consume(self, nbytes: int) -> bytes:
        if not isinstance(nbytes, int):
            raise TypeError(f"nbytes must be int, got {type(nbytes).__name__}")
        if nbytes <= 0:
            raise ValueError("nbytes must be positive")

        if len(self._buf) < nbytes:
            self._refill_to(nbytes)

        if len(self._buf) < nbytes:
            raise RuntimeError(f"KeyPool underflow: need {nbytes}, have {len(self._buf)}")

        out = bytes(self._buf[:nbytes])
        del self._buf[:nbytes]
        self.stats.consumed_bytes += nbytes
        return out

    def top_up(self) -> None:
        self._ensure_min()

    def _ensure_min(self) -> None:
        if len(self._buf) >= self._min_bytes:
            return
        need = max(self._refill_bytes, self._min_bytes - len(self._buf))
        self._refill(need)

    def _refill_to(self, nbytes_needed: int) -> None:
        if len(self._buf) >= nbytes_needed:
            return
        need = max(self._refill_bytes, nbytes_needed - len(self._buf))
        self._refill(need)

    def _record_meta(self) -> None:
        meta = {}
        try:
            meta = self._source.last_meta()
        except Exception:
            meta = {}

        ts = float(meta.get("timestamp") or time.time())
        st = str(meta.get("source_type") or type(self._source).__name__)
        ent = meta.get("entropy_estimate_bits")
        ent_i = int(ent) if isinstance(ent, int) else None
        trust = meta.get("trust_level")
        trust_s = str(trust) if isinstance(trust, (str, int, float)) else None

        # extra = everything except the common keys
        extra = dict(meta)
        for k in ("timestamp", "source_type", "entropy_estimate_bits", "trust_level"):
            extra.pop(k, None)

        self.refill_meta.append(
            KeyRefillMeta(
                timestamp=ts,
                source_type=st,
                entropy_estimate_bits=ent_i,
                trust_level=trust_s,
                extra=extra,
            )
        )
        if len(self.refill_meta) > self._keep_meta:
            self.refill_meta = self.refill_meta[-self._keep_meta :]

    def _refill(self, nbytes: int) -> None:
        if nbytes <= 0:
            return

        if len(self._buf) >= self._max_bytes:
            return

        can_take = min(nbytes, self._max_bytes - len(self._buf))
        if can_take <= 0:
            return

        chunk = self._source.next_key(can_take)
        if not isinstance(chunk, (bytes, bytearray)):
            raise TypeError("KeySource.next_key must return bytes-like")
        if len(chunk) != can_take:
            raise RuntimeError(
                f"KeySource returned unexpected length: expected {can_take}, got {len(chunk)}"
            )

        self._buf.extend(chunk)
        self.stats.acquired_bytes += can_take
        self.stats.refills += 1

        # Stage148: record meta each refill
        self._record_meta()


class QKDKeyPool(KeyPool):
    def __init__(
        self,
        source: Optional[KeySource] = None,
        *,
        src_type: QKDKeySourceType | str = QKDKeySourceType.OS,
        file_path: Optional[str] = None,
        min_bytes: int = 4096,
        refill_bytes: int = 16384,
        max_bytes: int = 1_048_576,
        keep_meta: int = 32,
    ) -> None:
        if source is None:
            source = create_qkd_source(src_type, file_path=file_path)
        super().__init__(
            source,
            min_bytes=min_bytes,
            refill_bytes=refill_bytes,
            max_bytes=max_bytes,
            keep_meta=keep_meta,
        )
