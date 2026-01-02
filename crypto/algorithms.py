# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlgorithmSuite:
    supported_sigs: list[str]
    supported_kems: list[str]
    supported_aeads: list[str]


def select_first_match(client: list[str], server: list[str]) -> str | None:
    client_l = [c.strip().lower() for c in client]
    server_l = [s.strip().lower() for s in server]
    for c in client_l:
        if c in server_l:
            return c
    return None
