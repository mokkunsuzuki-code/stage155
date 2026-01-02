# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from math import pi
from typing import Dict, Any, Optional, List
import os

# E91 depends on qiskit + qiskit-aer
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


@dataclass(frozen=True)
class E91Metrics:
    raw_bits: int
    raw_bytes: int
    qber: float
    chsh_s: float


def _pack_bits_to_bytes(bitstr: str) -> bytes:
    pad = (-len(bitstr)) % 8
    s = bitstr + ("0" * pad)
    out = bytearray()
    for i in range(0, len(s), 8):
        out.append(int(s[i:i+8], 2))
    return bytes(out)


def _measure_in_basis(qc: QuantumCircuit, qubit: int, theta: float) -> None:
    qc.ry(-theta, qubit)


def _make_bell_pair_circuit(theta_a: float, theta_b: float) -> QuantumCircuit:
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    _measure_in_basis(qc, 0, theta_a)
    _measure_in_basis(qc, 1, theta_b)
    qc.measure(0, 0)
    qc.measure(1, 1)
    return qc


def _run_counts(sim: AerSimulator, theta_a: float, theta_b: float, shots: int) -> Dict[str, int]:
    qc = _make_bell_pair_circuit(theta_a, theta_b)
    job = sim.run(qc, shots=shots)
    res = job.result()
    return res.get_counts(qc)


def _corr_from_counts(counts: Dict[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0

    def s(bit: str) -> int:
        return +1 if bit == "0" else -1

    acc = 0
    for key, n in counts.items():
        k = key.replace(" ", "")
        if len(k) != 2:
            continue
        b = k[0]
        a = k[1]
        acc += s(a) * s(b) * n
    return acc / total


def _qber_from_counts_zz(counts: Dict[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    err = 0
    for key, n in counts.items():
        k = key.replace(" ", "")
        if len(k) != 2:
            continue
        b = k[0]
        a = k[1]
        if a != b:
            err += n
    return err / total


class E91KeySource:
    def __init__(self, shots_key: int = 2048, shots_chsh: int = 2048, seed: Optional[int] = None) -> None:
        self.sim = AerSimulator()
        self.shots_key = int(shots_key)
        self.shots_chsh = int(shots_chsh)
        self.seed = seed

        # CHSH-max angles
        self.theta_a0 = 0.0
        self.theta_a1 = pi / 2
        self.theta_b0 = pi / 4
        self.theta_b1 = -pi / 4

        self._buf = bytearray()
        self._meta: Dict[str, Any] = {}

    def last_meta(self) -> Dict[str, Any]:
        return dict(self._meta)

    def next_key(self, nbytes: int) -> bytes:
        if nbytes <= 0:
            raise ValueError("nbytes must be positive")
        while len(self._buf) < nbytes:
            m, raw = self._generate_once()
            self._buf.extend(raw)
            self._meta = {
                "source_type": "QKD_E91",
                "raw_bits": m.raw_bits,
                "raw_bytes": m.raw_bytes,
                "qber": m.qber,
                "chsh_s": m.chsh_s,
                "shots_key": self.shots_key,
                "shots_chsh": self.shots_chsh,
                "seed": self.seed,
                "trust_level": "simulated/e91",
                "entropy_estimate": max(0.0, min(1.0, 1.0 - m.qber)),
            }
        out = bytes(self._buf[:nbytes])
        del self._buf[:nbytes]
        return out

    def _generate_once(self) -> tuple[E91Metrics, bytes]:
        # KEY part (use Z/Z style)
        counts_zz = _run_counts(self.sim, self.theta_a0, self.theta_b0, shots=self.shots_key)
        qber = float(_qber_from_counts_zz(counts_zz))

        bits: List[str] = []
        for key, n in counts_zz.items():
            k = key.replace(" ", "")
            if len(k) != 2:
                continue
            alice_bit = k[1]
            bits.extend([alice_bit] * n)

        # deterministic shuffle if seed set (to emulate shared source)
        if self.seed is not None:
            import random
            r = random.Random(self.seed)
            r.shuffle(bits)

        raw_key_bits = "".join(bits)
        raw_key_bytes = _pack_bits_to_bytes(raw_key_bits)

        # CHSH
        c_a0b0 = _run_counts(self.sim, self.theta_a0, self.theta_b0, shots=self.shots_chsh)
        c_a0b1 = _run_counts(self.sim, self.theta_a0, self.theta_b1, shots=self.shots_chsh)
        c_a1b0 = _run_counts(self.sim, self.theta_a1, self.theta_b0, shots=self.shots_chsh)
        c_a1b1 = _run_counts(self.sim, self.theta_a1, self.theta_b1, shots=self.shots_chsh)

        e_a0b0 = _corr_from_counts(c_a0b0)
        e_a0b1 = _corr_from_counts(c_a0b1)
        e_a1b0 = _corr_from_counts(c_a1b0)
        e_a1b1 = _corr_from_counts(c_a1b1)
        s_val = float(e_a0b0 + e_a0b1 + e_a1b0 - e_a1b1)

        m = E91Metrics(
            raw_bits=len(raw_key_bits),
            raw_bytes=len(raw_key_bytes),
            qber=qber,
            chsh_s=s_val,
        )
        return m, raw_key_bytes


def e91_from_env() -> E91KeySource:
    shots_key = int(os.getenv("QSP_E91_SHOTS_KEY", "2048"))
    shots_chsh = int(os.getenv("QSP_E91_SHOTS_CHSH", "2048"))
    seed_s = os.getenv("QSP_E91_SEED", "").strip()
    seed = int(seed_s) if seed_s else None
    return E91KeySource(shots_key=shots_key, shots_chsh=shots_chsh, seed=seed)
