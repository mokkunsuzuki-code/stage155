# MIT License © 2025 Motohiro Suzuki
"""
Stage148: QKD (E91) simulation via Qiskit as a KeySource component.

Outputs per batch:
- raw key bytes (sifted key material)
- QBER (estimated from key basis samples)
- CHSH S value (Bell inequality correlation)

Design note:
- This module is intentionally a pure "generator" (no networking).
- It can be used by KeySource (see key_source.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple
import math
import time

try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
except Exception as e:
    QuantumCircuit = None  # type: ignore
    AerSimulator = None  # type: ignore
    _QISKIT_IMPORT_ERROR = e
else:
    _QISKIT_IMPORT_ERROR = None


def _require_qiskit() -> None:
    if QuantumCircuit is None or AerSimulator is None:
        raise RuntimeError(f"Qiskit/Aer is not available: {_QISKIT_IMPORT_ERROR}")


def _epr_pair(c: "QuantumCircuit") -> None:
    # |Φ+> = (|00> + |11>)/sqrt(2)
    c.h(0)
    c.cx(0, 1)


def _measure_in_x(c: "QuantumCircuit", qubit: int) -> None:
    # X measurement = H then Z-measure
    c.h(qubit)


def _measure_angle_xz_plane(c: "QuantumCircuit", qubit: int, theta: float) -> None:
    """
    Measure along axis in X-Z plane:
      theta=0 -> Z
      theta=pi/2 -> X
    Implement by Ry(-theta) then Z measure.
    """
    c.ry(-theta, qubit)


def _exp_from_counts(counts: Dict[str, int]) -> float:
    """
    Expectation E = <A*B>, A,B in {+1,-1}
    Using bits a,b with mapping: 0->+1, 1->-1
    For correlation: (+1) if a==b, (-1) if a!=b
    E = sum (-1)^(a xor b) P(ab)
    """
    total = sum(counts.values()) or 1
    e = 0.0
    for bitstr, c in counts.items():
        # Qiskit counts order after measure(0->c0,1->c1) is "c1c0"
        b = int(bitstr[0])  # Bob
        a = int(bitstr[1])  # Alice
        parity = a ^ b
        e += ((-1.0) ** parity) * (c / total)
    return e


def _pack_bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    acc = 0
    n = 0
    for bit in bits:
        acc = (acc << 1) | (bit & 1)
        n += 1
        if n == 8:
            out.append(acc)
            acc = 0
            n = 0
    if n:
        out.append(acc << (8 - n))
    return bytes(out)


def _extract_key_bits_and_qber(counts: Dict[str, int]) -> Tuple[list[int], float]:
    bits: list[int] = []
    err = 0
    tot = 0
    for bitstr, c in counts.items():
        b = int(bitstr[0])
        a = int(bitstr[1])
        tot += c
        if a != b:
            err += c
        bits.extend([a] * c)
    qber = (err / tot) if tot else 0.0
    return bits, float(qber)


@dataclass
class E91Metrics:
    created_at_unix: float
    raw_bits: int
    qber: float
    chsh_s: float


def e91_generate(
    *,
    shots_key: int = 2048,
    shots_chsh: int = 2048,
) -> Tuple[bytes, E91Metrics]:
    """
    Generate raw key bytes and metrics.

    Key generation uses:
      - ZZ measurement batch
      - XX measurement batch
    raw key bits = concat(ZZ bits, XX bits)

    CHSH uses 4 settings in X-Z plane:
      a0=Z, a1=X, b0=pi/4, b1=-pi/4
      S = E(a0,b0)+E(a0,b1)+E(a1,b0)-E(a1,b1)
    """
    _require_qiskit()
    sim = AerSimulator()

    # ---- Key (ZZ, XX) ----
    c_zz = QuantumCircuit(2, 2)
    _epr_pair(c_zz)
    c_zz.measure(0, 0)  # Alice -> c0
    c_zz.measure(1, 1)  # Bob   -> c1

    c_xx = QuantumCircuit(2, 2)
    _epr_pair(c_xx)
    _measure_in_x(c_xx, 0)
    _measure_in_x(c_xx, 1)
    c_xx.measure(0, 0)
    c_xx.measure(1, 1)

    job = sim.run([c_zz, c_xx], shots=shots_key)
    res = job.result()
    counts_zz = res.get_counts(0)
    counts_xx = res.get_counts(1)

    bits_zz, qber_zz = _extract_key_bits_and_qber(counts_zz)
    bits_xx, qber_xx = _extract_key_bits_and_qber(counts_xx)
    raw_bits = bits_zz + bits_xx
    raw_key = _pack_bits_to_bytes(raw_bits)

    # Weighted-ish QBER (shots are identical per circuit, so mean is fine)
    qber = (qber_zz + qber_xx) / 2.0

    # ---- CHSH ----
    a0 = 0.0
    a1 = math.pi / 2.0
    b0 = math.pi / 4.0
    b1 = -math.pi / 4.0

    def corr(theta_a: float, theta_b: float) -> float:
        c = QuantumCircuit(2, 2)
        _epr_pair(c)
        _measure_angle_xz_plane(c, 0, theta_a)
        _measure_angle_xz_plane(c, 1, theta_b)
        c.measure(0, 0)
        c.measure(1, 1)
        r = sim.run(c, shots=shots_chsh).result()
        return _exp_from_counts(r.get_counts(0))

    E00 = corr(a0, b0)
    E01 = corr(a0, b1)
    E10 = corr(a1, b0)
    E11 = corr(a1, b1)
    chsh_s = float(E00 + E01 + E10 - E11)

    metrics = E91Metrics(
        created_at_unix=time.time(),
        raw_bits=len(raw_bits),
        qber=float(qber),
        chsh_s=chsh_s,
    )
    return raw_key, metrics
