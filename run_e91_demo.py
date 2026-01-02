# MIT License © 2025 Motohiro Suzuki
"""
Stage148 Demo: run E91 KeySource and print:
- CHSH S value
- QBER
- raw key length + sample

How to run:
  python3 run_e91_demo.py
"""

from __future__ import annotations

from qsp_core.keysource_e91 import E91KeySource


def main() -> None:
    src = E91KeySource(seed=1234)

    rep = src.generate(
        key_shots=4096,    # key material from Z/Z
        chsh_shots=8192,   # CHSH estimation
    )

    print("=== Stage148: E91 KeySource (Standalone) ===")
    print(f"timestamp(utc): {rep.timestamp_utc}")
    print(f"CHSH S        : {rep.chsh_s:.4f}   (classical<=2, quantum up to ~2.828)")
    print(f"QBER          : {rep.qber:.6f}")
    print(f"raw_key_bits  : {len(rep.raw_key_bits)} bits")
    print(f"raw_key_bytes : {len(rep.raw_key_bytes)} bytes")
    print(f"entropy_est   : {rep.entropy_estimate:.3f} (rough)")
    print(f"trust_level   : {rep.trust_level:.3f} (rough)")
    # show first 32 bytes as hex (safe small preview)
    preview = rep.raw_key_bytes[:32].hex()
    print(f"key_preview   : {preview} ...")


if __name__ == "__main__":
    main()
