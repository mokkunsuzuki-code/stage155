# MIT License © 2025 Motohiro Suzuki
"""
Stage141: Signature adapter

This layer bridges:
- QSP handshake logic (wants a "sign(msg)->sig", "verify(msg,sig)->bool")
- Signature engines (HMAC or SPHINCS+ PQClean)

For Stage141 demo stability:
- We store a SPHINCS+ keypair under vendor/keys/ so both client/server share it.
  (This is NOT production; it's for deterministic local integration testing.)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

from qsp_core.sig_engine import (
    SignatureEngine,
    make_engine,
    PQCleanSphincsSHA2128fSimpleClean,
    _default_dylib_path,
)


def _project_root() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent  # qsp_core/.. -> stage141/


def _keys_dir() -> Path:
    return _project_root() / "vendor" / "keys"


def _pk_path() -> Path:
    return _keys_dir() / "sphincs_sha2_128f_simple_pk.bin"


def _sk_path() -> Path:
    return _keys_dir() / "sphincs_sha2_128f_simple_sk.bin"


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _read_exact(p: Path, n: int) -> bytes:
    b = p.read_bytes()
    if len(b) != n:
        raise ValueError(f"Invalid key file size: {p} len={len(b)} expected={n}")
    return b


def ensure_sphincs_keypair(dylib_path: Optional[str] = None) -> Tuple[bytes, bytes]:
    """
    Ensure SPHINCS+ keypair exists on disk. If missing, generate via dylib and store.

    Returns: (pk, sk)
    """
    if dylib_path is None:
        dylib_path = _default_dylib_path()

    kdir = _keys_dir()
    _ensure_dir(kdir)

    pkp = _pk_path()
    skp = _sk_path()

    api = PQCleanSphincsSHA2128fSimpleClean(dylib_path)

    if pkp.exists() and skp.exists():
        pk = _read_exact(pkp, api.PK_BYTES)
        sk = _read_exact(skp, api.SK_BYTES)
        return pk, sk

    # Generate new keypair
    pk, sk = api.keypair()

    # Atomic-ish write
    pkp.write_bytes(pk)
    skp.write_bytes(sk)

    return pk, sk


def build_signature_engine(sig_name: str, *, shared_hmac_key: Optional[bytes] = None,
                           dylib_path: Optional[str] = None) -> SignatureEngine:
    """
    Create an engine instance for Stage141.

    - If sig_name == "SPHINCS+": load/generate keypair from vendor/keys
    - If sig_name == "HMAC": requires shared_hmac_key
    """
    n = (sig_name or "").upper()

    if n in ("SPHINCS+", "SPHINCS", "SPHINCS_PQCLEAN"):
        if dylib_path is None:
            dylib_path = _default_dylib_path()
        pk, sk = ensure_sphincs_keypair(dylib_path=dylib_path)
        return make_engine("SPHINCS+", pk=pk, sk=sk, dylib_path=dylib_path)

    # baseline
    if shared_hmac_key is None:
        raise ValueError("HMAC engine requires shared_hmac_key")
    return make_engine("HMAC", key=shared_hmac_key)


def sign_bytes(engine: SignatureEngine, msg: bytes) -> bytes:
    return engine.sign(msg)


def verify_bytes(engine: SignatureEngine, msg: bytes, sig: bytes) -> bool:
    return engine.verify(msg, sig)
