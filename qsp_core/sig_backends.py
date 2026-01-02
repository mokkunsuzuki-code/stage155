# MIT License © 2025 Motohiro Suzuki
"""
Stage150: Signature backends (ctypes wrapper)

macOS nm tip:
- 'T _qsp_sig_publickeybytes' means TEXT symbol => function.
- If we mistakenly read it via c_size_t.in_dll (global), we will "read" the function
  address as a size => absurdly huge numbers.
Therefore, we MUST prefer calling the function first, then fallback to global.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, Sequence

import ctypes


# -----------------------------
# Public types
# -----------------------------

@dataclass(frozen=True)
class SignatureKeyPair:
    public_key: bytes
    secret_key: bytes


class SignatureBackend(Protocol):
    name: str

    def keypair(self) -> SignatureKeyPair: ...
    def sign(self, msg: bytes, sk: bytes) -> bytes: ...
    def verify(self, sig: bytes, msg: bytes, pk: bytes) -> bool: ...


class SigBackendError(RuntimeError):
    pass


# -----------------------------
# ctypes helpers
# -----------------------------

_MAX_REASONABLE_SIZE = 1_000_000  # sanity cap (bytes)


def _load_dylib(path: Path) -> ctypes.CDLL:
    if not isinstance(path, Path):
        raise TypeError("path must be Path")
    if not path.exists():
        raise FileNotFoundError(f"dylib not found: {path}")
    return ctypes.CDLL(str(path))


def _first_symbol(lib: ctypes.CDLL, names: Sequence[str]) -> str:
    for n in names:
        try:
            getattr(lib, n)
            return n
        except AttributeError:
            continue
    raise SigBackendError(f"required symbol not found; tried {list(names)}")


def _validate_size(name: str, v: int) -> int:
    if not isinstance(v, int):
        raise SigBackendError(f"{name}: size is not int: {type(v).__name__}")
    if v <= 0:
        raise SigBackendError(f"{name}: size must be positive, got {v}")
    if v > _MAX_REASONABLE_SIZE:
        raise SigBackendError(f"{name}: size too large (likely mis-read): {v}")
    return v


def _try_call_size_t_function(lib: ctypes.CDLL, sym: str) -> Optional[int]:
    """
    Try calling an exported function that returns size_t.
    Returns int if successful; otherwise None.
    """
    try:
        fn = getattr(lib, sym)
    except AttributeError:
        return None

    try:
        fn.argtypes = []
        fn.restype = ctypes.c_size_t
        v = fn()
        return int(v)
    except Exception:
        return None


def _try_read_size_t_global(lib: ctypes.CDLL, sym: str) -> Optional[int]:
    """
    Try reading an exported size_t global variable.
    Returns int if successful; otherwise None.

    NOTE: For TEXT symbols (functions), in_dll can "succeed" but will read the address.
    Therefore this must be used ONLY as fallback after function call attempt.
    """
    try:
        v = ctypes.c_size_t.in_dll(lib, sym).value
        return int(v)
    except Exception:
        return None


def _first_size(lib: ctypes.CDLL, names: Sequence[str], label: str) -> int:
    """
    Resolve a size provider from candidates.

    Order (IMPORTANT):
      1) size_t returning function (call)  <-- preferred for your wrapper (nm shows 'T')
      2) size_t global (in_dll)            <-- fallback only

    Strict sanity check prevents using function addresses as sizes.
    """
    last_err: Optional[Exception] = None

    for sym in names:
        # (1) function returning size_t
        v = _try_call_size_t_function(lib, sym)
        if v is not None:
            try:
                return _validate_size(f"{label}:{sym}(func)", v)
            except Exception as e:
                last_err = e
                # try next candidate
                continue

        # (2) global size_t (fallback)
        v = _try_read_size_t_global(lib, sym)
        if v is not None:
            try:
                return _validate_size(f"{label}:{sym}(global)", v)
            except Exception as e:
                last_err = e
                continue

    raise SigBackendError(f"{label}: size symbol not found/invalid; tried {list(names)}") from last_err


# -----------------------------
# PQClean (SPHINCS+/etc) backend
# -----------------------------

class PQCleanCtypesBackend:
    """
    Wrapper for a PQClean-based signature dylib.

    Expects generic symbols:
      - qsp_sig_keypair / qsp_sig_sign / qsp_sig_verify
      - qsp_sig_publickeybytes / qsp_sig_secretkeybytes / qsp_sig_signaturebytes
        (often as FUNCTIONS returning size_t)
    """

    def __init__(self, *, name: str, dylib_path: Path) -> None:
        self.name = name
        self.dylib_path = dylib_path
        self.lib = _load_dylib(dylib_path)

        # --- size constants (function-first, then global) ---
        self.public_key_bytes = _first_size(
            self.lib,
            [
                "qsp_sphincs_publickeybytes",
                "qsp_publickeybytes",
                "qsp_sig_publickeybytes",
                "qsp_sig_publickey_bytes",
                "qsp_sig_pkbytes",
                "qsp_pkbytes",
            ],
            label=f"{self.name}.public_key_bytes",
        )

        self.secret_key_bytes = _first_size(
            self.lib,
            [
                "qsp_sphincs_secretkeybytes",
                "qsp_secretkeybytes",
                "qsp_sig_secretkeybytes",
                "qsp_sig_secretkey_bytes",
                "qsp_sig_skbytes",
                "qsp_skbytes",
            ],
            label=f"{self.name}.secret_key_bytes",
        )

        # signature size (try, but allow fallback)
        try:
            self.signature_bytes = _first_size(
                self.lib,
                [
                    "qsp_sphincs_signaturebytes",
                    "qsp_signaturebytes",
                    "qsp_sig_signaturebytes",
                    "qsp_sig_signature_bytes",
                    "qsp_sigbytes",
                ],
                label=f"{self.name}.signature_bytes",
            )
        except SigBackendError:
            self.signature_bytes = 64_000

        # --- function symbols ---
        keypair_sym = _first_symbol(self.lib, ["qsp_sig_keypair", "qsp_sphincs_keypair", "qsp_keypair"])
        sign_sym = _first_symbol(self.lib, ["qsp_sig_sign", "qsp_sphincs_sign", "qsp_sign"])
        verify_sym = _first_symbol(self.lib, ["qsp_sig_verify", "qsp_sphincs_verify", "qsp_verify"])

        self._keypair = getattr(self.lib, keypair_sym)
        self._sign = getattr(self.lib, sign_sym)
        self._verify = getattr(self.lib, verify_sym)

        # ctypes signatures
        # int keypair(uint8_t* pk, uint8_t* sk)
        self._keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._keypair.restype = ctypes.c_int

        # int sign(uint8_t* sig, size_t* siglen, const uint8_t* msg, size_t msglen, const uint8_t* sk)
        self._sign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        self._sign.restype = ctypes.c_int

        # int verify(const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen, const uint8_t* pk)
        self._verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        self._verify.restype = ctypes.c_int

    def keypair(self) -> SignatureKeyPair:
        pk = (ctypes.c_ubyte * int(self.public_key_bytes))()
        sk = (ctypes.c_ubyte * int(self.secret_key_bytes))()

        rc = int(self._keypair(ctypes.byref(pk), ctypes.byref(sk)))
        if rc != 0:
            raise SigBackendError(f"{self.name}: keypair failed rc={rc}")

        return SignatureKeyPair(bytes(pk), bytes(sk))

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg must be bytes")
        if not isinstance(sk, (bytes, bytearray)):
            raise TypeError("sk must be bytes")
        if len(sk) != self.secret_key_bytes:
            raise ValueError(f"sk length mismatch: got {len(sk)} expected {self.secret_key_bytes}")

        sig_buf = (ctypes.c_ubyte * int(self.signature_bytes))()
        sig_len = ctypes.c_size_t(0)

        rc = int(
            self._sign(
                ctypes.byref(sig_buf),
                ctypes.byref(sig_len),
                ctypes.c_char_p(bytes(msg)),
                ctypes.c_size_t(len(msg)),
                ctypes.c_char_p(bytes(sk)),
            )
        )
        if rc != 0:
            raise SigBackendError(f"{self.name}: sign failed rc={rc}")

        n = int(sig_len.value)
        if n <= 0 or n > int(self.signature_bytes):
            raise SigBackendError(f"{self.name}: invalid signature length returned: {n}")

        return bytes(sig_buf[:n])

    def verify(self, sig: bytes, msg: bytes, pk: bytes) -> bool:
        if not isinstance(sig, (bytes, bytearray)):
            raise TypeError("sig must be bytes")
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg must be bytes")
        if not isinstance(pk, (bytes, bytearray)):
            raise TypeError("pk must be bytes")
        if len(pk) != self.public_key_bytes:
            raise ValueError(f"pk length mismatch: got {len(pk)} expected {self.public_key_bytes}")

        rc = int(
            self._verify(
                ctypes.c_char_p(bytes(sig)),
                ctypes.c_size_t(len(sig)),
                ctypes.c_char_p(bytes(msg)),
                ctypes.c_size_t(len(msg)),
                ctypes.c_char_p(bytes(pk)),
            )
        )
        return rc == 0


# -----------------------------
# Factory
# -----------------------------

def get_sig_backend(sig_alg: str) -> SignatureBackend:
    if not isinstance(sig_alg, str) or not sig_alg.strip():
        raise TypeError("sig_alg must be non-empty str")

    alg = sig_alg.strip().lower()

    base = Path(__file__).resolve().parent.parent  # stage150/qsp_core -> stage150
    vendor = base / "vendor"

    if alg in ("sphincs", "sphincs+", "sphincsplus"):
        dylib = vendor / "libqsp_sphincs_wrapper.dylib"
        return PQCleanCtypesBackend(name="sphincs", dylib_path=dylib)

    if alg in ("dilithium", "mldsa", "ml-dsa"):
        dylib = vendor / "libqsp_dilithium_wrapper.dylib"
        return PQCleanCtypesBackend(name="dilithium", dylib_path=dylib)

    raise ValueError(f"unsupported sig_alg: {sig_alg}")
