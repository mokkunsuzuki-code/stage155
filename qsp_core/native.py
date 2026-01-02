# MIT License © 2025 Motohiro Suzuki
"""
Stage145: canonical native loader entrypoint

Purpose:
- Provide a stable import path: `from qsp_core.native import load_dylib`
- Internally delegate to existing `qsp_core.dylib_loader`

This keeps higher-level modules (e.g., sig_backends.py) independent from
the actual loader module name.
"""

from __future__ import annotations

from ctypes import CDLL
from typing import Optional

# Delegate to your existing loader module.
# Your project already has: qsp_core/dylib_loader.py
from .dylib_loader import load_dylib as _load_dylib


def load_dylib(path: str, *, mode: Optional[int] = None) -> CDLL:
    """
    Load a .dylib (or shared library) and return ctypes.CDLL.

    Args:
        path: Path to dylib (absolute or relative).
        mode: Optional ctypes dlopen mode (rarely needed on macOS).
    """
    # If your dylib_loader.load_dylib doesn't accept mode, we ignore it safely.
    try:
        return _load_dylib(path, mode=mode)  # type: ignore[arg-type]
    except TypeError:
        return _load_dylib(path)  # type: ignore[call-arg]
