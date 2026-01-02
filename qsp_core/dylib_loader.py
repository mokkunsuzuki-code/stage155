# MIT License © 2025 Motohiro Suzuki
"""
qsp_core/dylib_loader.py

Stage144: PQClean dylib backend loader (macOS/Linux)

目的:
- ctypes.CDLL で .dylib をロードする
- macOSで @rpath 依存が解決できないケースを自動救済する
  (例: libqsp_dilithium_wrapper.dylib が @rpath/libml_dsa_65_clean.dylib を要求するが見つからない)

戦略:
1) まず通常ロード
2) OSError で依存不足が疑われたら:
   - 依存 dylib を探索（同ディレクトリ / vendor/PQClean 配下）
   - 依存を RTLD_GLOBAL で先にロード
   - wrapper を再ロード
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Iterable, Optional, Sequence


class DylibLoadError(RuntimeError):
    pass


def _project_root() -> Path:
    # qsp_core/dylib_loader.py -> stage144/ が root
    return Path(__file__).resolve().parents[1]


def _iter_search_paths(wrapper_path: Path) -> Iterable[Path]:
    """
    依存 dylib 探索パスの候補を返す（優先順）
    """
    root = _project_root()

    # 1) wrapper と同じフォルダ（Aルートで依存を qsp_core/native に置く想定）
    yield wrapper_path.parent

    # 2) プロジェクト直下の qsp_core/native（念のため）
    yield root / "qsp_core" / "native"

    # 3) vendor/PQClean 配下（今回の find 結果に対応）
    yield root / "vendor" / "PQClean" / "crypto_sign" / "ml-dsa-65" / "clean"
    yield root / "vendor" / "PQClean" / "crypto_sign" / "ml-dsa-65" / "clean" / "lib"

    # 4) それでもダメなら vendor/PQClean 全体を軽く当たる（最後の手段）
    yield root / "vendor" / "PQClean"


def _find_file_in_paths(filename: str, paths: Sequence[Path]) -> Optional[Path]:
    """
    与えられた paths の直下から filename を探す。
    どうしても見つからなければ最後に vendor/PQClean だけ再帰検索する（重いので限定）。
    """
    # まずは直下探索
    for p in paths:
        try:
            cand = (p / filename)
            if cand.is_file():
                return cand
        except Exception:
            continue

    # 最後の手段：vendor/PQClean 再帰（root/vendor/PQClean のみ）
    root = _project_root()
    pqclean = root / "vendor" / "PQClean"
    if pqclean.exists():
        try:
            for cand in pqclean.rglob(filename):
                if cand.is_file():
                    return cand
        except Exception:
            pass

    return None


def _is_missing_ml_dsa_dep(err: OSError) -> bool:
    s = str(err)
    # 代表例:
    # Library not loaded: @rpath/libml_dsa_65_clean.dylib
    return ("libml_dsa_65_clean.dylib" in s) and ("Library not loaded" in s or "image not found" in s)


def load_dylib(path: str, *, preload_deps: bool = True) -> ctypes.CDLL:
    """
    指定された dylib をロードして ctypes.CDLL を返す。
    macOSで @rpath 依存が解決できない場合は自動救済する。
    """
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise DylibLoadError(f"dylib not found: {p}")

    # まず通常ロード
    try:
        return ctypes.CDLL(str(p))
    except OSError as e:
        if not preload_deps:
            raise DylibLoadError(f"failed to load dylib: {p}\n{e}") from e

        # 依存不足なら救済
        if _is_missing_ml_dsa_dep(e):
            # 依存 dylib を探して先にロードする
            search_paths = list(_iter_search_paths(p))
            dep = _find_file_in_paths("libml_dsa_65_clean.dylib", search_paths)
            if dep is None:
                raise DylibLoadError(
                    "Missing dependency: libml_dsa_65_clean.dylib\n"
                    f"Wrapper: {p}\n"
                    "Tried search paths:\n"
                    + "\n".join([f" - {sp}" for sp in search_paths])
                    + "\n\n"
                    "対処(Aルート):\n"
                    "  cp vendor/PQClean/crypto_sign/ml-dsa-65/clean/libml_dsa_65_clean.dylib qsp_core/native/\n"
                    "  install_name_tool -add_rpath \"@loader_path\" qsp_core/native/libqsp_dilithium_wrapper.dylib\n"
                ) from e

            # 依存を RTLD_GLOBAL で先にロード（wrapper の dlopen が参照できるようにする）
            try:
                ctypes.CDLL(str(dep), mode=ctypes.RTLD_GLOBAL)
            except OSError as e2:
                raise DylibLoadError(f"failed to preload dependency: {dep}\n{e2}") from e2

            # もう一度 wrapper をロード
            try:
                return ctypes.CDLL(str(p))
            except OSError as e3:
                raise DylibLoadError(
                    "failed to load wrapper even after preloading dependency.\n"
                    f"wrapper: {p}\n"
                    f"dependency: {dep}\n"
                    f"error: {e3}"
                ) from e3

        # それ以外の OSError はそのまま返す
        raise DylibLoadError(f"failed to load dylib: {p}\n{e}") from e


def get_env_dylib_path(env_key: str) -> Optional[str]:
    v = os.environ.get(env_key, "")
    v = v.strip()
    return v or None
