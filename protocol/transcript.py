# MIT License © 2025 Motohiro Suzuki
"""
Stage152: Transcript (TBS) — canonical encodings.
These definitions are FIXED to preserve security boundary under algorithm swapping.
"""

from __future__ import annotations


def _u16(x: int) -> bytes:
    if x < 0 or x > 0xFFFF:
        raise ValueError("u16 out of range")
    return x.to_bytes(2, "big")


def _u32(x: int) -> bytes:
    if x < 0 or x > 0xFFFFFFFF:
        raise ValueError("u32 out of range")
    return x.to_bytes(4, "big")


def _blob(b: bytes) -> bytes:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    b = bytes(b)
    return _u32(len(b)) + b


def _list_str(xs: list[str]) -> bytes:
    if not isinstance(xs, list):
        raise TypeError("xs must be list[str]")
    out = _u16(len(xs))
    for s in xs:
        if not isinstance(s, str):
            raise TypeError("list element must be str")
        sb = s.encode("utf-8")
        out += _u16(len(sb)) + sb
    return out


def handshake_tbs(
    client_nonce: bytes,
    supported_sigs: list[str],
    supported_kems: list[str],
    supported_aeads: list[str],
    client_sig_pk: bytes,
) -> bytes:
    return (
        b"QSP152|handshake_tbs|"
        + _blob(client_nonce)
        + _list_str(supported_sigs)
        + _list_str(supported_kems)
        + _list_str(supported_aeads)
        + _blob(client_sig_pk)
    )


def handshake_ack_tbs(
    client_hello_no_sig: bytes,
    server_nonce: bytes,
    selected_sig: str,
    selected_kem: str,
    selected_aead: str,
    server_sig_pk: bytes,
) -> bytes:
    return (
        b"QSP152|handshake_ack_tbs|"
        + _blob(client_hello_no_sig)
        + _blob(server_nonce)
        + _u16(len(selected_sig.encode("utf-8"))) + selected_sig.encode("utf-8")
        + _u16(len(selected_kem.encode("utf-8"))) + selected_kem.encode("utf-8")
        + _u16(len(selected_aead.encode("utf-8"))) + selected_aead.encode("utf-8")
        + _blob(server_sig_pk)
    )


def data_tbs(header_bytes: bytes, ciphertext: bytes) -> bytes:
    return b"QSP152|data_tbs|" + _blob(header_bytes) + _blob(ciphertext)


def rekey_tbs(old_epoch: int, new_epoch: int, material: bytes) -> bytes:
    return b"QSP152|rekey_tbs|" + _u32(old_epoch) + _u32(new_epoch) + _blob(material)
