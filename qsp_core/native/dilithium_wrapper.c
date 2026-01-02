// MIT License © 2025 Motohiro Suzuki
// Stage144: PQClean ML-DSA-65 wrapper dylib for ctypes
//
// Exports TWO API sets:
//
// (A) Algorithm-specific (keeps compatibility with your current naming)
//   - qsp_dilithium_publickeybytes
//   - qsp_dilithium_secretkeybytes
//   - qsp_dilithium_signaturebytes
//   - qsp_dilithium_keypair
//   - qsp_dilithium_sign
//   - qsp_dilithium_verify
//
// (B) Generic QSP signature API (recommended for Stage144 "可換性")
//   - qsp_sig_publickey_bytes
//   - qsp_sig_secretkey_bytes
//   - qsp_sig_signature_bytes
//   - qsp_sig_keypair
//   - qsp_sig_sign
//   - qsp_sig_verify
//
// Backing implementation: PQClean ML-DSA-65 (clean)

#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define QSP_EXPORT __attribute__((visibility("default")))
#else
#define QSP_EXPORT
#endif

// ★ ここが重要：パスは書かない（Makefile の -I で api.h の場所を教える）
#include "api.h"

// =========================
// (A) Algorithm-specific API
// =========================

QSP_EXPORT int qsp_dilithium_publickeybytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
}

QSP_EXPORT int qsp_dilithium_secretkeybytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
}

QSP_EXPORT int qsp_dilithium_signaturebytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
}

QSP_EXPORT int qsp_dilithium_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

QSP_EXPORT int qsp_dilithium_sign(
    uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *sk
) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk);
}

QSP_EXPORT int qsp_dilithium_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *pk
) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
}

// =========================
// (B) Generic QSP signature API
// =========================

QSP_EXPORT int qsp_sig_publickey_bytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
}

QSP_EXPORT int qsp_sig_secretkey_bytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
}

QSP_EXPORT int qsp_sig_signature_bytes(void) {
    return PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
}

QSP_EXPORT int qsp_sig_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

QSP_EXPORT int qsp_sig_sign(
    uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *sk
) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk);
}

QSP_EXPORT int qsp_sig_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *pk
) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
}
