// MIT License © 2025 Motohiro Suzuki
// Stage144: PQClean SPHINCS+ wrapper dylib for ctypes
//
// Exports symbols expected by qsp_core/sig_backends.py (prefix="qsp_sig"):
//  - qsp_sig_publickeybytes
//  - qsp_sig_secretkeybytes
//  - qsp_sig_signaturebytes
//  - qsp_sig_keypair
//  - qsp_sig_sign
//  - qsp_sig_verify
//
// Backing implementation: PQClean SPHINCS+ shake-256s-simple (clean)

#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define QSP_EXPORT __attribute__((visibility("default")))
#else
#define QSP_EXPORT
#endif

// IMPORTANT: do NOT hardcode a path. Provide include path via -I in Makefile.
#include "api.h"

// -----------------------------
// Size getters (EXPECTED NAMES)
// -----------------------------

QSP_EXPORT int qsp_sig_publickeybytes(void) {
    return (int)PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
}

QSP_EXPORT int qsp_sig_secretkeybytes(void) {
    return (int)PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
}

QSP_EXPORT int qsp_sig_signaturebytes(void) {
    return (int)PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES;
}

// -----------------------------
// Keypair / Sign / Verify
// -----------------------------

QSP_EXPORT int qsp_sig_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

QSP_EXPORT int qsp_sig_sign(
    uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *sk
) {
    // PQClean signature API: (sig, siglen, msg, msglen, sk)
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk);
}

QSP_EXPORT int qsp_sig_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *pk
) {
    // PQClean verify API: (sig, siglen, msg, msglen, pk)
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
}

// ------------------------------------------------------
// (OPTIONAL) Backward-compat aliases (old underscore names)
// If you previously tested with these names, keep them.
// They forward to the canonical names above.
// ------------------------------------------------------

QSP_EXPORT int qsp_sig_publickey_bytes(void) { return qsp_sig_publickeybytes(); }
QSP_EXPORT int qsp_sig_secretkey_bytes(void) { return qsp_sig_secretkeybytes(); }
QSP_EXPORT int qsp_sig_signature_bytes(void) { return qsp_sig_signaturebytes(); }
