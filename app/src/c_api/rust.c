#include "rust.h"  // Include our own header

#include <inttypes.h>
#include <zxformat.h>
#include <zxmacros.h>

#include "crypto_helper.h"

#if defined(LEDGER_SPECIFIC)
#include "cx.h"
#include "os.h"
#endif

uint16_t fp_uint64_to_str(char *out, uint16_t outLen, const uint64_t value, uint8_t decimals) {
    return fpuint64_to_str(out, outLen, value, decimals);
}

void check_canary() {
    CHECK_APP_CANARY()
}

void _zemu_log_stack(char *buffer) {
    zemu_log_stack(buffer);
}

// Computes SHA-256 of `in` into `out` (CX_SHA256_SIZE bytes). Returns false, with `out`
// zeroed, if the digest could not be computed: the caller must not use a zero digest as if it
// were the real one. It feeds the SIP-018 and JWT hashes and the c32 checksum.
bool hash_sha256(uint8_t *in, uint32_t in_len, uint8_t *out) {
    if (crypto_sha256_one_shot(out, CX_SHA256_SIZE, in, in_len) != zxerr_ok) {
        MEMZERO(out, CX_SHA256_SIZE);
        return false;
    }
    return true;
}

// Computes RIPEMD-160 of `in` into `out` (20 bytes). Used by the Rust multisig
// address derivation to form Hash160 = RIPEMD160(SHA256(redeem_script)).
// Returns false, with `out` zeroed, on failure, so no address is built from a zero hash.
bool hash_ripemd160(uint8_t *in, uint32_t in_len, uint8_t *out) {
#if defined(LEDGER_SPECIFIC)
    cx_ripemd160_t ctx;
    if (cx_ripemd160_init_no_throw(&ctx) != CX_OK ||
        cx_hash_no_throw(&ctx.header, CX_LAST, in, in_len, out, CX_RIPEMD160_SIZE) != CX_OK) {
        MEMZERO(out, CX_RIPEMD160_SIZE);
        return false;
    }
    return true;
#else
    // Host builds have no RIPEMD-160; the Rust unit tests and the fuzzer hash with the ripemd
    // crate instead. Fail rather than hand back an uninitialised digest.
    (void)in;
    (void)in_len;
    MEMZERO(out, 20);
    return false;
#endif
}