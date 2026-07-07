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

// If out length is less than CX_SHA256_SIZE
// this function will throw an exception
void hash_sha256(uint8_t *in, uint32_t in_len, uint8_t *out) {
    crypto_sha256_one_shot(out, CX_SHA256_SIZE, in, in_len);
}

// Computes RIPEMD-160 of `in` into `out` (20 bytes). Used by the Rust multisig
// address derivation to form Hash160 = RIPEMD160(SHA256(redeem_script)).
void hash_ripemd160(uint8_t *in, uint32_t in_len, uint8_t *out) {
#if defined(LEDGER_SPECIFIC)
    cx_ripemd160_t ctx;
    cx_ripemd160_init_no_throw(&ctx);
    cx_hash_no_throw(&ctx.header, CX_LAST, in, in_len, out, CX_RIPEMD160_SIZE);
#else
    (void)in;
    (void)in_len;
    (void)out;
#endif
}