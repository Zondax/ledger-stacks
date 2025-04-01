#include <inttypes.h>
#include <zxformat.h>
#include <zxmacros.h>

#include "cx.h"
#include "os.h"

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
    cx_hash_sha256(in, in_len, out, CX_SHA256_SIZE);
}
