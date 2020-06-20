#include <inttypes.h>
#include <zxmacros.h>
#include <zxformat.h>
#include <zbuffer.h>
#include "os.h"
#include "cx.h"



uint16_t fp_uint64_to_str(char *out, uint16_t outLen, const uint64_t value, uint8_t decimals) {
    return fpuint64_to_str(out, outLen, value, decimals);
}

void check_canary() {
    zb_check_canary();
}
