#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function declarations for C API functions called from Rust
uint16_t fp_uint64_to_str(char *out, uint16_t outLen, const uint64_t value, uint8_t decimals);
void check_canary(void);
void _zemu_log_stack(char *buffer);
void hash_sha256(uint8_t *in, uint32_t in_len, uint8_t *out);

#ifdef __cplusplus
}
#endif