/*******************************************************************************
 *   (c) 2018 - 2025 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#include "crypto_helper.h"

#include "bech32.h"
#include "zxformat.h"
#if defined(LEDGER_SPECIFIC)
#include "cx.h"
#include "cx_sha256.h"
cx_sha256_t ctx;
#else
#include "picohash.h"
picohash_ctx_t ctx;
#endif

zxerr_t crypto_sha256_init() {
#if defined(LEDGER_SPECIFIC)
    MEMZERO(&ctx, sizeof(ctx));
    cx_sha256_init_no_throw(&ctx);
#else
    picohash_init_sha256(&ctx);
#endif
    return zxerr_ok;
}

zxerr_t crypto_sha256_update(const uint8_t *input, uint16_t inputLen) {
#if defined(LEDGER_SPECIFIC)
    CHECK_CX_OK(cx_sha256_update(&ctx, input, inputLen));
#else
    picohash_update(&ctx, input, inputLen);
#endif
    return zxerr_ok;
}

zxerr_t crypto_sha256_final(uint8_t *output) {
#if defined(LEDGER_SPECIFIC)
    CHECK_CX_OK(cx_sha256_final(&ctx, output));
#else
    picohash_final(&ctx, output);
#endif
    return zxerr_ok;
}

zxerr_t crypto_sha256_one_shot(uint8_t *output, uint16_t outputLen, const uint8_t *input, uint16_t inputLen) {
    if (output == NULL || outputLen == 0 || input == NULL) {
        return zxerr_invalid_crypto_settings;
    }

    if (outputLen < CX_SHA256_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    MEMZERO(output, outputLen);

    CHECK_ZXERR(crypto_sha256_init());
    CHECK_ZXERR(crypto_sha256_update(input, inputLen));
    CHECK_ZXERR(crypto_sha256_final(output));

    return zxerr_ok;
}