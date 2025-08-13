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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>

#include "coin.h"
#include "zxerror.h"
#include "zxmacros.h"

#define PUBKEY_SHA_LEN 28
#define CX_SHA256_SIZE 32
#define HRP            "sov"

zxerr_t crypto_sha256_init();
zxerr_t crypto_sha256_update(const uint8_t *input, uint16_t inputLen);
zxerr_t crypto_sha256_final(uint8_t *output);
zxerr_t crypto_sha256_one_shot(uint8_t *output, uint16_t outputLen, const uint8_t *input, uint16_t inputLen);
zxerr_t crypto_computeAddress(uint8_t *address, uint16_t addressLen, const uint8_t *pubkey);

#ifdef __cplusplus
}
#endif