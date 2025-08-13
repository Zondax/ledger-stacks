/*******************************************************************************
 *  (c) 2020 Zondax GmbH
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

#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define POST_CONDITION_CODE_EQUAL         1
#define POST_CONDITION_CODE_GREATER       2
#define POST_CONDITION_CODE_GREATER_EQUAL 3
#define POST_CONDITION_CODE_LESS          4
#define POST_CONDITION_CODE_LESS_EQUAL    5

typedef struct {
    uint8_t *state;
    uint16_t len;
} parser_tx_t;

typedef struct {
    char contract_address[CONTRACT_ADDR_STR_MAX_LEN];
    char token_symbol[TOKEN_SYMBOL_MAX_LEN];
    uint8_t decimals;
    uint8_t post_condition_code;
} token_info_t;

#ifdef __cplusplus
}
#endif
