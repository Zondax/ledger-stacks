/*******************************************************************************
 *  (c) 2019 Zondax GmbH
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

#include "tx.h"

#include <string.h>

#include "../parser.h"
#include "apdu_codes.h"
#include "buffering.h"
#include "zxmacros.h"

#if !defined(TARGET_NANOS)
#define RAM_BUFFER_SIZE   8192
#define FLASH_BUFFER_SIZE (85 * 1024)
#else
#define RAM_BUFFER_SIZE   0
#define FLASH_BUFFER_SIZE 8192
#endif

// Ram
uint8_t ram_buffer[RAM_BUFFER_SIZE];

// Flash
typedef struct {
    uint8_t buffer[FLASH_BUFFER_SIZE];
} storage_t;

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
storage_t NV_CONST N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(NV_VOLATILE storage_t *)PIC(&N_appdata_impl))
#else
storage_t N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(storage_t *)PIC(&N_appdata_impl))
#endif

static parser_context_t ctx_parsed_tx;

void tx_initialize() {
    buffering_init(ram_buffer, sizeof(ram_buffer), (uint8_t *)N_appdata.buffer, sizeof(N_appdata.buffer));
}

void tx_reset() {
    buffering_reset();
}

void tx_reset_state() {
    parser_resetState();
}

uint32_t tx_append(unsigned char *buffer, uint32_t length) {
    return buffering_append(buffer, length);
}

uint32_t tx_get_buffer_length() {
    return buffering_get_buffer()->pos;
}

uint8_t *tx_get_buffer() {
    return buffering_get_buffer()->data;
}

const char *tx_parse() {
    uint8_t err = parser_parse(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length());

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    err = parser_validate(&ctx_parsed_tx);
    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    return NULL;
}

zxerr_t tx_getNumItems(uint8_t *num_items) {
    parser_error_t err = parser_getNumItems(&ctx_parsed_tx, num_items);

    if (err != parser_ok) {
        return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t tx_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                   uint8_t *pageCount) {
    uint8_t numItems = 0;

    CHECK_ZXERR(tx_getNumItems(&numItems))

    if (displayIdx < 0 || displayIdx > numItems) {
        return zxerr_no_data;
    }

    parser_error_t err =
        parser_getItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range)
        return zxerr_no_data;

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t tx_auth_flag(uint8_t *flag) {
    if (parser_tx_auth_flag(flag) != parser_ok) return zxerr_unknown;
    return zxerr_ok;
}

uint8_t tx_fee(uint8_t *fee, uint16_t fee_len) {
    return parser_tx_fee(fee, fee_len);
}

uint8_t tx_nonce(uint8_t *nonce, uint16_t nonce_len) {
    return parser_tx_nonce(nonce, nonce_len);
}

uint16_t tx_presig_hash_data(uint8_t *buf, uint16_t bufLen) {
    return parser_presig_hash_data(buf, bufLen);
}

uint16_t tx_last_tx_block(uint8_t **last_tx_block) {
    return parser_last_transaction_block(last_tx_block);
}

int8_t tx_is_multisig() {
    return parser_is_transaction_multisig();
}

zxerr_t tx_hash_mode(uint8_t *hash_mode) {
    parser_error_t err = parser_hash_mode(hash_mode);

    // Convert error codes
    if (err == parser_no_data) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

uint16_t tx_previous_signer_data(uint8_t **data) {
    return parser_previous_signer_data(data);
}

uint32_t tx_num_multisig_fields() {
    return parser_num_multisig_fields();
}

zxerr_t tx_get_multisig_field(uint32_t index, uint8_t *id, uint8_t **data) {
    parser_error_t err = parser_get_multisig_field(index, id, data);

    // Convert error codes
    if (err == parser_no_data) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

transaction_type_t tx_get_transaction_type() {
    return parser_get_transaction_type();
}

zxerr_t tx_structured_msg_hash(uint8_t *out, uint16_t out_len) {
    return parser_structured_msg_hash(out, out_len);
}

uint16_t get_error_message(char *out, uint16_t outLen, parser_error_t error_code) {
    const char *error_message = parser_getErrorDescription(error_code);
    if (error_message == NULL || outLen == 0) {
        return 0;
    }

    uint16_t len = strlen(error_message);

    if (outLen < len) {
        return 0;
    }

    memcpy(out, error_message, len);

    return len;
}
