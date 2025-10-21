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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define CHECK_PARSER_ERR(CALL)            \
    {                                     \
        parser_error_t err = CALL;        \
        if (err != parser_ok) return err; \
    }

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data = 1,
    parser_init_context_empty = 2,
    parser_display_idx_out_of_range = 3,
    parser_display_page_out_of_range = 4,
    parser_unexpected_error = 5,
    parser_no_memory_for_state = 6,
    // Context related errors
    parser_context_mismatch = 7,
    parser_context_unexpected_size = 8,
    parser_context_invalid_chars = 9,
    parser_context_unknown_prefix = 10,
    // Required fields
    parser_required_nonce = 11,
    parser_required_method = 12,
    ////////////////////////
    // Coin specific
    parser_post_condition_failed = 13,
    parser_invalid_contract_name = 14,
    parser_invalid_asset_name = 15,
    parser_invalid_clarity_name = 16,
    parser_invalid_fungible_code = 17,
    parser_invalid_non_fungible_code = 18,
    parser_invalid_asset_info = 19,
    parser_invalid_post_condition = 20,
    parser_invalid_post_condition_principal = 21,
    parser_invalid_hash_mode = 22,
    parser_invalid_signature = 23,
    parser_invalid_pubkey_encoding = 24,
    parser_invalid_auth_type = 25,
    parser_invalid_argument_id = 26,
    parser_invalid_transaction_payload = 27,
    parser_invalid_address_version = 28,
    parser_stacks_string_too_long = 29,
    parser_unexpected_type = 30,
    parser_unexpected_buffer_end = 31,
    parser_unexpected_value = 32,
    parser_unexpected_number_items = 33,
    parser_unexpected_characters = 34,
    parser_unexpected_field = 35,
    parser_value_out_of_range = 36,
    parser_invalid_address = 37,
    parser_invalid_token_transfer_type = 38,
    parser_invalid_bytestr_message = 39,
    parser_invalid_jwt = 40,
    parser_invalid_structured_msg = 41,
    parser_crypto_error = 42,
    parser_invalid_token_transfer_principal = 43,
    parser_recursion_limit = 44,
} parser_error_t;
typedef struct {
    const uint8_t *buffer;
    uint32_t bufferLen;
    uint32_t offset;
} parser_context_t;

typedef enum _TransactionType { Transaction, Message, Jwt, StructuredMsg, Invalid } transaction_type_t;

#ifdef __cplusplus
}
#endif
