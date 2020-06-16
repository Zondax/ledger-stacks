/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdio.h>
#include <zxmacros.h>
#include "parser_txdef.h"
#include "zbuffer.h"
#include "parser.h"
#include "coin.h"
#include "rslib.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_tx_t parser_state;

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    parser_state.state = NULL;
    parser_state.len = 0;
    // Just in case
    //zb_deallocate();
    CHECK_PARSER_ERR(_parser_init(ctx, data, dataLen, &parser_state.len))
    if ( parser_state.len> 0 && zb_allocate(parser_state.len) == zb_no_error) {
        zb_get(&parser_state.state);
    }
    return _read(ctx, &parser_state);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validate(ctx, &parser_state))

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_state);
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint16_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 0;

    uint8_t numItems;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    CHECK_PARSER_ERR(_getItem(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount, &parser_state));
    return parser_ok;
}


void parser_resetState() {
    zb_deallocate();
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexpected_error:
            return "Unexpected internal error";
        case parser_no_memory_for_state:
            return "No enough memory for parser state";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
            // Coin specific
        case parser_post_condition_failed:
            return "Unexpected post-condition";
        case parser_invalid_contract_name:
            return "Unexpected contract name characters";
        case parser_invalid_asset_name:
            return "Unexpected characters in asset name";
        case parser_invalid_clarity_name:
            return "Unexpected charactes in clarity name";
        case parser_invalid_fungible_code:
            return "Invalid fungible code type";
        case parser_invalid_non_fungible_code:
            return "Invalid non fungible code";
        case parser_invalid_asset_info:
            return "Invalid asset info";
        case parser_invalid_post_condition:
            return "Invalid post condition";
        case parser_invalid_post_condition_principal:
            return "Error processing post condition principal";
        case parser_invalid_hash_mode:
            return "Invalid hash mode";
        case parser_invalid_signature:
            return "Invalid signature";
        case parser_invalid_pubkey_encoding:
            return "Unsupported public key encoding";
        case parser_invalid_auth_type:
            return "Authorization type not supported";
        case parser_invalid_argument_id:
            return "Unrecognize argument type";
        case parser_invalid_token_transfer_type:
            return "Unrecognize token";
        case parser_invalid_transaction_payload:
            return "Unsupported transaction payload";
        case parser_stacks_string_too_long:
            return "Contract body too long";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        default:
            return "Unrecognized error code";
    }
}
