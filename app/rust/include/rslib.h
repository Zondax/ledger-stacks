#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

/******* Address c32-chack encoding **************************************************************/

uint16_t rs_c32_address(const uint8_t *input, uint8_t version, uint8_t *output, uint16_t outLen);

/****************************** others ***********************************************************/

parser_error_t _parser_init(parser_context_t *ctx, const uint8_t *buffer, uint32_t bufferSize, uint16_t *alloc_size);

parser_error_t _read(const parser_context_t *c, parser_tx_t *v);

parser_error_t _validate(const parser_context_t *ctx, const parser_tx_t *v);

parser_error_t _getNumItems(const parser_context_t *ctx, const parser_tx_t *v, uint8_t *num_items);

parser_error_t _getItem(const parser_context_t *ctx, int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outValue,
                        uint16_t outValueLen, uint8_t pageIdx, uint8_t *pageCount, const parser_tx_t *v);

/****************************** Getters for the required information for signing*******************/
transaction_type_t _transaction_type(const parser_tx_t *v);

parser_error_t _auth_flag(const parser_tx_t *v, uint8_t *auth_flag);

parser_error_t _structured_msg_hash(const parser_tx_t *v, uint8_t *out, uint16_t out_len);

uint8_t _is_multisig(const parser_tx_t *v);
uint32_t _num_multisig_fields(const parser_tx_t *v);
parser_error_t _get_multisig_field(const parser_tx_t *v, uint32_t index, uint8_t *id, uint8_t **data);

parser_error_t _hash_mode(const parser_tx_t *v, uint8_t *hash_mode);

uint8_t _fee_bytes(const parser_tx_t *v, uint8_t *fee, uint16_t fee_len);
uint8_t _nonce_bytes(const parser_tx_t *v, uint8_t *nonce, uint16_t nonce_len);

parser_error_t _check_pubkey_hash(const parser_tx_t *v, const uint8_t *pubKey, uint16_t pubKeyLen);

uint16_t _presig_hash_data(const parser_tx_t *v, uint8_t *buf, uint16_t bufLen);

uint16_t _last_block_ptr(const parser_tx_t *v, uint8_t **block_ptr);

uint16_t _previous_signer_data(const parser_tx_t *v, uint8_t **data);
