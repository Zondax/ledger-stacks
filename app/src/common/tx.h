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

#include "os.h"
#include "coin.h"
#include "zxerror.h"
#include "parser_common.h"

void tx_initialize();

/// Clears the transaction buffer
void tx_reset();

void tx_reset_state();

/// Appends buffer to the end of the current transaction buffer
/// Transaction buffer will grow until it reaches the maximum allowed size
/// \param buffer
/// \param length
/// \return It returns an error message if the buffer is too small.
uint32_t tx_append(unsigned char *buffer, uint32_t length);

/// Returns size of the raw json transaction buffer
/// \return
uint32_t tx_get_buffer_length();

/// Returns the raw json transaction buffer
/// \return
uint8_t *tx_get_buffer();

/// Parse message stored in transaction buffer
/// This function should be called as soon as full buffer data is loaded.
/// \return It returns NULL if data is valid or error message otherwise.
const char *tx_parse();

/// Return the number of items in the transaction
zxerr_t tx_getNumItems(uint8_t *num_items);

/// Gets an specific item from the transaction (including paging)
zxerr_t tx_getItem(int8_t displayIdx,
                   char *outKey, uint16_t outKeyLen,
                   char *outValue, uint16_t outValueLen,
                   uint8_t pageIdx, uint8_t *pageCount);

// Gets the transaction authorization type
zxerr_t tx_auth_flag(uint8_t *flag);

// Returns 1 if the transaction is multisig, 0 otherwise
int8_t tx_is_multisig();

// Returns # of fields in a multisig spending condition, or 0 if not multisig
uint32_t tx_num_multisig_fields();

// Returns multisig auth field at position `index`
zxerr_t tx_get_multisig_field(uint32_t index, uint8_t *id, uint8_t **data);

// Gets the origin fee as bytes
uint8_t tx_fee(uint8_t *fee, uint16_t fee_len);

// Gets the origin nonce as bytes
uint8_t tx_nonce(uint8_t *nonce, uint16_t nonce_len);

// Writes in buf, the auth fields used for the initial transaction hash
uint16_t tx_presig_hash_data(uint8_t *buf, uint16_t bufLen);

// Gets a pointer to the last block in the transaction and returns its lenght
uint16_t tx_last_tx_block(uint8_t ** last_tx_block);

// Gets the pointer to the previous signer signature and required data
// for signing a multisig transaction
uint16_t tx_previous_signer_data(uint8_t **data);

transaction_type_t tx_get_transaction_type();

zxerr_t tx_structured_msg_hash(uint8_t *out, uint16_t out_len);
