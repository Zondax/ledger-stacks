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
#pragma once

#include <stdint.h>
#include "zxmacros.h"
#include "crypto.h"
#include "cx.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "zxformat.h"
#include "sha512.h"

// The initial tx hash is done in 3 blocks
// this is the length in bytes of the first block
// which includes:
// 1-byte transaction version
// 4-byte chainID
// 1-byte authorization type
// 21-byte origin hash-mode and public-key hash
#define TRANSACTION_FIRST_BLOCK_LEN 27

// The length in bytes of the auth fields
// after zeroizing them for the initial transaction hash
// which is required as part of the signing algorithm
#define INITIAL_SIGHASH_AUTH_LEN 185

// The presign data that includes:
// 32-byte full transaction hash
// 1-byte auth flag
// 8-byte big-endian fee
// 8-byte big-endian nonce
#define PRESIG_DATA_LEN CX_SHA256_SIZE + 1 + 8 + 8

// The data required to calculate the post_sighash hash
// 32-byte presig_hash calculated above
// 1-byte publicKey encoding. It seems to be 0x00(compressed)
// according to the blockstack's rust implementation
#define POST_SIGNHASH_DATA_LEN CX_SHA256_SIZE + 1

// The previous signer signature data and post_sig_hash
// that should be treated as the pre_sig_hash for this signer
// this includes:
// 32-byte previous signer post_sig_hash
// 1-byte pubkey type(compressed/uncompressed)
// 65-byte previous signer signature(vrs)
#define PREVIOUS_SIGNER_DATA_LEN CX_SHA256_SIZE + 1 + 65

extern uint8_t action_addr_len;

// helper function to get the presig_hash of the transaction being signed
__Z_INLINE zxerr_t get_presig_hash(uint8_t* hash, uint16_t hashLen);

// Helper function that appends the transaction auth_type, fee and  nonce getting the hash of the result
__Z_INLINE zxerr_t append_fee_nonce_auth_hash(uint8_t* input_hash, uint16_t input_hashLen, uint8_t* hash, uint16_t hashLen);

// Helper function to verify the previous signer post_sig_hash in a multisig transaction
__Z_INLINE zxerr_t validate_post_sig_hash(uint8_t *current_pre_sig_hash, uint16_t hash_len, uint8_t *signer_data, uint16_t signer_data_len);

__Z_INLINE void app_sign() {
    uint8_t presig_hash[CX_SHA256_SIZE];
    uint8_t post_sighash_data[POST_SIGNHASH_DATA_LEN];
    zxerr_t err = zxerr_ok;

    // Get the current transaction presig_hash
    err = get_presig_hash(presig_hash, CX_SHA256_SIZE);

    // Check if this is a multisig transaction, If so, checks that there is a previous
    // signer data, in that case we know we have to use that signers's data as our
    // pre_sig_hash. Otherwise, we are the first signer in a multisig transaction
    if (tx_is_multisig() && err == zxerr_ok) {
        // Get the previous signer data to do the verification and to sign it
        uint8_t *data = NULL;
        uint8_t **previous_signer_data = &data;
        uint16_t len = tx_previous_signer_data(previous_signer_data);

        if (data != NULL && len >= PREVIOUS_SIGNER_DATA_LEN) {
            // Check postsig_hash and append the authfield, fee and nonce, after that the result is copied to the presig_hash
            // buffer
            err = validate_post_sig_hash(presig_hash, CX_SHA256_SIZE, data, len);
            if(err == zxerr_ok) {
                err = append_fee_nonce_auth_hash(data, CX_SHA256_SIZE, presig_hash, CX_SHA256_SIZE);
            }
        }
    }

    if (err != zxerr_ok) {
        uint8_t errLen = getErrorMessage((char *) G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, err);
        set_code(G_io_apdu_buffer, errLen, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, errLen + 2);
        return;
    }

    // Take "ownership" of the memory used by the transaction parser
    tx_reset_state();

    uint16_t replyLen;
    err = crypto_sign(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, presig_hash, CX_SHA256_SIZE, &replyLen);
    if (err != zxerr_ok) {
        uint8_t errLen = getErrorMessage((char *) G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, err);
        set_code(G_io_apdu_buffer, errLen, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, errLen + 2);
        return;
    }

    if(tx_is_transaction()) {
        // Calculates the post_sighash
        memcpy(post_sighash_data, presig_hash, CX_SHA256_SIZE);

        // set the signing public key's encoding byte, it is compressed(it is our device pubkey)
        post_sighash_data[CX_SHA256_SIZE] = 0x00;

        // Now gets the post_sighash from the data and write it down to the first 32-byte of the  G_io_apdu_buffer
        uint8_t hash_temp[SHA512_DIGEST_LENGTH];

        // Now get the presig_hash
        sha512_256_ctx ctx;
        SHA512_256_init(&ctx);
        SHA512_256_starts(&ctx);

        // sighash + pubkey encoding
        SHA512_256_update(&ctx, post_sighash_data, POST_SIGNHASH_DATA_LEN);
        // the signature's v value
        SHA512_256_update(&ctx, &G_io_apdu_buffer[96], 1);

        // the signature's rs values
        SHA512_256_update(&ctx, &G_io_apdu_buffer[32], 64);
        SHA512_256_finish(&ctx, hash_temp);
        memcpy(G_io_apdu_buffer, hash_temp, CX_SHA256_SIZE);
    }

    if (replyLen == 0) {
        uint8_t errLen = getErrorMessage((char *) G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zxerr_no_data);
        set_code(G_io_apdu_buffer, errLen, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, errLen + 2);
        return;
    }

    set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
}

__Z_INLINE void app_reject() {
    tx_reset_state();

    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE uint8_t app_fill_address(address_kind_e kind) {
    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    switch (kind) {
        case addr_secp256k1:
            action_addr_len = crypto_fillAddress_secp256k1(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
            break;
        default:
            action_addr_len = 0;
            break;
    }

    return action_addr_len;
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, action_addr_len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addr_len + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE zxerr_t validate_post_sig_hash(uint8_t *current_pre_sig_hash, uint16_t hash_len, uint8_t *signer_data, uint16_t signer_data_len) {

    // get the previous signer post_sig_hash and validate it
    uint8_t reconstructed_post_sig_hash[CX_SHA256_SIZE];

    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);
    SHA512_256_update(&ctx, current_pre_sig_hash, hash_len);
    // include the previous signer pubkey type(compressed/uncompressed) and its signature(vrs)
    // those bytes are the last 66-bytes in the previous signer data
    SHA512_256_update(&ctx, signer_data + CX_SHA256_SIZE, PREVIOUS_SIGNER_DATA_LEN - CX_SHA256_SIZE);
    SHA512_256_finish(&ctx, reconstructed_post_sig_hash);

    // now compare
    for (unsigned int i = 0; i < CX_SHA256_SIZE; ++i) {
        if ( reconstructed_post_sig_hash[i] != signer_data[i]) {
            zemu_log_stack("Invalid post_sig_hash\n");
            return zxerr_no_data;
        }
    }
    return zxerr_ok;
}

__Z_INLINE zxerr_t get_presig_hash(uint8_t* hash, uint16_t hashLen) {
    uint8_t tx_auth[INITIAL_SIGHASH_AUTH_LEN];
    MEMZERO(tx_auth, INITIAL_SIGHASH_AUTH_LEN);
    uint8_t hash_temp[SHA512_DIGEST_LENGTH];

    // Before hashing the transaction the auth field should be cleared
    // and the sponsor set to signing sentinel.
    uint16_t auth_len = 0;
    auth_len = tx_presig_hash_data(tx_auth, INITIAL_SIGHASH_AUTH_LEN);

    // Init the hasher
    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);

    const uint8_t *message = tx_get_buffer() + CRYPTO_BLOB_SKIP_BYTES;

    // Update the hasher with the first and second block of bytes
    if(tx_is_transaction()) {
        // prepare the last transaction block to be hashed
        SHA512_256_update(&ctx, message, TRANSACTION_FIRST_BLOCK_LEN);
        SHA512_256_update(&ctx, tx_auth, auth_len);
        uint8_t *last_block = NULL;
        uint8_t **last_block_ptr = &last_block;

        uint16_t last_block_len = tx_last_tx_block(last_block_ptr);
        if (last_block == NULL || last_block_len == 0) {
            return zxerr_no_data;
        }

        SHA512_256_update(&ctx, last_block, last_block_len);
        SHA512_256_finish(&ctx, hash_temp);
        return append_fee_nonce_auth_hash(hash_temp, CX_SHA256_SIZE, hash, hashLen);
    } else {
        const uint16_t messageLength = tx_get_buffer_length() - CRYPTO_BLOB_SKIP_BYTES;
        SHA512_256_update(&ctx, message, messageLength);
        SHA512_256_finish(&ctx, hash);
        return zxerr_ok;
    }
}

__Z_INLINE zxerr_t append_fee_nonce_auth_hash(uint8_t* input_hash, uint16_t input_hashLen, uint8_t* hash, uint16_t hashLen) {
    uint8_t presig_data[PRESIG_DATA_LEN];
    // uint8_t hash_temp[SHA512_DIGEST_LENGTH];

    if ( input_hashLen != CX_SHA256_SIZE )
        return zxerr_no_data;

    memcpy(presig_data, input_hash, input_hashLen);

    // now append the auth-flag, fee and nonce
    uint8_t idx = CX_SHA256_SIZE;

    // append the tx auth type
    if (tx_auth_flag(&presig_data[idx++]) != zxerr_ok)
        return zxerr_no_data;

    // append the 8-byte transaction fee
    idx += tx_fee(&presig_data[idx], 8);

    // append the 8-byte transaction nonce
    idx += tx_nonce(&presig_data[idx], 8);

    if (hashLen < CX_SHA256_SIZE || idx != PRESIG_DATA_LEN)
        return zxerr_no_data;

    // Now get the hash
    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);
    SHA512_256_update(&ctx, presig_data, PRESIG_DATA_LEN);
    SHA512_256_finish(&ctx, hash);
    return zxerr_ok;
}

