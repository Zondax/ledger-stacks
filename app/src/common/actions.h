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

extern uint8_t action_addr_len;

// helper function to get the presig_hash of the transaction being signed
__Z_INLINE zxerr_t get_presig_hash(uint8_t* hash, uint16_t hashLen);

__Z_INLINE void app_sign() {
    uint8_t presig_hash[CX_SHA256_SIZE];
    uint8_t post_sighash_data[POST_SIGNHASH_DATA_LEN];

    zxerr_t err = get_presig_hash(presig_hash, CX_SHA256_SIZE);

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

    // Calculates the post_sighash
    memcpy(post_sighash_data, presig_hash, CX_SHA256_SIZE);

    // set the signing public key's encoding byte, it is compressed
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


__Z_INLINE zxerr_t get_presig_hash(uint8_t* hash, uint16_t hashLen) {
    uint8_t tx_auth[INITIAL_SIGHASH_AUTH_LEN];
    MEMZERO(tx_auth, INITIAL_SIGHASH_AUTH_LEN);
    uint8_t presig_data[PRESIG_DATA_LEN];
    uint8_t hash_temp[SHA512_DIGEST_LENGTH];

    // Before hashing the transaction the auth field should be cleared
    // and the sponsor set to signing sentinel.
    uint16_t auth_len = 0;
    auth_len = tx_presig_hash_data(tx_auth, INITIAL_SIGHASH_AUTH_LEN);

    // Init the hasher
    //cx_sha256_t ctx;
    //cx_sha256_init(&ctx);
    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);

    const uint8_t *message = tx_get_buffer() + CRYPTO_BLOB_SKIP_BYTES;
    const uint16_t messageLength = tx_get_buffer_length() - CRYPTO_BLOB_SKIP_BYTES;

    // Update the hasher with the first and second block of bytes
    SHA512_256_update(&ctx, message, TRANSACTION_FIRST_BLOCK_LEN);
    SHA512_256_update(&ctx, tx_auth, auth_len);

    // prepare the last transaction block to be hashed
    uint8_t* last_block = NULL;

    last_block = tx_last_tx_block();

    if (last_block == NULL) {
        return zxerr_no_data;
    }

    // Gets the last block length
    uint16_t last_block_len = messageLength - (last_block - message);

    // gets the full transaction hash used for signing and copies the result into the first
    // 32-bytes of presig_data
    SHA512_256_update(&ctx, last_block, last_block_len);
    SHA512_256_finish(&ctx, hash_temp);
    memcpy(presig_data, hash_temp, CX_SHA256_SIZE);
    {
        zemu_log("tx_hash: ***");
        char buffer[65];
        array_to_hexstr(buffer, 65, presig_data, CX_SHA256_SIZE);
        zemu_log(buffer);
        zemu_log("\n");
    }

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

    // Now get the presig_hash
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);
    SHA512_256_update(&ctx, presig_data, PRESIG_DATA_LEN);
    SHA512_256_finish(&ctx, hash_temp);
    memcpy(hash, hash_temp, CX_SHA256_SIZE);

    return zxerr_ok;
}

