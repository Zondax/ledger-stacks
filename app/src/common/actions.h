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

#include <os_io_seproxyhal.h>
#include <stdint.h>

#include "apdu_codes.h"
#include "coin.h"
#include "crypto.h"
#include "cx.h"
#include "sha512.h"
#include "tx.h"
#include "zxformat.h"
#include "zxmacros.h"

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
// according to the stacks's rust implementation
#define POST_SIGNHASH_DATA_LEN CX_SHA256_SIZE + 1

// The previous signer signature length
#define PREVIOUS_SIGNER_SIG_LEN 65

// The previous signer signature data and post_sig_hash
// that should be treated as the pre_sig_hash for this signer
// this includes:
// 32-byte previous signer post_sig_hash
// 1-byte pubkey type(compressed/uncompressed)
// 65-byte previous signer signature(vrs)
#define PREVIOUS_SIGNER_DATA_LEN CX_SHA256_SIZE + 1 + PREVIOUS_SIGNER_SIG_LEN

extern uint8_t action_addr_len;

// helper function to get the presig_hash of the transaction being signed
__Z_INLINE zxerr_t get_presig_hash(uint8_t *hash, uint16_t hashLen);

// Helper function that appends the transaction auth_type, fee and  nonce getting the hash of the result
__Z_INLINE zxerr_t append_fee_nonce_auth_hash(uint8_t *input_hash, uint16_t input_hashLen, uint8_t *hash, uint16_t hashLen);

// Helper function to compute post_sighash from pre_sighash
// Updates `hash` in place
__Z_INLINE zxerr_t compute_post_sig_hash(uint8_t *hash, uint16_t hash_len, uint8_t *signer_data, uint16_t signer_data_len);

// Helper function to verify full sig_hash chain in a multisig transaction (after initial pre_sig_hash)
// Updates `hash` in place
__Z_INLINE zxerr_t compute_sig_hash_chain(uint8_t *hash, uint16_t hash_len);

__Z_INLINE void app_sign() {
    uint8_t presig_hash[CX_SHA256_SIZE] = {0};
    uint8_t post_sighash_data[POST_SIGNHASH_DATA_LEN] = {0};
    zxerr_t err = zxerr_ok;

    const uint8_t transaction_type = tx_get_transaction_type();

    // Get the current transaction presig_hash
    err = get_presig_hash(presig_hash, CX_SHA256_SIZE);

    // Check if this is a multisig transaction, If so, checks that there is a previous
    // signer data, in that case we know we have to use that signers's data as our
    // pre_sig_hash. Otherwise, we are the first signer in a multisig transaction
    if (tx_is_multisig() && err == zxerr_ok) {
        // Validate post_sig_hashes of previous signers
        uint8_t hash_mode = -1;
        err = tx_hash_mode(&hash_mode);
        if (err == zxerr_ok) {
            switch (hash_mode) {
                case 0x00:  // P2PKH
                case 0x02:  // P2WPKH
                    // Singlesig
                    // Shouldn't be here!
                    zemu_log_stack("HashMode is not multisig\n");
                    err = zxerr_unknown;
                    break;
                case 0x01:  // P2SH sequential
                case 0x03:  // P2WSH sequential
                    // Sequential multisig
                    // Need to compute sighashes of all previous signers
                    err = compute_sig_hash_chain(presig_hash, CX_SHA256_SIZE);
                    break;
                case 0x05:  // PWSH non-sequential
                case 0x07:  // P2WSH non-sequential
                    // Non-sequential multisig
                    // No need to do anything
                    err = zxerr_ok;
                    break;
                default:
                    zemu_log_stack("Invalid HashMode\n");
                    err = zxerr_unknown;
                    break;
            }
        }
    }

    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    // Take "ownership" of the memory used by the transaction parser
    tx_reset_state();

    uint16_t replyLen = 0;
    err = crypto_sign(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, presig_hash, CX_SHA256_SIZE, &replyLen);
    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    switch (transaction_type) {
        case Transaction: {
            // Calculates the post_sighash
            memcpy(post_sighash_data, presig_hash, CX_SHA256_SIZE);

            // set the signing public key's encoding byte, it is compressed(it is our device pubkey)
            post_sighash_data[CX_SHA256_SIZE] = 0x00;

            // Now get the post_sighash from the data and write it down to the first 32-byte of the  G_io_apdu_buffer
            uint8_t hash_temp[SHA512_DIGEST_LENGTH] = {0};

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
            break;
        }
        case Message:
        case Jwt:
        case StructuredMsg: {
            // just return as a post_sighash the presig_hash
            // which is the hash that is signed allowing for  easy signature verification
            memcpy(G_io_apdu_buffer, presig_hash, CX_SHA256_SIZE);
            break;
        }
        default: {
            set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
            return;
        }
    }

    if (replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
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

__Z_INLINE uint8_t app_fill_auth_pubkey(address_kind_e kind) {
    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    switch (kind) {
        case addr_secp256k1:
            action_addr_len = crypto_fillAuthkey_secp256k1(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
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

__Z_INLINE zxerr_t compute_post_sig_hash(uint8_t *hash, uint16_t hash_len, uint8_t *signer_data, uint16_t signer_data_len) {
    uint16_t expected_signer_data_len = 1 + PREVIOUS_SIGNER_SIG_LEN;
    if ((hash_len != CX_SHA256_SIZE) || (signer_data_len != expected_signer_data_len)) {
        return zxerr_no_data;
    }

    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);
    SHA512_256_update(&ctx, hash, CX_SHA256_SIZE);
    // include the previous signer pubkey type(compressed/uncompressed) and its signature(vrs)
    // those bytes are the 66-bytes in the previous signer data
    SHA512_256_update(&ctx, signer_data, signer_data_len);
    SHA512_256_finish(&ctx, hash);

    return zxerr_ok;
}

// Validate sighash of all previous signers
__Z_INLINE zxerr_t compute_sig_hash_chain(uint8_t *hash, uint16_t hash_len) {
    if (hash_len != CX_SHA256_SIZE) {
        return zxerr_no_data;
    }

    // 1-byte pubkey type(compressed/uncompressed)
    // 65-byte previous signer signature(vrs)
    uint8_t previous_signer_data[1 + PREVIOUS_SIGNER_SIG_LEN] = {0};
    memset(previous_signer_data, 0, sizeof(previous_signer_data));

    uint32_t num_fields = tx_num_multisig_fields();
    for (uint32_t i = 0; i < num_fields; ++i) {
        // `TransactionAuthFieldID` part of `MultisigSpendingCondition` auth field
        uint8_t id = 0xFF;
        // Pointer to either pubkey or signature part of `MultisigSpendingCondition`
        uint8_t *data = NULL;
        zxerr_t err = tx_get_multisig_field(i, &id, &data);

        if (err != zxerr_ok || !data) {
            continue;
        }

        switch (id) {
            case 0x00:
            case 0x01:
                // Pubkey, don't need to do anything
                continue;
            case 0x02:
                // Signature with recoverable compressed pubkey
                previous_signer_data[0] = 0x00;
                break;
            case 0x03:
                // Signature with recoverable uncompressed pubkey
                previous_signer_data[0] = 0x01;
                break;
            default:
                zemu_log_stack("Invalid TransactionAuthFieldID\n");
        };

        // Copy previous signer's signature
        memcpy(&previous_signer_data[1], data, PREVIOUS_SIGNER_SIG_LEN);

        // Compute post_sig_hash from pre_sig_hash and previous signature
        err = compute_post_sig_hash(hash, CX_SHA256_SIZE, previous_signer_data, sizeof(previous_signer_data));
        if (err != zxerr_ok) {
            zemu_log_stack("Failed to compute post_sig_hash\n");
            return zxerr_no_data;
        }

        // Compute pre_sig_hash for next signer from post_sig_hash, fee, and nonce
        err = append_fee_nonce_auth_hash(hash, CX_SHA256_SIZE, hash, CX_SHA256_SIZE);
        if (err != zxerr_ok) {
            zemu_log_stack("Failed to compute pre_sig_hash\n");
            return zxerr_no_data;
        }
    }
    return zxerr_ok;
}

__Z_INLINE zxerr_t get_presig_hash(uint8_t *hash, uint16_t hashLen) {
    zemu_log_stack("computing presig_hash");

    uint8_t tx_auth[INITIAL_SIGHASH_AUTH_LEN];
    MEMZERO(tx_auth, INITIAL_SIGHASH_AUTH_LEN);
    uint8_t hash_temp[SHA512_DIGEST_LENGTH];

    transaction_type_t tx_typ = tx_get_transaction_type();

    // Init the hasher
    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);

    const uint8_t *data = tx_get_buffer() + CRYPTO_BLOB_SKIP_BYTES;
    const uint32_t data_len = tx_get_buffer_length() - CRYPTO_BLOB_SKIP_BYTES;

    switch (tx_typ) {
        case Transaction: {
            // Before hashing the transaction the auth field should be cleared
            // and the sponsor set to signing sentinel.
            uint16_t auth_len = 0;
            auth_len = tx_presig_hash_data(tx_auth, INITIAL_SIGHASH_AUTH_LEN);
            // prepare the last transaction block to be hashed
            SHA512_256_update(&ctx, data, TRANSACTION_FIRST_BLOCK_LEN);
            SHA512_256_update(&ctx, tx_auth, auth_len);
            uint8_t *last_block = NULL;
            uint8_t **last_block_ptr = &last_block;

            uint32_t last_block_len = tx_last_tx_block(last_block_ptr);
            if (last_block == NULL || last_block_len == 0) {
                return zxerr_no_data;
            }

            SHA512_256_update(&ctx, last_block, last_block_len);
            SHA512_256_finish(&ctx, hash_temp);
            return append_fee_nonce_auth_hash(hash_temp, CX_SHA256_SIZE, hash, hashLen);
        }
        case Message:
        case Jwt: {
            // we have byteString or JWT messages. The hash is the same for both types
            cx_hash_sha256(data, data_len, hash, CX_SHA256_SIZE);
            return zxerr_ok;
        }
        // special case is delegated to the rust side
        case StructuredMsg: {
            return tx_structured_msg_hash(hash, CX_SHA256_SIZE);
        }
        default:
            return zxerr_no_data;
    }
}

__Z_INLINE zxerr_t append_fee_nonce_auth_hash(uint8_t *input_hash, uint16_t input_hashLen, uint8_t *hash, uint16_t hashLen) {
    uint8_t presig_data[PRESIG_DATA_LEN] = {0};
    // uint8_t hash_temp[SHA512_DIGEST_LENGTH];

    if (input_hashLen != CX_SHA256_SIZE) return zxerr_no_data;

    memcpy(presig_data, input_hash, input_hashLen);

    // now append the auth-flag, fee and nonce
    uint8_t idx = CX_SHA256_SIZE;

    // append the tx auth type
    if (tx_auth_flag(&presig_data[idx++]) != zxerr_ok) return zxerr_no_data;

    // append the 8-byte transaction fee
    idx += tx_fee(&presig_data[idx], 8);

    // append the 8-byte transaction nonce
    idx += tx_nonce(&presig_data[idx], 8);

    if (hashLen < CX_SHA256_SIZE || idx != PRESIG_DATA_LEN) return zxerr_no_data;

    // Now get the hash
    sha512_256_ctx ctx;
    SHA512_256_init(&ctx);
    SHA512_256_starts(&ctx);
    SHA512_256_update(&ctx, presig_data, PRESIG_DATA_LEN);
    SHA512_256_finish(&ctx, hash);
    return zxerr_ok;
}
