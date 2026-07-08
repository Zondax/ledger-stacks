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

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>
#include <zxmacros.h>

#include "coin.h"
#include "zxerror.h"

#define CHECKSUM_LENGTH 4

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];
extern uint32_t hdPath_len;

extern address_kind_e addressKind;

extern uint8_t version;

// Holds the parameters of an in-flight multisig address request.
// `pubkeys` points at the (num_pubkeys - 1) cosigner compressed public keys, in
// the order they appear in the multisig, excluding the slot the device's own
// derived key occupies (see `device_key_index`). The keys are NOT copied: this
// borrows the reassembled chunk buffer (`tx_get_buffer()`), the same way
// `tx_parse()` points the transaction parser at it. The address is derived
// synchronously while that buffer is still live. NULL when num_pubkeys == 1.
typedef struct {
    uint8_t hash_mode;         // MULTISIG_HASH_MODE_P2SH or ..._P2SH_NONSEQ
    uint8_t num_required;      // m: required signatures
    uint8_t num_pubkeys;       // n: total participating keys
    uint8_t device_key_index;  // position of this device's key in the ordered set
    const uint8_t *pubkeys;    // borrowed, (n-1) * PK_LEN_SECP256K1 bytes
} multisig_data_t;

extern multisig_data_t multisig_data;

bool set_network_version(uint8_t version);

// Set the address version for a multisig request (mainnet/testnet multisig only).
bool set_multisig_version(uint8_t version);

bool isTestnet();

zxerr_t crypto_extractPublicKey(const uint32_t *path, uint32_t path_len, uint8_t *pubKey, uint16_t pubKeyLen);

bool crypto_extractPublicKeyHash(uint8_t *pubKey, uint16_t pubKeyLen);

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t bufferLen);
uint16_t crypto_fillAuthkey_secp256k1(uint8_t *buffer, uint16_t bufferLen);

// Builds the multisig (P2SH) address from the device's derived key plus the
// cosigner keys stored in `multisig_data`, and writes [device pubkey || c32
// address] into `buffer`. Returns the total number of bytes written, or 0 on
// error.
uint16_t crypto_fillAddress_multisig(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                    uint16_t *sigSize);

zxerr_t crypto_getMasterFingerprint(uint8_t *fingerprint, uint16_t fingerprintLen);

#ifdef __cplusplus
}
#endif
