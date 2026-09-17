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

#define CLA 0x09

#define HDPATH_LEN_DEFAULT 5
// support m/888'/0'/<account> path
#define HDPATH_LEN_AUTH 3

#define HDPATH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT (0x80000000u | 5757)
#define HDPATH_2_DEFAULT (0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define HDPATH_0_AUTH (0x80000000u | 888)
#define HDPATH_1_AUTH (0x80000000u | 0)

#define HDPATH_0_ALTERNATIVE (0x80000000u | 5757)

#define HDPATH_0_TESTNET (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET (0x80000000u | 0x1u)

// compressed key
#define PK_LEN_SECP256K1 33u

// BIP32 fingerprint length
#define FINGERPRINT_LEN 4u

typedef enum {
    addr_secp256k1 = 0,
} address_kind_e;

#define VIEW_ADDRESS_OFFSET_SECP256K1  PK_LEN_SECP256K1
#define VIEW_ADDRESS_ITEM_COUNT        2
#define VIEW_ADDRESS_LAST_PAGE_DEFAULT 255

#define MENU_MAIN_APP_LINE1 "Stacks"
#define MENU_MAIN_APP_LINE2 "Ready"
#define APPVERSION_LINE1    "Stacks"
#define APPVERSION_LINE2    ("v" APPVERSION)

#define COIN_SECRET_REQUIRED_CLICKS 0
#define MENU_MAIN_APP_LINE2_SECRET  "??????"

#define CRYPTO_BLOB_SKIP_BYTES 0

#define COIN_VERSION_MAINNET_SINGLESIG 22
#define COIN_VERSION_TESTNET_SINGLESIG 26
#define COIN_VERSION_MAINNET_MULTISIG  20
#define COIN_VERSION_TESTNET_MULTISIG  21

// Multisig address derivation limits.
// Stacks multisig (P2SH) addresses are the Hash160 of a Bitcoin-style redeem
// script. The 520-byte redeem-script limit caps a P2SH multisig at 15
// compressed keys (matches stacks.js), so 15 is the protocol maximum. The
// header + (n-1) cosigner keys are received over chunked transport.
#define MULTISIG_MIN_PUBKEYS 1u
#define MULTISIG_MAX_PUBKEYS 15u
// Sequential (0x01) and non-sequential (0x05) P2SH multisig derive the *same*
// address (identical redeem script / Hash160); they differ only in how the
// transaction is later signed. We accept both for address verification.
#define MULTISIG_HASH_MODE_P2SH        0x01u
#define MULTISIG_HASH_MODE_P2SH_NONSEQ 0x05u

// 0x05 is unassigned and was never dispatched. SIP-018 structured messages are signed through
// INS_SIGN_SECP256K1 (0x02); the parser recognises them from the "SIP018" prefix on the data,
// not from the instruction. Keep 0x05 reserved rather than reusing it.
#define INS_GET_VERSION            0x00
#define INS_GET_ADDR_SECP256K1     0x01
#define INS_SIGN_SECP256K1         0x02
#define INS_GET_AUTH_PUBKEY        0x03
#define INS_SIGN_JWT_SECP256K1     0x04
#define INS_GET_MASTER_FINGERPRINT 0x06
#define INS_GET_ADDR_MULTISIG      0x07

#ifdef __cplusplus
}
#endif
