/*******************************************************************************
 *   (c) 2018, 2019 Zondax GmbH
 *   (c) 2016 Ledger
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>

#include "actions.h"
#include "addr.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

static bool tx_initialized = false;

bool review_pending = false;

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset, uint32_t path_len) {
    if ((rx - offset) < sizeof(uint32_t) * path_len) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * path_len);
    hdPath_len = path_len;
}

__Z_INLINE bool process_chunk(uint32_t rx) {
    uint8_t payloadType = 0;
    payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    uint32_t added = 0;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
        default:
            tx_initialized = false;
            THROW(APDU_CODE_INVALIDP1P2);
            return false;
    }
}

__Z_INLINE void extract_default_path(uint32_t rx, uint32_t offset) {
    extractHDPath(rx, offset, HDPATH_LEN_DEFAULT);

    // validate
    bool mainnet = false;
    mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    mainnet |= (hdPath[0] == HDPATH_0_ALTERNATIVE);

    bool testnet = false;
    testnet = hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void extract_identity_path(uint32_t rx, uint32_t offset) {
    extractHDPath(rx, offset, HDPATH_LEN_AUTH);

    // validate
    bool identity_path = false;
    identity_path = hdPath[0] == HDPATH_0_AUTH && hdPath[1] == HDPATH_1_AUTH;
    if (!identity_path) THROW(APDU_CODE_DATA_INVALID);
}

__Z_INLINE void handle_getversion(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    UNUSED(flags);
    UNUSED(rx);
#ifdef DEBUG
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;
    G_io_apdu_buffer[4] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

    *tx += 9;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extract_default_path(rx, OFFSET_DATA);

    uint8_t requireConfirmation = 0;
    uint8_t network = 0;
    requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    network = G_io_apdu_buffer[OFFSET_P2];

    // Set the address version
    if (!set_network_version(network)) {
        return THROW(APDU_CODE_DATA_INVALID);
    }

    if (requireConfirmation) {
        review_pending = true;
        app_fill_address(addr_secp256k1);

        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);

        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_secp256k1);
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddrMultisig(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // The device's own derivation path comes first, validated as a standard
    // Stacks path (mainnet/testnet). This also sets `hdPath`.
    extract_default_path(rx, OFFSET_DATA);

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    const uint8_t version_byte = G_io_apdu_buffer[OFFSET_P2];

    // P2 carries the c32 multisig version byte (mainnet=20 / testnet=21)
    if (!set_multisig_version(version_byte)) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Multisig header follows the 20-byte path:
    //   hash_mode (1) | m (1) | n (1) | device_key_index (1) | cosigner keys ((n-1) * 33)
    const uint32_t path_bytes = sizeof(uint32_t) * HDPATH_LEN_DEFAULT;
    uint32_t offset = OFFSET_DATA + path_bytes;

    if (rx < offset + 4) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    const uint8_t hash_mode = G_io_apdu_buffer[offset++];
    const uint8_t num_required = G_io_apdu_buffer[offset++];
    const uint8_t num_pubkeys = G_io_apdu_buffer[offset++];
    const uint8_t device_key_index = G_io_apdu_buffer[offset++];

    if (hash_mode != MULTISIG_HASH_MODE_P2SH && hash_mode != MULTISIG_HASH_MODE_P2SH_NONSEQ) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (num_pubkeys < MULTISIG_MIN_PUBKEYS || num_pubkeys > MULTISIG_MAX_PUBKEYS) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (num_required < MULTISIG_MIN_PUBKEYS || num_required > num_pubkeys) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (device_key_index >= num_pubkeys) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    const uint32_t cosigner_bytes = (uint32_t)(num_pubkeys - 1) * PK_LEN_SECP256K1;
    if (rx - offset < cosigner_bytes) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMZERO(&multisig_data, sizeof(multisig_data));
    multisig_data.hash_mode = hash_mode;
    multisig_data.num_required = num_required;
    multisig_data.num_pubkeys = num_pubkeys;
    multisig_data.device_key_index = device_key_index;
    if (cosigner_bytes > 0) {
        MEMCPY(multisig_data.pubkeys, &G_io_apdu_buffer[offset], cosigner_bytes);
    }

    if (requireConfirmation) {
        review_pending = true;
        if (app_fill_address_multisig() == 0) {
            review_pending = false;
            THROW(APDU_CODE_DATA_INVALID);
        }

        view_review_init(addr_multisig_getItem, addr_multisig_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);

        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address_multisig();
    if (*tx == 0) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAuthPubKey(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extract_identity_path(rx, OFFSET_DATA);

    *tx = app_fill_auth_pubkey(addr_secp256k1);
    THROW(APDU_CODE_OK);
}

__Z_INLINE void SignSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // process the rest of the chunk as usual
    if (!process_chunk(rx)) {
        THROW(APDU_CODE_OK);
    }

    uint8_t error_code = parser_ok;
    const char *error_msg = tx_parse(&error_code);

    if (error_msg != NULL) {
        if (error_code == parser_blindsign_mode_required) {
            // The transaction carries data we cannot display and the user has not opted in.
            // Show the dedicated screen instead of failing the APDU outright; dismissing it
            // (or rejecting from the settings prompt on NBGL) calls app_reply_error() for us.
            *flags |= IO_ASYNCH_REPLY;
            view_blindsign_error_show();
        } else {
            int error_msg_length = strlen(error_msg);
            MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
            *tx += (error_msg_length);
            THROW(APDU_CODE_DATA_INVALID);
        }
    } else {
        zemu_log_stack("tx_parse done\n");

        CHECK_APP_CANARY()
        review_pending = true;
        view_review_init(tx_getItem, tx_getNumItems, app_sign);
        view_review_show(REVIEW_TXN);
        *flags |= IO_ASYNCH_REPLY;
    }
}

__Z_INLINE void handleSignSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // check first for the expected path at initialization
    if (G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE] == 0) {
        extract_default_path(rx, OFFSET_DATA);
    }

    SignSecp256K1(flags, tx, rx);
}

__Z_INLINE void handleSignJwtSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // check first for the expected path at initialization
    if (G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE] == 0) {
        extract_identity_path(rx, OFFSET_DATA);
    }

    SignSecp256K1(flags, tx, rx);
}

__Z_INLINE void handleGetMasterFingerprint(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx,
                                           __Z_UNUSED uint32_t rx) {
    uint8_t fingerprint[FINGERPRINT_LEN];

    zxerr_t err = crypto_getMasterFingerprint(fingerprint, sizeof(fingerprint));
    if (err != zxerr_ok) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    MEMCPY(G_io_apdu_buffer, fingerprint, FINGERPRINT_LEN);
    *tx = FINGERPRINT_LEN;
    THROW(APDU_CODE_OK);
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            if (review_pending) {
                THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleGetAddrSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_MULTISIG: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleGetAddrMultisig(flags, tx, rx);
                    break;
                }

                case INS_GET_AUTH_PUBKEY: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleGetAuthPubKey(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleSignSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_SIGN_JWT_SECP256K1: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleSignJwtSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_MASTER_FINGERPRINT: {
                    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleGetMasterFingerprint(flags, tx, rx);
                    break;
                }

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            review_pending = false;
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(err) {
            switch (err & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = err;
                    break;
                default:
                    sw = 0x6800 | (err & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}
