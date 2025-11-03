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
        case 0:
            tx_initialize();
            tx_reset();
            tx_initialized = true;
            return false;
        case 1:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case 2:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
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
        app_fill_address(addr_secp256k1);

        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);

        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_secp256k1);
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

    const char *error_msg = tx_parse();

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    zemu_log_stack("tx_parse done\n");

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
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

/* TODO: Implement once the Ledger SDK provides an API to derive the Master Key.
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
*/

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

                    /* TODO: Implement once the Ledger SDK provides an API to derive the Master Key.
                        case INS_GET_MASTER_FINGERPRINT: {
                            if (os_global_pin_is_validated() != BOLOS_UX_OK) {
                                THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                            }
                            handleGetMasterFingerprint(flags, tx, rx);
                            break;
                        }
                    */

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
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
