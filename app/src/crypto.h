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

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include "zxerror.h"

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

extern address_kind_e addressKind;

extern uint8_t version;

bool set_network_version(uint8_t version);

bool isTestnet();

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

void crypto_extractPublicKeyHash(uint8_t *pubKey, uint16_t pubKeyLen);

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_sign(uint8_t *buffer,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize);

#ifdef __cplusplus
}
#endif
