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

#include "crypto.h"
#include "sha512.h"
#include "coin.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "rslib.h"
#include "cx_errors.h"

uint8_t version;

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint32_t hdPath_len;

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

#include "cx.h"

bool ripemd160(uint8_t *in, uint16_t inLen, uint8_t *out) {
    cx_ripemd160_t rip160;
    if( cx_ripemd160_init_no_throw(&rip160) == CX_OK &&
        cx_hash_no_throw(&rip160.header, CX_LAST, in, inLen, out, CX_RIPEMD160_SIZE) == CX_OK) {
        return true;
    } else {
        MEMZERO(out, CX_RIPEMD160_SIZE);
        return false;
    }
}

typedef struct {
    uint8_t publicKey[PK_LEN_SECP256K1];
    uint8_t address[50];
} __attribute__((packed)) answer_t;

#define VERSION_SIZE            1

typedef struct {
    uint8_t hash_sha256[CX_SHA256_SIZE];
    uint8_t hash_ripe[CX_RIPEMD160_SIZE];
} __attribute__((packed)) address_temp_t;


bool is_valid_network_version(uint8_t ver);

// Set the network version to be used when getting the address from
// the device public key.
bool set_network_version(uint8_t network) {
    if (is_valid_network_version(network)) {
        version = network;
        return true;
    }
    zemu_log_stack("Address version not supported/0");
    return false;
}

bool is_valid_network_version(uint8_t ver) {
    switch(ver) {
        case COIN_VERSION_TESTNET_SINGLESIG: break;
        case COIN_VERSION_MAINNET_SINGLESIG: break;
        default: {
            return false;
        }
    }
    return true;
}

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t buffer_len) {
    if (buffer_len < sizeof(answer_t)) {
        return 0;
    }

    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    if(crypto_extractPublicKey(hdPath, HDPATH_LEN_DEFAULT, answer->publicKey, sizeof_field(answer_t, publicKey)) != zxerr_ok) {
        return 0;
    }

    address_temp_t address_temp;

    if(!crypto_extractPublicKeyHash(address_temp.hash_ripe, CX_RIPEMD160_SIZE)) {
        return 0;
    }

    size_t outLen = sizeof_field(answer_t, address);
    if ( !is_valid_network_version(version) )
        version = COIN_VERSION_MAINNET_SINGLESIG;
    outLen = rs_c32_address(address_temp.hash_ripe, version, answer->address, outLen);

    return PK_LEN_SECP256K1 + outLen;
}

uint16_t crypto_fillAuthkey_secp256k1(uint8_t *buffer, uint16_t buffer_len) {
    if (buffer_len < sizeof(answer_t)) {
        return 0;
    }

    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    if(crypto_extractPublicKey(hdPath, HDPATH_LEN_AUTH, answer->publicKey, sizeof_field(answer_t, publicKey)) != zxerr_ok) {
        return 0;
    }

    return PK_LEN_SECP256K1;
}


zxerr_t crypto_extractPublicKey(const uint32_t *path, uint32_t path_len, uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519];
    MEMZERO(&cx_publicKey, sizeof(cx_publicKey));

    if (pubKeyLen < PK_LEN_SECP256K1 || path_len == 0) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t error = zxerr_unknown;
    CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_256K1,
                                           path,
                                           path_len,
                                           privateKeyData, NULL));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));

    error = zxerr_ok;

    // Format pubkey
    for (int i = 0; i < 32; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    if ((cx_publicKey.W[32] & 1) != 0) {
        pubKey[31] |= 0x80;
    }
    MEMCPY(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

    return error;
}

bool crypto_extractPublicKeyHash(uint8_t *pubKeyHash, uint16_t pubKeyLen) {

    if (pubKeyLen < CX_RIPEMD160_SIZE || pubKeyHash == NULL)
        return false;

    // gets the raw public key
    uint8_t publicKey[PK_LEN_SECP256K1];

    if (crypto_extractPublicKey(hdPath, HDPATH_LEN_DEFAULT, publicKey, PK_LEN_SECP256K1) != zxerr_ok) {
        return false;
    }

#ifdef APP_TESTING
    {
        zemu_log("pubKey: ***");
        char buffer[PK_LEN_SECP256K1 * 3];
        array_to_hexstr(buffer, PK_LEN_SECP256K1 * 3,  publicKey, PK_LEN_SECP256K1 );
        zemu_log(buffer);
        zemu_log("\n");
    }
#endif

    // calculates the sha256 + ripemd160
    address_temp_t address_temp;

    cx_hash_sha256(publicKey, PK_LEN_SECP256K1, address_temp.hash_sha256, CX_SHA256_SIZE);
    return ripemd160(address_temp.hash_sha256, CX_SHA256_SIZE, pubKeyHash);         // RIPEMD-160
}

typedef struct {
    uint8_t post_sighash[32];
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

zxerr_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (signatureMaxlen < sizeof_field(signature_t, der_signature)) {
        return zxerr_buffer_too_small;
    }
    *sigSize=0;

    if (messageLen != CX_SHA256_SIZE) {
        return zxerr_out_of_bounds;
    }
    #ifdef APP_TESTING
        char tmpBuff[65] = {0};
        array_to_hexstr(tmpBuff, sizeof(tmpBuff), message, CX_SHA256_SIZE);
        ZEMU_LOGF(100, "Digest: *** %s\n", tmpBuff)
    #endif

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519];
    unsigned int info = 0;

    signature_t *const signature = (signature_t *) buffer;

    zxerr_t zxerr = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_256K1,
                                hdPath,
                                hdPath_len,
                                privateKeyData, NULL));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));

    // Sign
    size_t signatureLength = sizeof_field(signature_t, der_signature);
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                    CX_RND_RFC6979 | CX_LAST,
                                    CX_SHA256,
                                    message,
                                    CX_SHA256_SIZE,
                                    signature->der_signature,
                                    &signatureLength,
                                    &info));

    zxerr = zxerr_ok;

    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);

    if (err != no_error) {
        return zxerr_encoding_failed;
    }

    // return actual size using value from signatureLength
    *sigSize = sizeof_field(signature_t, r) +
               sizeof_field(signature_t, s) +
               sizeof_field(signature_t, v) +
               sizeof_field(signature_t, post_sighash) +
               signatureLength;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, 32);

    if (zxerr != zxerr_ok) {
        MEMZERO(signature, signatureMaxlen);
    }

    return zxerr;
}
