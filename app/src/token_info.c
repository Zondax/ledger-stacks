/*******************************************************************************
 *  (c) 2020 Zondax GmbH
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
#include "token_info.h"

#include "crypto.h"
#include "parser_common.h"
#include "zxmacros.h"

// Static definition of all tokens
static const token_info_t TOKEN_REGISTRY[] = {
    {.contract_address = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token", .token_symbol = "sBTC", .decimals = 8},
    {.contract_address = "SP2XD7417HGPRTREMKF748VNEQPDRR0RMANB7X1NK.token-abtc", .token_symbol = "aBTC", .decimals = 8},
    {.contract_address = "SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.token-alex", .token_symbol = "ALEX", .decimals = 8},
    {.contract_address = "SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.auto-alex-v3", .token_symbol = "LiALEX", .decimals = 8},
    {.contract_address = "SP3Y2ZSH8P7D50B0VBTSX11S7XSG24M1VB9YFQA4K.token-aeusdc", .token_symbol = "aeUSDC", .decimals = 6},
    {.contract_address = "SP3Y2ZSH8P7D50B0VBTSX11S7XSG24M1VB9YFQA4K.token-aewbtc", .token_symbol = "aeWBTC", .decimals = 8},
    {.contract_address = "SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG.ststx-token", .token_symbol = "stSTX", .decimals = 6},
    {.contract_address = "SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG.ststxbtc-token",
     .token_symbol = "stSTXbtc",
     .decimals = 6},
    {.contract_address = "SM26NBC8SFHNW4P1Y4DFH27974P56WN86C92HPEHH.token-lqstx", .token_symbol = "LiSTX", .decimals = 6},
    {.contract_address = "SM26NBC8SFHNW4P1Y4DFH27974P56WN86C92HPEHH.token-vlqstx", .token_symbol = "vLiSTX", .decimals = 6},
    {.contract_address = "SP673Z4BPB4R73359K9HE55F2X91V5BJTN5SXZ5T.token-liabtc", .token_symbol = "LiaBTC", .decimals = 8},
    {.contract_address = "SP2XD7417HGPRTREMKF748VNEQPDRR0RMANB7X1NK.token-susdt", .token_symbol = "aUSD", .decimals = 8},
    {.contract_address = "SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG.usdh-token-v1", .token_symbol = "USDh", .decimals = 8},
    {.contract_address = "SP2C2YFP12AJZB4MABJBAJ55XECVS7E4PMMZ89YZR.usda-token", .token_symbol = "USDA", .decimals = 6},
    {.contract_address = "SP1Y5YSTAHZ88XYK1VPDH24GY0HPX5J4JECTMY4A1.velar-token", .token_symbol = "VELAR", .decimals = 6},
    {.contract_address = "SP14NS8MVBRHXMM96BQY0727AJ59SWPV7RMHC0NCG.pontis-bridge-pBTC",
     .token_symbol = "pBTC",
     .decimals = 8},
    {.contract_address = "SP2C2YFP12AJZB4MABJBAJ55XECVS7E4PMMZ89YZR.arkadiko-token", .token_symbol = "DIKO", .decimals = 6},
    {.contract_address = "SP3K8BC0PPEVCV7NZ6QSRWPQ2JE9E5B6N3PA0KBR9.brc20-trio", .token_symbol = "TRIO", .decimals = 8},
    {.contract_address = "SP3BRXZ9Y7P5YP28PSR8YJT39RT51ZZBSECTCADGR.skullcoin-stxcity",
     .token_symbol = "SKULL",
     .decimals = 6},
    {.contract_address = "SP2ZNGJ85ENDY6QRHQ5P2D4FXKGZWCKTB2T0Z55KS.charisma-token", .token_symbol = "CHA", .decimals = 6},
    {.contract_address = "SP3D6PV2ACBPEKYJTCMH7HEN02KP87QSP8KTEH335.mega", .token_symbol = "MEGA", .decimals = 2},
    {.contract_address = "SP32AEEF6WW5Y0NMJ1S8SBSZDAY8R5J32NBZFPKKZ.nope", .token_symbol = "NOT", .decimals = 0},
    {.contract_address = "SP3NE50GEXFG9SZGTT51P40X2CKYSZ5CC4ZTZ7A2G.welshcorgicoin-token",
     .token_symbol = "WELSH",
     .decimals = 6},
    {.contract_address = "SP1AY6K3PQV5MRT6R4S671NWW2FRVPKM0BR162CT6.leo-token", .token_symbol = "LEO", .decimals = 6},
    {.contract_address = "SP2C1WREHGM75C7TGFAEJPFKTFTEGZKF6DFT6E2GE.kangaroo", .token_symbol = "ROO", .decimals = 6}};

#define TOKEN_REGISTRY_SIZE (sizeof(TOKEN_REGISTRY) / sizeof(TOKEN_REGISTRY[0]))

bool token_principal_matches(const token_info_t *token, const char *addr);

// Compare a token's principal address with an input address
// token: Pointer to token record from registry
// addr: Address to compare with (just the principal part)
bool token_principal_matches(const token_info_t *token, const char *addr) {
    if (token == NULL || addr == NULL) {
        return false;
    }

    const char *addr2 = addr;
    const char *token_addr = token->contract_address;

    // Compare characters until we find a dot in token address or end of either string
    while (*token_addr != '\0' && *addr2 != '\0') {
        if (*token_addr == '.') {
            // We've reached the dot in token address
            break;
        }

        if (*token_addr != *addr2) {
            // Characters don't match
            return false;
        }

        token_addr++;
        addr2++;
    }

    // If we reached the end of token_addr before finding a dot,
    // or reached the dot in token_addr, and addr is also at its end, then it's a match
    return (*token_addr == '.' || *token_addr == '\0') && *addr2 == '\0';
}

// Compare a token's contract name with an input contract name
// token: Pointer to token record from registry
// contract_name: Contract name to compare with
bool token_contract_name_matches(const token_info_t *token, const char *contract_name) {
    if (token == NULL || contract_name == NULL) {
        return false;
    }

    const char *token_addr = token->contract_address;

    size_t i = 0;
    size_t j = 0;
    size_t count = 0;

    // Find the dot in the token's contract address
    while (*token_addr != '\0' && *token_addr != '.') {
        // a.contract_name
        token_addr++;
    }
    // move to first character of the contract name
    token_addr++;

    while (token_addr[i] != '\0' && contract_name[j] != '\0' && count < CONTRACT_ADDR_STR_MAX_LEN) {
        if (token_addr[i] != contract_name[j]) {
            return false;
        }

        i++;
        j++;
        count++;
    }

    return true;
}

// Function to get token info for a contract address
const token_info_t *get_token(const char *contract_address, const char *contract_name) {
    if (contract_address == NULL || contract_name == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < TOKEN_REGISTRY_SIZE; i++) {
        const token_info_t *token = &TOKEN_REGISTRY[i];
        if (token_principal_matches(token, contract_address) && token_contract_name_matches(token, contract_name)) {
            return token;
        }
    }

    return NULL;
}
