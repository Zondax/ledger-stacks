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
#pragma once

#if defined(APP_STANDARD)
#include "coin_standard.h"
#else
#error "APP MODE IS NOT SUPPORTED"
#endif

#define SK_LEN_25519              64u
#define CONTRACT_ADDR_STR_MAX_LEN 100
#define TOKEN_SYMBOL_MAX_LEN      20
