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

#define COIN_SECRET_REQUIRED_CLICKS 0
#define MENU_MAIN_APP_LINE2_SECRET ""

#if defined(APP_STANDARD)
#include "coin_standard.h"
#elif defined(APP_VARIANT1)
#include "coin_variant1.h"
#else
#error "APP MODE IS NOT SUPPORTED"
#endif
