/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018, 2019 Zondax GmbH
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
#include "app_main.h"
#include "view.h"

#include <os_io_seproxyhal.h>

__attribute__((section(".boot"))) int
main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    view_init();
    os_boot();

    volatile uint8_t app_init_done = 0;
    volatile uint32_t rx = 0, tx = 0, flags = 0;
    volatile uint16_t sw = 0;

    for (;;) {
        BEGIN_TRY
        {
            TRY
            {
                if (!app_init_done) {
                    app_init();
                    app_init_done = 1;
                }

                rx = tx;
                tx = 0;

                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;
                CHECK_APP_CANARY()

                if (rx == 0)
                    THROW(APDU_CODE_EMPTY_BUFFER);

                handle_generic_apdu(&flags, &tx, rx);
                CHECK_APP_CANARY()

                handleApdu(&flags, &tx, rx);
                CHECK_APP_CANARY()
            }
            CATCH_OTHER(e)
            {
                if (app_init_done) {
                    switch (e & 0xF000) {
                        case 0x6000:
                        case 0x9000:
                            sw = e;
                            break;
                        default:
                            sw = 0x6800 | (e & 0x7FF);
                            break;
                    }
                    G_io_apdu_buffer[tx] = sw >> 8;
                    G_io_apdu_buffer[tx + 1] = sw;
                    tx += 2;
                }
            }
            FINALLY
            {}
        }
        END_TRY;
    }
}
