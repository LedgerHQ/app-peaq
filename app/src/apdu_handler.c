/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "apdu_handler_evm.h"
#include "app_main.h"
#include "coin.h"
#include "coin_evm.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

bool review_pending = false;

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (PATCH_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[7] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            const uint8_t cla = G_io_apdu_buffer[OFFSET_CLA];

            if ((cla != CLA) && (cla != CLA_ETH)) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            if (is_review_pending()) {
                THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
            }

            const uint8_t instruction = G_io_apdu_buffer[OFFSET_INS];
            switch (instruction) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }
                case INS_GET_ADDR_ETH:
                    CHECK_PIN_VALIDATED()
                    if (cla != CLA_ETH) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleGetAddrEth(flags, tx, rx);
                    break;

                case INS_SIGN_ETH: {
                    CHECK_PIN_VALIDATED()
                    if (cla != CLA_ETH) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleSignEth(flags, tx, rx);
                    break;
                }

                case INS_SIGN_PERSONAL_MESSAGE: {
                    CHECK_PIN_VALIDATED()
                    if (cla != CLA_ETH) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    handleSignEip191(flags, tx, rx);
                    break;
                }
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            set_review_pending(false);
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case APDU_CODE_OK:
                    // Multi-chunk continuation (handleSign* THROWs APDU_CODE_OK between chunks).
                    // Leave state alone so the next chunk can resume.
                    sw = e;
                    break;
                case 0x6000:
                    reset_evm_chunk_state();
                    sw = e;
                    break;
                default:
                    reset_evm_chunk_state();
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}
