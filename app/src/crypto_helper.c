
/*******************************************************************************
 *   (c) 2018 - 2022 Zondax AG
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
#include "crypto_helper.h"

#include "zxmacros_ledger.h"
#if defined(LEDGER_SPECIFIC)
#include "cx.h"
#else
#define CX_SHA256_SIZE    32
#define CX_RIPEMD160_SIZE 20
#endif

uint8_t peaq_chain_code;

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
#if defined(LEDGER_SPECIFIC)
    // return actual size using value from signatureLength
    cx_sha3_t keccak;
    if (cx_keccak_init_no_throw(&keccak, outLen * 8) != CX_OK) {
        return zxerr_unknown;
    }
    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&keccak, CX_LAST, in, inLen, out, outLen));
#endif
    return zxerr_ok;
}
