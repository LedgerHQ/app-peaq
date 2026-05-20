
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

#include <stdint.h>

#include "zxerror.h"

#define KECCAK_256_SIZE 32

#define CHECK_CX_OK(CALL)         \
    do {                          \
        cx_err_t __cx_err = CALL; \
        if (__cx_err != CX_OK) {  \
            return zxerr_unknown; \
        }                         \
    } while (0)

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen);

#ifdef __cplusplus
}
#endif
