
/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>

#include "appspawn_utils.h"

#define BASE64_SOURCE_STEP 3
#define BASE64_DEST_STEP 4
#define BASE64_MASK 0x3F
#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'

#define CALC_ENCODE_LEN(len) ((((len) + 2) / 3 + 1) * 4 + 1)
#define CALC_DECODE_LEN(len) ((len) / 4 * 3)

static const char g_base64EncodeTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/* ASCII order for BASE 64 decode, 255 in unused character */
static const uint8_t g_base64DecodeTab[] = {
    /* nul, soh, stx, etx, eot, enq, ack, bel, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /*  sp, '!', '"', '#', '$', '%', '&', ''', */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* '(', ')', '*', '+', ',', '-', '.', '/', */
    255, 255, 255, 62, 255, 255, 255, 63,

    /* '0', '1', '2', '3', '4', '5', '6', '7', */
    52, 53, 54, 55, 56, 57, 58, 59,

    /* '8', '9', ':', ';', '<', '=', '>', '?', */
    60, 61, 255, 255, 255, 255, 255, 255,

    /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
    255, 0, 1, 2, 3, 4, 5, 6,

    /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
    7, 8, 9, 10, 11, 12, 13, 14,

    /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
    15, 16, 17, 18, 19, 20, 21, 22,

    /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
    23, 24, 25, 255, 255, 255, 255, 255,

    /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
    255, 26, 27, 28, 29, 30, 31, 32,

    /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
    33, 34, 35, 36, 37, 38, 39, 40,

    /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
    41, 42, 43, 44, 45, 46, 47, 48,

    /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
    49, 50, 51, 255, 255, 255, 255, 255
};

static void EncodeSection(const uint8_t *data, char *out)
{
	// get data[0] high 6 bit 2 0x3F
    out[0] = g_base64EncodeTab[(data[0] >> 2) & 0x3F];
   	// get data[0] low 2 bit and data[1] high 4 bit 0x3 0xF
    out[1] = g_base64EncodeTab[((data[0] & 0x3) << 4) | ((data[1] >> 4) & 0xF)];
    // get data[1] low 4 bit and data[2] high 2 bit 6 0x3 0xF
    out[2] = g_base64EncodeTab[((data[1] & 0xF) << 2) | ((data[2] >> 6) & 0x3)];
    out[3] = g_base64EncodeTab[data[2] & 0x3F]; // get data[2] low 4 bit 2 0x3F
}

char *Base64Encode(const uint8_t *data, uint32_t len)
{
    APPSPAWN_CHECK_ONLY_EXPER(data != NULL && len > 0, return NULL);
    uint32_t realLen = CALC_ENCODE_LEN(len);
    APPSPAWN_CHECK_ONLY_EXPER(realLen > 0, return NULL);
    char *out = (char *)malloc(realLen);
    APPSPAWN_CHECK(out != NULL, return NULL, "Failed to alloc memory %{public}d", realLen);

    uint32_t sourceIndex = 0;
    uint32_t destIndex = 0;
    while (sourceIndex < len) {
        if (sourceIndex + BASE64_SOURCE_STEP > len) {
            break;
        }
        EncodeSection(data + sourceIndex, out + destIndex);
        sourceIndex += BASE64_SOURCE_STEP;
        destIndex += BASE64_DEST_STEP;
    }

    if ((len - sourceIndex) == 1) { // 1 byte
        out[destIndex++] = g_base64EncodeTab[(data[sourceIndex] >> 2) & 0x3F]; // 2 0x3F
        out[destIndex++] = g_base64EncodeTab[(data[sourceIndex] & 0x3) << 4]; // 4 0x3
        out[destIndex++] = BASE64_PAD;
        out[destIndex++] = BASE64_PAD;
    } else if ((len - sourceIndex) == 2) { // 2 byte
        out[destIndex++] = g_base64EncodeTab[(data[sourceIndex] >> 2) & 0x3F]; // 2 0x3F
        // 0x3 4 0xF
        out[destIndex++] = g_base64EncodeTab[((data[sourceIndex] & 0x3) << 4) | ((data[sourceIndex + 1] >> 4) & 0xF)];
        out[destIndex++] = g_base64EncodeTab[((data[sourceIndex + 1] & 0xF) << 2)]; // 2 0xF
        out[destIndex++] = BASE64_PAD;
    }
    out[destIndex] = 0;
    return out;
}

uint8_t *Base64Decode(const char *data, uint32_t dataLen, uint32_t *outLen)
{
    APPSPAWN_CHECK_ONLY_EXPER(data != NULL && dataLen > 0 && outLen != NULL, return NULL);
    if (dataLen & 0x3) {  // 0x3 4 algin
        return NULL;
    }
    *outLen = 0;
    uint32_t realLen = CALC_DECODE_LEN(dataLen);
    uint8_t *out = (uint8_t *)malloc(realLen);
    APPSPAWN_CHECK(out != NULL, return NULL, "Failed to alloc memory %{public}d", realLen);

    uint32_t source = 0;
    uint32_t destIndex = 0;
    for (; source < dataLen; source++) {
        if (data[source] == BASE64_PAD) {
            break;
        }

		// invalid char
        if (data[source] < BASE64DE_FIRST || data[source] > BASE64DE_LAST) {
            free(out);
            return NULL;
        }
        uint8_t dest = g_base64DecodeTab[(uint8_t)data[source]];
        if (dest == 255) { // 255 invalid
            free(out);
            return NULL;
        }

        switch (source & 0x3) {
            case 0:
                out[destIndex] = (dest << 2) & 0xFF; // 2 oxFF
                break;
            case 1:
                out[destIndex++] |= (dest >> 4) & 0x3; // 4 0x3
                out[destIndex] = (dest & 0xF) << 4; // 4 0xF
                break;
            case 2: // 2 byte
                out[destIndex++] |= (dest >> 2) & 0xF; // 2 0xF
                out[destIndex] = (dest & 0x3) << 6; // 3 0x3 6
                break;
            case 3: // 3 byte
                out[destIndex++] |= dest;
                break;
        }
    }
    *outLen = destIndex;
    return out;
}