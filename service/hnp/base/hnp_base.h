 /*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HNP_BASE_H
#define HNP_BASE_H

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILE_PATH_LEN 128

#define HNP_HEAD_MAGIC 0x12345678
#define HNP_HEAD_VERSION 1

/* Native软件二进制软链接配置 */
typedef struct NativeBinLink {
    char source[MAX_FILE_PATH_LEN];
    char target[MAX_FILE_PATH_LEN];
} NativeBinLink;

/* hnp文件头结构 */
typedef struct NativeHnpHead {
    unsigned int magic;     // 魔术字校验
    unsigned int version;   // 版本号
    unsigned int headLen;   // hnp结构头大小
    unsigned int reserve;   // 预留字段
    char hnpVersion[32];    // Native软件包版本号
    unsigned int linkNum;   // 软链接配置个数
    NativeBinLink links[0];
} NativeHnpHead;

typedef enum  {
    HNP_LOG_INFO    = 0,
    HNP_LOG_WARN    = 1,
    HNP_LOG_ERROR   = 2,
    HNP_LOG_DEBUG   = 3,
    HNP_LOG_BUTT
} HNP_LOG_LEVEL_E;

void HnpLogPrintf(int logLevel, char *module, const char *format, ...);

#define HNP_LOGI(args...) \
    HnpLogPrintf(HNP_LOG_INFO, "HNP", ##args)

#define HNP_LOGE(args...) \
    HnpLogPrintf(HNP_LOG_ERROR, "HNP", ##args)

#ifdef __cplusplus
}
#endif

#endif