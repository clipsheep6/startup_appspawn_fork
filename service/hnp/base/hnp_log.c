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

#include <stdio.h>
#include <stdarg.h>

#include "securec.h"
#include "hnp_base.h"

#ifdef __cplusplus
extern "C" {
#endif

char *g_logLevelName[HNP_LOG_BUTT] = {"INFO", "DEBUG", "ERROR", "DEBUG"};

void HnpLogPrintf(int logLevel, char *module, const char *format, ...)
{
    char logFormatBuff[1024]; /* 1024:缓存长度 */
    int iRet;

    va_list args;
    va_start(args, format);
    iRet = vsnprintf_s(logFormatBuff, sizeof(logFormatBuff), sizeof(logFormatBuff) - 1, format, args);
    va_end(args);
    if (iRet == -1) {
        return;
    }

    printf("[%s][%s]%s\n", g_logLevelName[logLevel], module, logFormatBuff);
    
    return;
}

#ifdef __cplusplus
}
#endif