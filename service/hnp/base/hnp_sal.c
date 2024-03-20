/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#endif

#include "hnp_base.h"

#ifdef __cplusplus
extern "C" {
#endif

int HnpProgramRunCheck(const char *programName)
{
    char command[HNP_COMMAND_LEN];
    int ret;

    if (sprintf_s(command, HNP_COMMAND_LEN, "ps -ef | grep %s | grep -v grep") < 0) {
        HNP_LOGE("program[%s] run command sprintf unsuccess", programName);
        return HNP_ERRNO_BASE_SPRINTF_FAILED;
    }

    ret = system(command);
    if (ret == 0) {
        HNP_LOGE("program[%s] is running now", programName);
        return HNP_ERRNO_PROGRAM_RUNNING;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif