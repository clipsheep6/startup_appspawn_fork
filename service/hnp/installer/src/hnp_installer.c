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
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#include "hnp_installer.h"

#ifdef __cplusplus
extern "C" {
#endif

static int HnpUnInstall(const char *uninstallPath, const char *programName)
{
    int ret;

    /* 查询软件是否正在运行 */
    ret = HnpProgramRunCheck(programName);
    if (ret != 0) {
        return ret;
    }

    return HnpDeleteFolder(uninstallPath);
}

int HnpCmdInstall(int argc, char *argv[])
{
    HNP_LOGI("\r\ninstall cmd not support now!");
    return -1;
}

int HnpCmdUnInstall(int argc, char *argv[])
{
    int uid;
    char uninstallPath[MAX_FILE_PATH_LEN];

    if (argc < HNP_INDEX_4) {
        HNP_LOGE("uninstall args num[%u] unsuccess!", argc);
        return HNP_ERRNO_UNINSTALLER_ARGV_NUM_INVALID;
    }

    uid = atoi(argv[HNP_INDEX_2]);
    /* 拼接卸载路径 */
    if (sprintf_s(uninstallPath, MAX_FILE_PATH_LEN, HNP_DEFAULT_INSTALL_ROOT_PATH"%d/hnp/%s.org/%s_%s/", uid,
        argv[HNP_INDEX_3], argv[HNP_INDEX_3], argv[HNP_INDEX_4]) < 0) {
        HNP_LOGE("uninstall path sprintf unsuccess, uid:%u", uid);
        return HNP_ERRNO_BASE_SPRINTF_FAILED;
    }

    /* 校验目标目录是否存在判断是否安装 */
    if (access(uninstallPath, F_OK) != 0) {
        HNP_LOGE("uninstall path:%s is not exist", uninstallPath);
        return HNP_ERRNO_UNINSTALLER_PATH_NOT_EXIST;
    }

    return HnpUnInstall(uninstallPath, argv[HNP_INDEX_3]);
}

#ifdef __cplusplus
}
#endif