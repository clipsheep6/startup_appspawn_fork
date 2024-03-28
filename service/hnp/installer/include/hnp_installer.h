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

#ifndef HNP_INSTALLER_H
#define HNP_INSTALLER_H

#include "hnp_base.h"

#ifdef __cplusplus
extern "C" {
#endif

// 0x801306 卸载命令参数错误
#define HNP_ERRNO_UNINSTALLER_ARGV_NUM_INVALID             HNP_ERRNO_COMMON(HNP_MID_INSTALLER, 0x6)

// 0x801307 获取卸载路径失败
#define HNP_ERRNO_UNINSTALLER_PATH_NOT_EXIST               HNP_ERRNO_COMMON(HNP_MID_INSTALLER, 0x7)

#define HNP_DEFAULT_INSTALL_ROOT_PATH "/data/app/el1/bundle/"

int HnpCmdInstall(int argc, char *argv[]);

int HnpCmdUnInstall(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif