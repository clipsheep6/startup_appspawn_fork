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

#ifndef HNP_API_H
#define HNP_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FALSE,
    TRUE
} Bool;

#define HNP_API_ERRNO_BASE 0x2000

// 0x2001 参数非法
#define HNP_API_ERRNO_PARAM_INVALID             (HNP_API_ERRNO_BASE + 0x1)

// 0x2002 fork子进程失败
#define HNP_API_ERRNO_FORK_FAILED               (HNP_API_ERRNO_BASE + 0x2)

// 0x2003 等待子进程退出失败
#define HNP_API_WAIT_PID_FAILED                 (HNP_API_ERRNO_BASE + 0x3)

/**
 * Install native software package.
 *
 * @param userId Indicates id of user.
 * @param packages  Indicates the path of hnp file.
 * @param count  Indicates num of hnp file.
 * @param installPath  Indicates the path for private hnp file.
 * @param installOptions Indicates install options.
 *
 * @return 0:success;other means failure.
 */
int NativeInstallHnp(const char *userId, const char *packages[], int count, const char installPath, int installOptions);

/**
 * Uninstall native software package.
 *
 * @param userId Indicates id of user.
 * @param hnpName  Indicates the name of native software.
 * @param hnpVersion Indicates the version of native software.
 * @param installPath  Indicates the path for private hnp file.
 *
 * @return 0:success;other means failure.
 */
int NativeUnInstallHnp(const char *userId, const char *hnpName, const char *hnpVersion, const char *installPath);

#ifdef __cplusplus
}
#endif

#endif