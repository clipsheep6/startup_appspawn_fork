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

#include "appspawn_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "appspawn_hook.h"
#include "parameter.h"
#include "securec.h"

uint64_t DiffTime(const struct timespec *startTime, const struct timespec *endTime)
{
    uint64_t diff = (uint64_t)((endTime->tv_sec - startTime->tv_sec) * 1000000);  // 1000000 s-us
    if (endTime->tv_nsec > startTime->tv_nsec) {
        diff += (endTime->tv_nsec - startTime->tv_nsec) / 1000;  // 1000 ns - us
    } else {
        diff -= (startTime->tv_nsec - endTime->tv_nsec) / 1000;  // 1000 ns - us
    }
    return diff;
}

int MakeDirRec(const char *path, mode_t mode, int lastPath)
{
    if (path == NULL || *path == '\0') {
        return -1;
    }
    APPSPAWN_CHECK(path != NULL && *path != '\0', return -1, "Invalid path to create");
    char buffer[PATH_MAX] = {0};
    const char slash = '/';
    const char *p = path;
    char *curPos = strchr(path, slash);
    while (curPos != NULL) {
        int len = curPos - p;
        p = curPos + 1;
        if (len == 0) {
            curPos = strchr(p, slash);
            continue;
        }
        int ret = memcpy_s(buffer, PATH_MAX, path, p - path - 1);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to copy path");
        ret = mkdir(buffer, mode);
        if (ret == -1 && errno != EEXIST) {
            return errno;
        }
        curPos = strchr(p, slash);
    }
    if (lastPath) {
        if (mkdir(path, mode) == -1 && errno != EEXIST) {
            return errno;
        }
    }
    return 0;
}

static void CheckDirRecursive(const char *path)
{
    char buffer[PATH_MAX] = {0};
    const char slash = '/';
    const char *p = path;
    char *curPos = strchr(path, slash);
    while (curPos != NULL) {
        int len = curPos - p;
        p = curPos + 1;
        if (len == 0) {
            curPos = strchr(p, slash);
            continue;
        }
        int ret = memcpy_s(buffer, PATH_MAX, path, p - path - 1);
        APPSPAWN_CHECK(ret == 0, return, "Failed to copy path");
        ret = access(buffer, F_OK);
        APPSPAWN_CHECK(ret == 0, return, "Dir not exit %{public}s errno: %{public}d", buffer, errno);
        curPos = strchr(p, slash);
    }
    int ret = access(path, F_OK);
    APPSPAWN_CHECK(ret == 0, return, "Dir not exit %{public}s errno: %{public}d", buffer, errno);
    return;
}

int SandboxMountPath(const MountArg *arg)
{
    int ret = mount(arg->originPath, arg->destinationPath, arg->fsType, arg->mountFlags, arg->options);
    if (ret != 0) {
        if (arg->originPath != NULL && strstr(arg->originPath, "/data/app/el2/") != NULL) {
            CheckDirRecursive(arg->originPath);
        }
        APPSPAWN_LOGW("errno is: %{public}d, bind mount %{public}s => %{public}s",
            errno, arg->originPath, arg->destinationPath);
        return errno;
    }
    ret = mount(NULL, arg->destinationPath, NULL, arg->mountSharedFlag, NULL);
    if (ret != 0) {
        APPSPAWN_LOGW("errno is: %{public}d, bind mount %{public}s => %{public}s",
            errno, arg->originPath, arg->destinationPath);
        return errno;
    }
    return 0;
}

static uint32_t g_dumpToConsole = 0;
void SetDumpFlags(uint32_t flags)
{
    g_dumpToConsole = flags;
}

#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wvarargs"
#elif defined(__GNUC__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wvarargs"
#elif defined(_MSC_VER)
#    pragma warning(push)
#endif

void AppSpawnDump(const char *fmt, ...)
{
    if (!g_dumpToConsole) {
        return;
    }
    char format[128] = {0};  // 128 max buffer for format
    uint32_t size = strlen(fmt);
    int curr = 0;
    for (uint32_t index = 0; index < size; index++) {
        if (curr >= (int)sizeof(format)) {
            format[curr - 1] = '\0';
        }
        if (fmt[index] == '%' && (strncmp(&fmt[index + 1], "{public}", strlen("{public}")) == 0)) {
            format[curr++] = fmt[index];
            index += strlen("{public}");
            continue;
        }
        format[curr++] = fmt[index];
    }
    va_list vargs;
    va_start(vargs, format);
    vprintf(format, vargs);
    va_end(vargs);
    printf("\n");
    (void)fflush(stdout);
}

#if defined(__clang__)
#    pragma clang diagnostic pop
#elif defined(__GNUC__)
#    pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#    pragma warning(pop)
#endif
