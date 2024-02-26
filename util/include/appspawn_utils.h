/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef APPSPAWN_UTILS_H
#define APPSPAWN_UTILS_H

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#ifndef APPSPAWN_TEST
#define APPSPAWN_STATIC static
#else
#define APPSPAWN_STATIC
#endif

#ifndef APPSPAWN_BASE_DIR
#define APPSPAWN_BASE_DIR ""
#endif
#if defined(__MUSL__)
#define APPSPAWN_SOCKET_DIR APPSPAWN_BASE_DIR "/dev/unix/socket/"
#else
#define APPSPAWN_SOCKET_DIR APPSPAWN_BASE_DIR "/dev/socket/"
#endif

#define APPSPAWN_CHECK_EXIT "AppSpawnCheckUnexpectedExitCall"
#define UNUSED(x) (void)(x)

#define APP_COLD_START 0x01
#define APP_ASAN_DETECTOR 0x02
#define APP_DEVELOPER_MODE 0x04

#define MAX_LEN_SHORT_NAME 16
#define DEFAULT_UMASK 0002
#define UID_BASE 200000 // 20010029
#define DEFAULT_DIR_MODE 0711
#define USER_ID_BUFFER_SIZE 32

#define APPSPAWN_SEC_TO_NSEC 1000000000
#define APPSPAWN_MSEC_TO_NSEC 1000000
#define APPSPAWN_USEC_TO_NSEC 1000
#define APPSPAWN_SEC_TO_MSEC 1000

#define TEST_FLAGS_BY_INDEX(flags, index) ((((flags) >> (index)) & 0x1) == 0x1)

typedef enum {
    APPSPAWN_OK = 0,
    APPSPAWN_INVALID_ARG = 0xD000000,
    APPSPAWN_INVALID_MSG,
    APPSPAWN_SYSTEM_ERROR,
    APPSPAWN_NO_TLV,
    APPSPAWN_NO_SANDBOX,
    APPSPAWN_LOAD_SANDBOX_FAIL,
    APPSPAWN_CLIENT_TIMEOUT,
    APPSPAWN_CHILD_CRASH,
    APPSPAWN_NOT_SUPPORT_NATIVE,
    APPSPAWN_INVALID_ACCESS_TOKEN,
    APPSPAWN_NODE_EXIST,

    APPSPAWN_TIMEOUT = 0xD100000, // for client
    APPSPAWN_RETRY_MAX,
    APPSPAWN_RETRY_AGAIN,
    APPSPAWN_CLOSE_CONNECT,
    APPSPAWN_RETRY_CONNECT,
    APPSPAWN_TLV_NOT_SUPPORT,
} AppSpawnErrorCode;

typedef enum  {
    // run in init
    HOOK_PRELOAD  = 10,
    // run before fork
    HOOK_SPAWN_PREPARE = 20,
    // run in child process
    HOOK_SPAWN_FIRST = 30, // clear env, set token
    HOOK_SPAWN_SECOND,
    HOOK_SPAWN_THIRD,

    HOOK_SPAWN_POST = 40,
    // for app change
    HOOK_APP_ADD = 50,
    HOOK_APP_DIED,
} APPSPAWN_HOOK;

typedef enum {
    HOOK_PRIO_STEP1 = 1000,
    HOOK_PRIO_STEP2 = 2000,
    HOOK_PRIO_STEP3 = 3000,
    HOOK_PRIO_STEP4 = 4000,
    HOOK_PRIO_SANDBOX = 5000,
    HOOK_PRIO_STEP6 = 6000,
    HOOK_PRIO_STEP7 = 7000,
} AppSpawnHookPrio;

int CheckEnabled(const char *param, const char *defValue);
uint64_t DiffTime(const struct timespec *startTime, const struct timespec *endTime);
uint8_t *Base64Decode(const char *data, uint32_t dataLen, uint32_t *outLen);
char *Base64Encode(const uint8_t *data, uint32_t len);
void AppSpawnDump(const char *fmt, ...);
void SetDumpFlags(uint32_t flags);

#ifndef APP_FILE_NAME
#define APP_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#ifndef OHOS_LITE
#define APPSPAWN_DOMAIN (0xD002C00 + 0x11)
#ifndef APPSPAWN_LABEL
#define APPSPAWN_LABEL "APPSPAWN"
#endif

#ifndef APPSPAWN_TEST
#define APPSPAWN_LOG(logLevel, domain, tag, fmt, ...) \
    HiLogPrint(LOG_CORE, (LogLevel)logLevel, domain, tag, \
        "[%{public}s:%{public}d]" fmt,  (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#else
#define APPSPAWN_LOG(logLevel, domain, tag, fmt, ...) \
    AppSpawnDump("[%d %d][%{public}s:%{public}d]" fmt, getpid(), gettid(), (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#endif

#define APPSPAWN_LOGI(fmt, ...) \
    APPSPAWN_LOG(LOG_INFO, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__)
#define APPSPAWN_LOGE(fmt, ...) \
    APPSPAWN_LOG(LOG_ERROR, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__)
#define APPSPAWN_LOGV(fmt, ...) \
    APPSPAWN_LOG(LOG_INFO, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__)
#define APPSPAWN_LOGW(fmt, ...) \
    APPSPAWN_LOG(LOG_WARN, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__)
#define APPSPAWN_LOGF(fmt, ...) \
    APPSPAWN_LOG(LOG_FATAL, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__)

#define APPSPAPWN_DUMP(fmt, ...) \
    do { \
        HiLogPrint(LOG_CORE, LOG_INFO, APPSPAWN_DOMAIN, APPSPAWN_LABEL, fmt, ##__VA_ARGS__); \
        AppSpawnDump(fmt, ##__VA_ARGS__); \
    } while (0)

#else

#define APPSPAWN_LOGI(fmt, ...) \
    HILOG_INFO(HILOG_MODULE_HIVIEW, "[%{public}s:%{public}d]" fmt,  (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#define APPSPAWN_LOGE(fmt, ...) \
    HILOG_ERROR(HILOG_MODULE_HIVIEW, "[%{public}s:%{public}d]" fmt,  (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#define APPSPAWN_LOGV(fmt, ...) \
    HILOG_DEBUG(HILOG_MODULE_HIVIEW, "[%{public}s:%{public}d]" fmt,  (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#define APPSPAWN_LOGW(fmt, ...) \
    HILOG_FATAL(HILOG_MODULE_HIVIEW, "[%{public}s:%{public}d]" fmt,  (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)
#endif

#define APPSPAWN_CHECK(retCode, exper, fmt, ...) \
    if (!(retCode)) {                    \
        APPSPAWN_LOGE(fmt, ##__VA_ARGS__);         \
        exper;                           \
    }

#define APPSPAWN_CHECK_ONLY_EXPER(retCode, exper) \
    if (!(retCode)) {                  \
        exper;                 \
    }                         \

#define APPSPAWN_CHECK_ONLY_LOG(retCode, fmt, ...) \
    if (!(retCode)) {                    \
        APPSPAWN_LOGE(fmt, ##__VA_ARGS__);      \
    }
#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // APPSPAWN_UTILS_H
