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

#ifndef APPSPAWN_SERVER_H
#define APPSPAWN_SERVER_H
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "appspawn_utils.h"
#ifdef __cplusplus
extern "C" {
#endif

#define HOOK_STOP_WHEN_ERROR 0x2
typedef enum RunMode_ {
    MODE_FOR_APPSPAWN,
    MODE_FOR_NWEBSPAWN,
    MODE_FOR_APP_COLD_RUN,
    MODE_FOR_NWEB_COLD_RUN
} RunMode;

typedef struct AppSpawnClient_ {
    uint32_t id;
    uint32_t flags; // Save negotiated flags
} AppSpawnClient;

typedef struct AppSpawnContent_ {
    char *longProcName;
    uint32_t longProcNameLen;
    uint32_t sandboxNsFlags;
    RunMode mode;

    // system
    void (*runAppSpawn)(struct AppSpawnContent_ *content, int argc, char *const argv[]);
    void (*notifyResToParent)(struct AppSpawnContent_ *content, AppSpawnClient *client, int result);
    void (*runChildProcessor)(struct AppSpawnContent_ *content, AppSpawnClient *client);
    // for cold start
    int (*coldStartApp)(struct AppSpawnContent_ *content, AppSpawnClient *client);
} AppSpawnContent;

typedef struct AppSpawnForkArg_ {
    struct AppSpawnContent_ *content;
    AppSpawnClient *client;
} AppSpawnForkArg;

AppSpawnContent *AppSpawnCreateContent(const char *socketName, char *longProcName, uint32_t longProcNameLen, int cold);
int AppSpawnHookExecute(int stage, uint32_t flags, AppSpawnContent *content, AppSpawnClient *client);
int AppSpawnProcessMsg(AppSpawnContent *content, AppSpawnClient *client, pid_t *childPid);
#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_SERVER_H
