/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef APPSPAWN_SERVICE_H
#define APPSPAWN_SERVICE_H

#include <unistd.h>
#include <stdbool.h>
#include "appspawn_msg.h"
#include "appspawn_server.h"
#include "init_hashmap.h"
#include "loop_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef APPSPAWN_TEST
#define APPSPAWN_STATIC
#else
#define APPSPAWN_STATIC static
#endif

#define APP_HASH_BUTT 32
#define FLAGS_ON_DEMAND 0x1
#define FLAGS_MODE_COLD 0x2
#define FLAGS_SANDBOX_PRIVATE 0x10
#define FLAGS_SANDBOX_APP 0x20

#define START_INDEX 1
#define FD_INDEX 2
#define PARAM_INDEX 3
#define HSP_LIST_LEN_INDEX 4
#define HSP_LIST_INDEX 5
#define OVERLAY_LEN_INDEX 6
#define OVERLAY_INDEX 7
#define DIR_LIST_LEN_INDEX 8
#define DIR_LIST_INDEX 9
#define NULL_INDEX 10
#define PARAM_BUFFER_LEN 128
typedef struct {
    AppSpawnClient client;
    TaskHandle stream;
    int32_t fd[2];  // 2 fd count
    AppParameter property;
    pid_t pid;
} AppSpawnClientExt;

typedef struct {
    HashNode node;
    pid_t pid;
    char name[0];
} AppInfo;

typedef struct {
    AppSpawnContent content;
    uint32_t flags;
    TaskHandle server;
    SignalHandle sigHandler;
    TimerHandle timer;
    HashMapHandle appMap;  // save app pid and name
} AppSpawnContentExt;

void SetContentFunction(AppSpawnContent *content);
void AppSpawnColdRun(AppSpawnContent *content, int argc, char *const argv[]);
int GetAppSpawnClientFromArg(int argc, char *const argv[], AppSpawnClientExt *client);
#define SHOW_CLIENT(info, clientExt) \
do { \
    APPSPAWN_LOGI("Info %{public}s id %{public}d code %{public}d ",                                 \
        info, (clientExt)->client.id, (clientExt)->property.code);                                  \
    APPSPAWN_LOGI("processname %{public}s flags 0x%{public}x",                                      \
        (clientExt)->property.processName, (clientExt)->property.flags);                            \
    APPSPAWN_LOGI("flags 0x%{public}x cloneFlags 0x%{public}x hapFlags 0x%{public}x",               \
        (clientExt)->client.flags, (clientExt)->client.cloneFlags, (clientExt)->property.hapFlags); \
    APPSPAWN_LOGI("bundleName %{public}s soPath %{public}s",                                        \
        (clientExt)->property.bundleName, (clientExt)->property.soPath);                            \
    APPSPAWN_LOGI("Access token apl %{public}s renderCmd %{public}s",                               \
        (clientExt)->property.apl, (clientExt)->property.renderCmd);                                \
    APPSPAWN_LOGI("uid %{public}u %{public}u gid count %{public}u",                                 \
        (clientExt)->property.uid, (clientExt)->property.gid, (clientExt)->property.gidCount);      \
    APPSPAWN_LOGI("setAllowInternet %{public}d allowInternet %{public}d ",                          \
        (clientExt)->property.setAllowInternet, (clientExt)->property.allowInternet);               \
} while (0)

#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_SERVICE_H
