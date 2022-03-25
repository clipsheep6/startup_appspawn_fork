/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "appspawn_msg.h"
#include "appspawn_server.h"
#include "init_hashmap.h"
#include "loop_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RETRY_TIME 10
#define DELAY_US 10 * 1000  // 10ms

typedef struct {
    AppSpawnClient client;
    TaskHandle stream;
    int32_t fd[2]; // 2 fd count
    AppParameter property;
} AppSpawnClientExt;

typedef struct {
    HashNode hashNode;
    uint32_t pid;
    char *appName;
} AppInfo;

typedef struct {
    AppSpawnContent content;
    TaskHandle servcer;
    SignalHandle sigHandler;
    HashMapHandle appMap; // save app pid and name
} AppSpawnContentExt;

void SetContentFunction(AppSpawnContent *content);

#ifdef __cplusplus
}
#endif
#endif // APPSPAWN_SERVICE_H
