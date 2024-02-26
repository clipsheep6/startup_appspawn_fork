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

#ifndef APPSPAWN_MODULE_MGR_H
#define APPSPAWN_MODULE_MGR_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "hookmgr.h"
#include "modulemgr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppSpawnContent_ AppSpawnContent;
typedef struct AppSpawnClient_ AppSpawnClient;
typedef struct AppSpawnAppInfo_ AppSpawnAppInfo;
typedef enum {
    MODULE_DEFAULT,
    MODULE_APPSPAWN,
    MODULE_NWEBSPAWN,
    MODULE_COMMON,
    MODULE_MAX
} AppSpawnModuleType;

typedef struct {
    AppSpawnContent *content;
    AppSpawnClient *client;
    struct timespec tmStart;
    struct timespec tmEnd;
} AppSpawnHookArg;

int AppSpawnModuleMgrInstall(const char *mgrName);
int AppSpawnLoadAutoRunModules(int type);
void AppSpawnModuleMgrUnInstall(int type);
void DeleteAppSpawnHookMgr(void);

int PreloadHookExecute(AppSpawnContent *content);

typedef struct {
    const struct AppSpawnContent_ *content;
    const AppSpawnAppInfo *appInfo;
} AppSpawnAppArg;

int AppChangeHookExecute(int stage, const AppSpawnContent *content, const AppSpawnAppInfo *appInfo);

#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_MODULE_MGR_H
