/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef APPSPAWN_ADPATER_CPP
#define APPSPAWN_ADPATER_CPP

#include "appspawn_service.h"

#include <dlfcn.h>
#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif

int32_t SetAppSandboxProperty(struct AppSpawnContent_ *content, AppSpawnClient *client);
void SetAppAccessToken(struct AppSpawnContent_ *content, AppSpawnClient *client);
void LoadExtendLib(AppSpawnContent *content);
void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client);

void RegisterAppSandbox(struct AppSpawnContent_ *content, AppSpawnClient *client);
#ifdef __cplusplus
}
#endif
#endif
