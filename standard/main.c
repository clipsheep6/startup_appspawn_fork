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

#include "appspawn_server.h"
#include "appspawn_msg.h"
#include "appspawn_adapter.h"

extern void * g_nwebHandle;

#ifdef NWEB_SPAWN
void LoadExtendLib(AppSpawnContent *content)
{
    LoadAceLib();
}

void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    typedef void (*FuncType) (const char *cmd);
    FuncType funcNWebRenderMain = (FuncType)(dlsym(g_nwebHandle, "NWebRenderMain"));
    if (funcNWebRenderMain == NULL) {
        APPSPAWN_LOGI("webviewspawn dlsym ERROR=%s", dlerror());
        return;
    }
    funcNWebRenderMain(appProperty->property.renderCmd);
}

#else
void LoadExtendLib(AppSpawnContent *content)
{
    const char* acelibdir = "/system/lib/libace.z.so";
    void *AceAbilityLib = NULL;
    APPSPAWN_LOGI("MainThread::LoadAbilityLibrary. Start calling dlopen acelibdir.");
    AceAbilityLib = dlopen(acelibdir, RTLD_NOW | RTLD_GLOBAL);
    if (AceAbilityLib == NULL) {
        APPSPAWN_LOGE("Fail to dlopen %s, [%s]", acelibdir, dlerror());
    } else {
        APPSPAWN_LOGI("Success to dlopen %s", acelibdir);
    }
    APPSPAWN_LOGI("MainThread::LoadAbilityLibrary. End calling dlopen.");
}

void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    StartMainThread();
}
#endif

int main(int argc, char *const argv[])
{
    SetInitLogLevel(1);
    if (argc > 0) {
        // calculate child process long name size
        uintptr_t start = (uintptr_t)argv[0];
        uintptr_t end = (uintptr_t)strchr(argv[argc - 1], 0);
        int64_t argvSize = end - start;
        AppSpawnContent *content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, argv[0], argvSize);
        APPSPAWN_CHECK(content != NULL, return -1, "Invalid content for appspawn");
        APPSPAWN_CHECK(content->runAppSpawn != NULL, return -1, "Invalid content for appspawn");
        APPSPAWN_CHECK(content->initAppSpawn != NULL, return -1, "Invalid content for appspawn");

        // set common operation
        content->loadExtendLib = LoadExtendLib;
        content->runChildProcessor = RunChildProcessor;

        content->initAppSpawn(content);
        // run, to start loop and wait message
        content->runAppSpawn(content);
    }
    return 0;
}
