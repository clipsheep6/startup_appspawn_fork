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
#ifndef APPSPAWN_TEST
#include <dlfcn.h>
#endif
#include "appspawn_adapter.h"

#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/app/main_thread.h"
#ifndef APPSPAWN_TEST
using AllowFunc = void(*)(uint8_t);
static const char *LIBNETSYS_CLIENT_NAME = "libnetsys_client.z.so";
static const char *ALLOW_SOCKET_FUNCNAME = "SetAllowCreateSocket";
#endif
void LoadExtendLib(AppSpawnContent *content)
{
#ifdef __aarch64__
    const char *acelibdir("/system/lib64/libace.z.so");
#else
    const char *acelibdir("/system/lib/libace.z.so");
#endif
    APPSPAWN_LOGI("MainThread::LoadAbilityLibrary. Start calling dlopen acelibdir.");
#ifndef APPSPAWN_TEST
    void *AceAbilityLib = NULL;
    AceAbilityLib = dlopen(acelibdir, RTLD_NOW | RTLD_GLOBAL);
    APPSPAWN_CHECK(AceAbilityLib != NULL, return, "Fail to dlopen %s, [%s]", acelibdir, dlerror());
#endif
    APPSPAWN_LOGI("Success to dlopen %s", acelibdir);
    APPSPAWN_LOGI("MainThread::LoadAbilityLibrary. End calling dlopen");
}

void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGI("AppExecFwk::MainThread::Start");
#ifndef APPSPAWN_TEST
    if (client != NULL && client->setAllowInternet == 1 && client->allowInternet == 0) {
        void* handler = dlopen(LIBNETSYS_CLIENT_NAME, RTLD_LAZY);
        if (handler != NULL) {
            AllowFunc func = (AllowFunc)dlsym(handler, ALLOW_SOCKET_FUNCNAME);
            if (func != NULL) {
                func(0);
            }
            dlclose(handler);
        }
    }
    OHOS::AppExecFwk::MainThread::Start();
#endif
}
