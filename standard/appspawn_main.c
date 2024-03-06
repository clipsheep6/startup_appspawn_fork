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

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

#include "appspawn_hook.h"
#include "appspawn_modulemgr.h"
#include "appspawn_service.h"
#include "securec.h"

#define APPSPAWN_PRELOAD "libappspawn_helper.z.so"

static void CheckPreload(char *const argv[])
{
    char *preload = getenv("LD_PRELOAD");
    if (preload && strstr(preload, APPSPAWN_PRELOAD)) {
        return;
    }
    char buf[128] = APPSPAWN_PRELOAD;  // 128 is enough in most cases
    if (preload && preload[0]) {
        int len = sprintf_s(buf, sizeof(buf), "%s:" APPSPAWN_PRELOAD, preload);
        APPSPAWN_CHECK(len > 0, return, "preload too long: %{public}s", preload);
    }
    int ret = setenv("LD_PRELOAD", buf, true);
    APPSPAWN_CHECK(ret == 0, return, "setenv fail: %{public}s", buf);
    ssize_t nread = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    APPSPAWN_CHECK(nread != -1, return, "readlink fail: /proc/self/exe: %{public}d", errno);
    buf[nread] = 0;
    ret = execv(buf, argv);
    APPSPAWN_LOGE("execv fail: %{public}s: %{public}d: %{public}d", buf, errno, ret);
}


static int AppSpawnSpawnPost(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("AppSpawnSpawnPost clear all appspawn content");
    // delete all hook
    /*
    AppSpawnModuleMgrUnInstall(MODULE_DEFAULT);
    AppSpawnModuleMgrUnInstall(MODULE_APPSPAWN);
    AppSpawnModuleMgrUnInstall(MODULE_NWEBSPAWN);
    AppSpawnModuleMgrUnInstall(MODULE_COMMON);
    DeleteAppSpawnHookMgr();
    DeleteAppSpawningCtx(property);
    AppSpawnDestroyContent(&content->content);
    */
    return 0;
}

// appspawn -mode appspawn | cold | nwebspawn -param app_property -fd clientFd
int main(int argc, char *const argv[])
{
    if (argc <= 0) {
        return 0;
    }
    SetDumpFlags(0);
    uintptr_t start = (uintptr_t)argv[0];
    uintptr_t end = (uintptr_t)strchr(argv[argc - 1], 0);
    if (end == 0) {
        return 0;
    }
    uint32_t argvSize = end - start;
    if (argvSize < APP_LEN_PROC_NAME) {
        return 0;
    }
    APPSPAWN_LOGV("Start appspawn ...");
    CheckPreload(argv);
    (void)signal(SIGPIPE, SIG_IGN);
    AppSpawnContent *content = StartSpawnService(argvSize, argc, argv);
    if (content != NULL) {
        AddAppSpawnHook(HOOK_SPAWN_POST, HOOK_PRIO_STEP7, AppSpawnSpawnPost);
        content->runAppSpawn(content, argc, argv);
    }
    return 0;
}
