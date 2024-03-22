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

#include "appspawn_modulemgr.h"

#include "appspawn_hook.h"
#include "appspawn_manager.h"
#include "appspawn_utils.h"
#include "hookmgr.h"
#include "modulemgr.h"

typedef struct {
    const AppSpawnContent *content;
    const AppSpawnedProcess *appInfo;
} AppSpawnAppArg;

static struct {
    MODULE_MGR *moduleMgr;
    AppSpawnModuleType type;
    const char *moduleName;
} g_moduleMgr[MODULE_MAX] = {
    {NULL, MODULE_DEFAULT, "appspawn"},
    {NULL, MODULE_APPSPAWN, "appspawn/appspawn"},
    {NULL, MODULE_NWEBSPAWN, "appspawn/nwebspawn"},
    {NULL, MODULE_COMMON, "appspawn/common"},
};
static HOOK_MGR *g_appspawnHookMgr = NULL;

int AppSpawnModuleMgrInstall(const char *moduleName)
{
    if (moduleName == NULL) {
        return -1;
    }
    int type = MODULE_DEFAULT;
    if (g_moduleMgr[type].moduleMgr == NULL) {
        g_moduleMgr[type].moduleMgr = ModuleMgrCreate(g_moduleMgr[type].moduleName);
    }
    if (g_moduleMgr[type].moduleMgr == NULL) {
        return -1;
    }
#ifndef APPSPAWN_TEST
    return ModuleMgrInstall(g_moduleMgr[type].moduleMgr, moduleName, 0, NULL);
#else
    return 0;
#endif
}

void AppSpawnModuleMgrUnInstall(int type)
{
    if (type >= MODULE_MAX) {
        return;
    }
    if (g_moduleMgr[type].moduleMgr == NULL) {
        return;
    }
    ModuleMgrDestroy(g_moduleMgr[type].moduleMgr);
    g_moduleMgr[type].moduleMgr = NULL;
}

int AppSpawnLoadAutoRunModules(int type)
{
    if (type >= MODULE_MAX) {
        return -1;
    }
    if (g_moduleMgr[type].moduleMgr != NULL) {
        return 0;
    }
    APPSPAWN_LOGI("AppSpawnLoadAutoRunModules: %{public}d moduleName: %{public}s", type, g_moduleMgr[type].moduleName);
#ifndef APPSPAWN_TEST
    g_moduleMgr[type].moduleMgr = ModuleMgrScan(g_moduleMgr[type].moduleName);
    return g_moduleMgr[type].moduleMgr == NULL ? -1 : 0;
#else
    return 0;
#endif
}

HOOK_MGR *GetAppSpawnHookMgr(void)
{
    if (g_appspawnHookMgr != NULL) {
        return g_appspawnHookMgr;
    }
    g_appspawnHookMgr = HookMgrCreate("appspawn");
    return g_appspawnHookMgr;
}

void DeleteAppSpawnHookMgr(void)
{
    HookMgrDestroy(g_appspawnHookMgr);
    g_appspawnHookMgr = NULL;
}

static int PreloadHookRun(const HOOK_INFO *hookInfo, void *executionContext)
{
    AppSpawnHookArg *arg = (AppSpawnHookArg *)executionContext;
    PreloadHook realHook = (PreloadHook)hookInfo->hookCookie;
    return realHook((void *)arg->content);
}

static void PreHookExec(const HOOK_INFO *hookInfo, void *executionContext)
{
    AppSpawnHookArg *arg = (AppSpawnHookArg *)executionContext;
    AppSpawnMgr *spawnMgr = (AppSpawnMgr *)arg->content;
    clock_gettime(CLOCK_MONOTONIC, &spawnMgr->perLoadStart);
    APPSPAWN_LOGI("Hook stage: %{public}d prio: %{public}d start", hookInfo->stage, hookInfo->prio);
}

static void PostHookExec(const HOOK_INFO *hookInfo, void *executionContext, int executionRetVal)
{
    AppSpawnHookArg *arg = (AppSpawnHookArg *)executionContext;
    AppSpawnMgr *spawnMgr = (AppSpawnMgr *)arg->content;
    clock_gettime(CLOCK_MONOTONIC, &spawnMgr->perLoadEnd);
    uint64_t diff = DiffTime(&spawnMgr->perLoadStart, &spawnMgr->perLoadEnd);
    APPSPAWN_LOGI("Hook stage: %{public}d prio: %{public}d end time %{public}" PRId64 " ns result: %{public}d",
        hookInfo->stage, hookInfo->prio, diff, executionRetVal);
}

int PreloadHookExecute(AppSpawnContent *content)
{
    AppSpawnHookArg arg;
    arg.content = content;
    arg.client = NULL;
    HOOK_EXEC_OPTIONS options;
    options.flags = TRAVERSE_STOP_WHEN_ERROR;
    options.preHook = PreHookExec;
    options.postHook = PostHookExec;
    int ret = HookMgrExecute(GetAppSpawnHookMgr(), HOOK_PRELOAD, (void *)(&arg), &options);
    APPSPAWN_LOGI("Execute hook [%{public}d] result %{public}d", HOOK_PRELOAD, ret);
    return ret == ERR_NO_HOOK_STAGE ? 0 : ret;
}

int AddPreloadHook(int prio, PreloadHook hook)
{
    APPSPAWN_CHECK(hook != NULL, return APPSPAWN_ARG_INVALID, "Invalid hook");
    HOOK_INFO info;
    info.stage = HOOK_PRELOAD;
    info.prio = prio;
    info.hook = PreloadHookRun;
    info.hookCookie = (void *)hook;
    APPSPAWN_LOGI("AddPreloadHook prio: %{public}d", prio);
    return HookMgrAddEx(GetAppSpawnHookMgr(), &info);
}

static int AppSpawnHookRun(const HOOK_INFO *hookInfo, void *executionContext)
{
    AppSpawnForkArg *arg = (AppSpawnForkArg *)executionContext;
    AppSpawnHook realHook = (AppSpawnHook)hookInfo->hookCookie;
    return realHook((AppSpawnMgr *)arg->content, (AppSpawningCtx *)arg->client);
}

static void PreAppSpawnHookExec(const HOOK_INFO *hookInfo, void *executionContext)
{
    AppSpawnHookArg *arg = (AppSpawnHookArg *)executionContext;
    clock_gettime(CLOCK_MONOTONIC, &arg->tmStart);
    APPSPAWN_LOGI("Hook stage: %{public}d prio: %{public}d start", hookInfo->stage, hookInfo->prio);
}

static void PostAppSpawnHookExec(const HOOK_INFO *hookInfo, void *executionContext, int executionRetVal)
{
    AppSpawnHookArg *arg = (AppSpawnHookArg *)executionContext;
    clock_gettime(CLOCK_MONOTONIC, &arg->tmEnd);
    uint64_t diff = DiffTime(&arg->tmStart, &arg->tmEnd);
    APPSPAWN_LOGI("Hook stage: %{public}d prio: %{public}d end time %{public}" PRId64 " ns result: %{public}d",
        hookInfo->stage, hookInfo->prio, diff, executionRetVal);
}

int AppSpawnHookExecute(AppSpawnHookStage stage, uint32_t flags, AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGV("Execute hook [%{public}d] for app: %{public}s", stage, GetProcessName((AppSpawningCtx *)client));
    AppSpawnHookArg forkArg;
    forkArg.client = client;
    forkArg.content = content;
    HOOK_EXEC_OPTIONS options;
    options.flags = flags;  // TRAVERSE_STOP_WHEN_ERROR : 0;
    options.preHook = PreAppSpawnHookExec;
    options.postHook = PostAppSpawnHookExec;
    int ret = HookMgrExecute(GetAppSpawnHookMgr(), stage, (void *)(&forkArg), &options);
    return ret == ERR_NO_HOOK_STAGE ? 0 : ret;
}

int AppSpawnExecuteClearEnvHook(AppSpawnContent *content, AppSpawnClient *client)
{
    return AppSpawnHookExecute(HOOK_SPAWN_CLEAR_ENV, HOOK_STOP_WHEN_ERROR, content, client);
}

int AppSpawnExecuteSpawningHook(AppSpawnContent *content, AppSpawnClient *client)
{
    return AppSpawnHookExecute(HOOK_SPAWN_SET_CHILD_PROPERTY, HOOK_STOP_WHEN_ERROR, content, client);
}

int AppSpawnExecuteCompleteHook(AppSpawnContent *content, AppSpawnClient *client)
{
    return AppSpawnHookExecute(HOOK_SPAWN_COMPLETED, HOOK_STOP_WHEN_ERROR, content, client);
}

void AppSpawnEnvClear(AppSpawnContent *content, AppSpawnClient *client)
{
    (void)AppSpawnHookExecute(HOOK_SPAWN_POST, 0, content, client);
}

int AddAppSpawnHook(AppSpawnHookStage stage, int prio, AppSpawnHook hook)
{
    APPSPAWN_CHECK(hook != NULL, return APPSPAWN_ARG_INVALID, "Invalid hook");
    HOOK_INFO info;
    info.stage = stage;
    info.prio = prio;
    info.hook = AppSpawnHookRun;
    info.hookCookie = (void *)hook;
    APPSPAWN_LOGI("AddAppSpawnHook stage: %{public}d prio: %{public}d", stage, prio);
    return HookMgrAddEx(GetAppSpawnHookMgr(), &info);
}

int AppChangeHookExecute(AppSpawnHookStage stage, const AppSpawnContent *content, const AppSpawnedProcess *appInfo)
{
    AppSpawnAppArg arg;
    arg.appInfo = appInfo;
    arg.content = content;
    int ret = HookMgrExecute(GetAppSpawnHookMgr(), stage, (void *)(&arg), NULL);
    return ret == ERR_NO_HOOK_STAGE ? 0 : ret;
}

static int AppChangeHookRun(const HOOK_INFO *hookInfo, void *executionContext)
{
    AppSpawnAppArg *arg = (AppSpawnAppArg *)executionContext;
    ProcessChangeHook realHook = (ProcessChangeHook)hookInfo->hookCookie;
    return realHook((AppSpawnMgr *)arg->content, arg->appInfo);
}

int AddAppChangeHook(AppSpawnHookStage stage, int prio, ProcessChangeHook hook)
{
    APPSPAWN_CHECK(hook != NULL, return APPSPAWN_ARG_INVALID, "Invalid hook");
    HOOK_INFO info;
    info.stage = stage;
    info.prio = prio;
    info.hook = AppChangeHookRun;
    info.hookCookie = hook;
    return HookMgrAddEx(GetAppSpawnHookMgr(), &info);
}

void RegChildLooper(struct TagAppSpawnContent *content, ChildLoop loop)
{
    APPSPAWN_CHECK(content != NULL && loop != NULL, return, "Invalid content for RegChildLooper");
    content->runChildProcessor = loop;
}
