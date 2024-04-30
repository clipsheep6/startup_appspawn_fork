/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "appspawn_hook.h"
#include "appspawn_manager.h"
#include "appspawn_utils.h"

static int g_execHookResult[STAGE_MAX] = {0};

void TestSetExecHookResult(AppSpawnHookStage stage, int result)
{
    g_execHookResult[stage] = result;
}

void TestRestoreExecHookResult(AppSpawnHookStage stage)
{
    g_execHookResult[stage] = 0;
}

static int TestPluginReportProcessExit(const AppSpawnMgr *content, const AppSpawnedProcess *appInfo)
{
    APPSPAWN_LOGI("Process %{public}s exit", appInfo->name);
    return g_execHookResult[STAGE_SERVER_APP_DIED];
}

static int TestPluginReportProcessAdd(const AppSpawnMgr *content, const AppSpawnedProcess *appInfo)
{
    APPSPAWN_LOGI("Process %{public}s add", appInfo->name);
    return g_execHookResult[STAGE_SERVER_APP_ADD];
}

static int TestPluginPreload(AppSpawnMgr *content)
{
    APPSPAWN_LOGI("TestPlugin preload");
    return g_execHookResult[STAGE_SERVER_PRELOAD];
}

static int TestPluginExit(AppSpawnMgr *content)
{
    APPSPAWN_LOGI("TestPlugin exit");
    return g_execHookResult[STAGE_SERVER_EXIT];
}

static int TestPluginPreFork(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin pre fork for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_PARENT_PRE_FORK];
}

static int TestPluginPostFork(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin post fork for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_PARENT_POST_FORK];
}

static int TestPluginPreReply(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin pre reply to client for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_PARENT_PRE_RELY];
}

static int TestPluginPostReply(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin post reply to client for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_PARENT_POST_RELY];
}

static int ChildPreColdBoot(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin pre cold boot for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_CHILD_PRE_COLDBOOT];
}
static int ChildExecute(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin set app property for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_CHILD_EXECUTE];
}
static int ChildPreRely(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin pre reply to parent for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_CHILD_PRE_RELY];
}
static int ChildPostRely(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin post reply to parent for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_CHILD_POST_RELY];
}
static int ChildPreRun(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGI("TestPlugin pre child run for %{public}s ", GetProcessName(property));
    return g_execHookResult[STAGE_CHILD_PRE_RUN];
}

MODULE_CONSTRUCTOR(void)
{
    APPSPAWN_LOGI("Load test plugin module ...");
    AddProcessMgrHook(STAGE_SERVER_APP_DIED, 0, TestPluginReportProcessExit);
    AddProcessMgrHook(STAGE_SERVER_APP_ADD, 0, TestPluginReportProcessAdd);
    AddServerStageHook(STAGE_SERVER_EXIT, 0, TestPluginExit);
    AddPreloadHook(HOOK_PRIO_LOWEST - 1, TestPluginPreload);
    AddAppSpawnHook(STAGE_PARENT_PRE_FORK, HOOK_PRIO_COMMON - 1, TestPluginPreFork);
    AddAppSpawnHook(STAGE_PARENT_POST_FORK, HOOK_PRIO_COMMON - 1, TestPluginPostFork);
    AddAppSpawnHook(STAGE_PARENT_POST_RELY, HOOK_PRIO_COMMON - 1, TestPluginPostReply);
    AddAppSpawnHook(STAGE_PARENT_PRE_RELY, HOOK_PRIO_COMMON - 1, TestPluginPreReply);
    AddAppSpawnHook(STAGE_CHILD_PRE_COLDBOOT, HOOK_PRIO_COMMON - 1, ChildPreColdBoot);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_HIGHEST - 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_COMMON - 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_SANDBOX - 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_SANDBOX + 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_PROPERTY - 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_EXECUTE, HOOK_PRIO_PROPERTY + 1, ChildExecute);
    AddAppSpawnHook(STAGE_CHILD_PRE_RELY, HOOK_PRIO_COMMON - 1, ChildPreRely);
    AddAppSpawnHook(STAGE_CHILD_POST_RELY, HOOK_PRIO_COMMON - 1, ChildPostRely);
    AddAppSpawnHook(STAGE_CHILD_PRE_RUN, HOOK_PRIO_COMMON - 1, ChildPreRun);
}
