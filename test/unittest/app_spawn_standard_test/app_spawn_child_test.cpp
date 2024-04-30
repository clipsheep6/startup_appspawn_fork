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
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "appspawn_modulemgr.h"
#include "appspawn_server.h"
#include "appspawn_manager.h"
#include "json_utils.h"
#include "parameter.h"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
static AppSpawnTestHelper g_testHelper;
class AppSpawnChildTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static int TestRunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGV("TestRunChildProcessor %{public}u", client->id);
    AppSpawnEnvClear(content, client);
    usleep(1000); // 1000 1ms
    return 0;
}

static AppSpawnContent *CreateTestAppSpawnContent(const char *name, uint32_t mode)
{
    static char path[PATH_MAX] = {};
    AppSpawnContent *content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APP_SPAWN);
    APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, return nullptr);

    ServerStageHookExecute(STAGE_SERVER_PRELOAD, content);  // 预加载，解析sandbox
    AddAppSpawnHook(STAGE_CHILD_PRE_RUN, HOOK_PRIO_LOWEST, AppSpawnClearEnv); // clear
    return content;
}

/**
 * @brief 测试appspanw spawn的后半部分，子进程的处理
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_001, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);

        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试appspanw spawn的后半部分，子进程的处理
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_002, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_003, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);

        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_004, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_005, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and render
        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        ASSERT_EQ(ret, 0);
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_006, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        const char *appEnv = "{\"test.name1\": \"test.value1\", \"test.name2\": \"test.value2\"}";
        ret = AppSpawnReqMsgAddExtInfo(reqHandle, "AppEnv",
            reinterpret_cast<uint8_t *>(const_cast<char *>(appEnv)), strlen(appEnv) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add ext tlv %{public}s", appEnv);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        ASSERT_EQ(ret, 0);
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试冷启动，exec之前部分
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_007, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);
        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        ASSERT_EQ(ret, 0);
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试子进程执行失败
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_008, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        TestSetExecHookResult(STAGE_CHILD_PRE_COLDBOOT, APPSPAWN_TLV_NONE);

        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    TestRestoreExecHookResult(STAGE_CHILD_PRE_COLDBOOT);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_009, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        TestSetExecHookResult(STAGE_CHILD_EXECUTE, APPSPAWN_SANDBOX_MOUNT_FAIL);

        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    TestRestoreExecHookResult(STAGE_CHILD_EXECUTE);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_010, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        TestSetExecHookResult(STAGE_CHILD_PRE_RELY, APPSPAWN_TLV_NONE);

        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    TestRestoreExecHookResult(STAGE_CHILD_PRE_RELY);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 冷启动转普通启动
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_011, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);
        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        content->coldStartApp = nullptr;
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        ASSERT_EQ(ret, 0);
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 没有 runChildProcessor
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_012, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        reqHandle = nullptr;
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        content = CreateTestAppSpawnContent(APPSPAWN_SOCKET_NAME, MODE_FOR_APP_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        content->runChildProcessor = nullptr;
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        ASSERT_EQ(ret, 0);
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnReqMsgFree(reqHandle);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 子进程nweb后半部分处理
 *
 */
HWTEST(AppSpawnChildTest, NWeb_Spawn_Child_001, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req ");

        content = CreateTestAppSpawnContent(NWEBSPAWN_SOCKET_NAME, MODE_FOR_NWEB_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);

        // spawn
        property->client.flags &= ~APP_COLD_START;
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        content = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, NWeb_Spawn_Child_002, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req");

        content = CreateTestAppSpawnContent(NWEBSPAWN_SOCKET_NAME, MODE_FOR_NWEB_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);

        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        content = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, NWeb_Spawn_Child_004, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req");
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        content = CreateTestAppSpawnContent(NWEBSPAWN_SOCKET_NAME, MODE_FOR_NWEB_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        property->client.flags = 0;
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        // spawn
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        content = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, NWeb_Spawn_Child_005, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and render
        g_testHelper.SetTestUid(10010029);  // 10010029
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req");
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        content = CreateTestAppSpawnContent(NWEBSPAWN_SOCKET_NAME, MODE_FOR_NWEB_SPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);

        // spawn
        property->client.flags &= ~APP_COLD_START;
        ret = AppSpawnChild(nullptr, &property->client);
        ASSERT_NE(ret, 0);
        ret = AppSpawnChild(content, nullptr);
        ASSERT_NE(ret, 0);
        ret = AppSpawnChild(content, &property->client);
        property = nullptr;
        content = nullptr;
    } while (0);
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

static std::string GetColdRunArgs(AppSpawningCtx *property, bool isNweb, const char *arg)
{
    std::string argStr = arg;
    int ret = WriteMsgToChild(property, isNweb);
    APPSPAWN_CHECK(ret == 0, return nullptr,
        "Failed to get shm for %{public}s errno %{public}d", GetProcessName(property), errno);

    char path[PATH_MAX] = {};
    int len = sprintf_s(path, sizeof(path), APPSPAWN_MSG_DIR "/%s_%d", GetProcessName(property), property->client.id);
    APPSPAWN_CHECK(len > 0, return argStr, "Failed to format path %{public}s", GetProcessName(property));
    int mode = O_CREAT | O_RDWR | O_TRUNC;
    int fd = open(path, mode, S_IRWXU);
    APPSPAWN_CHECK(fd >= 0, return argStr, "Failed to open errno %{public}d path %{public}s", errno, path);

    argStr += "  -fd ";
    argStr += std::to_string(fd);
    argStr += " 4 ";
    argStr += std::to_string(property->forkCtx.msgSize);
    argStr += "  -param ";
    argStr += GetProcessName(property);
    argStr += "  ";
    argStr += std::to_string(property->client.id);
    return argStr;
}

/**
 * @brief 测试冷启动后半部处理
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_001, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string cmd = GetColdRunArgs(property, false, "appspawn -mode app_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_002, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req ");
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string cmd = GetColdRunArgs(property, true, "appspawn -mode nweb_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_NWEB_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_003, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // asan set cold
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ASANENABLED);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_FORCE);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string cmd = GetColdRunArgs(property, false, "appspawn -mode app_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_004, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // asan set cold
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ASANENABLED);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string cmd = GetColdRunArgs(property, false, "appspawn -mode app_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 构建失败的参数，冷启动运行失败
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_005, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // 构建失败的参数，冷启动运行失败
        std::string cmd = "appspawn -mode app_cold ";
        cmd += "  -fd -1 4  ";
        cmd += std::to_string(1024); // 1024 msg size
        cmd += "  -param ";
        cmd += GetProcessName(property);
        cmd += "  ";
        cmd += std::to_string(property->client.id);
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 修改消息错误，冷启动启动失败
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_006, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // 修改消息错误，冷启动启动失败
        property->message->msgHeader.magic = 0;
        std::string cmd = GetColdRunArgs(property, false, "appspawn -mode app_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 沙盒执行失败
 *
 */
HWTEST(AppSpawnChildTest, App_Spawn_Child_Cold_Run_007, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    int ret = -1;
    do {
        TestSetExecHookResult(STAGE_CHILD_EXECUTE, APPSPAWN_SANDBOX_MOUNT_FAIL);

        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // asan set cold
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ASANENABLED);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string cmd = GetColdRunArgs(property, false, "appspawn -mode app_cold ");
        content = AppSpawnTestHelper::StartSpawnServer(cmd, args);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, content, &property->client);
        AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, content, &property->client);
        // run in cold mode
        // child run in TestRunChildProcessor
        RegChildLooper(content, TestRunChildProcessor);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(GetAppSpawnMgr());
    AppSpawnClientDestroy(clientHandle);
    TestRestoreExecHookResult(STAGE_CHILD_EXECUTE);
    ASSERT_EQ(ret, 0);
}
}  // namespace OHOS
