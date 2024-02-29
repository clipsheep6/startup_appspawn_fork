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
#include <memory>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "appspawn_modulemgr.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "parameter.h"
#include "sandbox_utils.h"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using nlohmann::json;

namespace OHOS {
static AppSpawnTestHelper g_testHelper;
class AppSpawnColdRunTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * 接管启动的exec 过程
 *
 */
static int ExecvAbortStub(const char *pathName, char *const argv[])
{
    if (!(strcmp(pathName, "/system/bin/appspawn") == 0 || strcmp(pathName, "/system/asan/bin/appspawn") == 0)) {
        return 0;
    }
    APPSPAWN_LOGV("ExecvAbortStub pathName: %{public}s ", pathName);
    _exit(0x7f);
    return 0;
}

static int ExecvLocalProcessStub(const char *pathName, char *const argv[])
{
    if (!(strcmp(pathName, "/system/bin/appspawn") == 0 || strcmp(pathName, "/system/asan/bin/appspawn") == 0)) {
        return 0;
    }
    APPSPAWN_LOGV("ExecvLocalProcessStub pathName: %{public}s ", pathName);
    return 0;
}

static int ExecvTimeoutStub(const char *pathName, char *const argv[])
{
    if (!(strcmp(pathName, "/system/bin/appspawn") == 0 || strcmp(pathName, "/system/asan/bin/appspawn") == 0)) {
        return 0;
    }
    APPSPAWN_LOGV("ExecvLocalProcessStub pathName: %{public}s ", pathName);
    usleep(500000);  // 500000 500ms
    return 0;
}

static int HandleExecvStub(const char *pathName, char *const argv[])
{
    if (!(strcmp(pathName, "/system/bin/appspawn") == 0 || strcmp(pathName, "/system/asan/bin/appspawn") == 0)) {
        return 0;
    }
    std::string arg;
    int index = 0;
    do {
        arg += argv[index];
        arg += " ";
        index++;
    } while (argv[index] != nullptr);
    APPSPAWN_LOGV("HandleExecvStub arg: %{public}s ", arg.c_str());

    CmdArgs *args = AppSpawnTestHelper::ToCmdList(arg.c_str());
    APPSPAWN_CHECK(args != nullptr, return -1, "Failed to alloc args");
    AppSpawnContent *content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
    if (content == nullptr) {
        free(args);
        return -1;
    }
    content->runAppSpawn(content, args->argc, args->argv);
    free(args);
    // exit delete content
    AppSpawnDestroyContent(content);
    APPSPAWN_LOGV("HandleExecvStub %{public}s exit", pathName);
    return 0;
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_001, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    StubNode *node = GetStubNode(STUB_EXECV);
    ASSERT_NE(node != nullptr, 0);
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = -1;
        node->flags |= STUB_NEED_CHECK;
        node->arg = reinterpret_cast<void *>(HandleExecvStub);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        if (ret == 0 && result.pid > 0) {
            APPSPAWN_LOGI("App_Spawn_Cold_Run_001 Kill pid %{public}d ", result.pid);
            kill(result.pid, SIGKILL);
        }
        ret = 0;
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_002, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    StubNode *node = GetStubNode(STUB_EXECV);
    ASSERT_NE(node != nullptr, 0);
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        AppSpawnReqMsgHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = -1;
        node->flags |= STUB_NEED_CHECK;
        node->arg = reinterpret_cast<void *>(HandleExecvStub);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        if (ret == 0 && result.pid > 0) {
            APPSPAWN_LOGI("App_Spawn_Cold_Run_002 Kill pid %{public}d ", result.pid);
            kill(result.pid, SIGKILL);
        }
        ret = 0;
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    node->flags &= ~STUB_NEED_CHECK;
    ASSERT_EQ(ret, 0);
}

static CmdArgs *GetColdRunArgs(const AppSpawningCtx *property, const char *arg)
{
    std::string argStr = arg;
    char *param = Base64Encode(property->receiver->buffer, property->receiver->msgRecvLen - sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(param != nullptr, return nullptr, "Failed to encode msg");
    char *header = Base64Encode(reinterpret_cast<uint8_t *>(&property->receiver->msgHeader), sizeof(AppSpawnMsg));
    if (header != nullptr) {
        argStr += param;
        argStr += "  -fd -1 0  ";
        argStr += header;
        free(header);
    } else {
        free(param);
        return nullptr;
    }
    free(param);
    return AppSpawnTestHelper::ToCmdList(argStr.c_str());
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_003, TestSize.Level0)
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

        ret = APPSPAWN_INVALID_ARG;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string arg = "appspawn -mode app_cold -param ";
        args = GetColdRunArgs(property, arg.c_str());
        APPSPAWN_CHECK(args != nullptr, break, "Failed to alloc args");
        content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        AppSpawnHookExecute(HOOK_SPAWN_FIRST, 0, content, &property->client);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_004, TestSize.Level0)
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

        ret = APPSPAWN_INVALID_ARG;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string arg = "appspawn -mode nweb_cold -param ";
        args = GetColdRunArgs(property, arg.c_str());
        APPSPAWN_CHECK(args != nullptr, break, "Failed to alloc args");
        content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_NWEB_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        AppSpawnHookExecute(HOOK_SPAWN_FIRST, 0, content, &property->client);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_005, TestSize.Level0)
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

        ret = APPSPAWN_INVALID_ARG;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string arg = "appspawn -mode app_cold -param ";
        args = GetColdRunArgs(property, arg.c_str());
        APPSPAWN_CHECK(args != nullptr, break, "Failed to alloc args");
        content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        AppSpawnHookExecute(HOOK_SPAWN_FIRST, 0, content, &property->client);
        content->runAppSpawn(content, args->argc, args->argv);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_006, TestSize.Level0)
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

        ret = APPSPAWN_INVALID_ARG;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string arg = "appspawn -mode app_cold -param ";
        args = GetColdRunArgs(property, arg.c_str());
        APPSPAWN_CHECK(args != nullptr, break, "Failed to alloc args");
        content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ASSERT_EQ(content->mode, MODE_FOR_APP_COLD_RUN);
        // add property to content
        OH_ListAddTail(&(reinterpret_cast<AppSpawnMgr *>(content))->processMgr.appSpawnQueue, &property->node);
        DumpApSpawn(reinterpret_cast<AppSpawnMgr *>(content));
        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        AppSpawnHookExecute(HOOK_SPAWN_FIRST, 0, content, &property->client);
        content->runAppSpawn(content, args->argc, args->argv);
        property = nullptr;
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试冷启动子进程中执行的 coldStartApp
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_007, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnContent *content = nullptr;
    CmdArgs *args = nullptr;
    StubNode *node = GetStubNode(STUB_EXECV);
    ASSERT_NE(node != nullptr, 0);
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

        ret = APPSPAWN_INVALID_ARG;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        std::string arg = "appspawn -mode nwebspawn";
        args = AppSpawnTestHelper::ToCmdList(arg.c_str());
        APPSPAWN_CHECK(args != nullptr, break, "Failed to alloc args");
        content = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        ret = -1;
        node->flags |= STUB_NEED_CHECK;
        node->arg = reinterpret_cast<void *>(ExecvLocalProcessStub);
        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        content->coldStartApp(content, &property->client);
        ret = 0;
    } while (0);
    if (args) {
        free(args);
    }
    node->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试子进程abort
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_008, TestSize.Level0)
{
    // child abort
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    StubNode *node = GetStubNode(STUB_EXECV);
    ASSERT_NE(node != nullptr, 0);
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = -1;
        node->flags |= STUB_NEED_CHECK;
        node->arg = reinterpret_cast<void *>(ExecvAbortStub);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGI("AppSpawnClientSendMsg result %{public}d ", ret);
        if (ret == 0 && result.pid > 0) {
            APPSPAWN_LOGI("Kill pid %{public}d ", result.pid);
            kill(result.pid, SIGKILL);
        }
        ret = 0;
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    node->flags &= ~STUB_NEED_CHECK;
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试子进程不回复，导致等到超时
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Cold_Run_009, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    StubNode *node = GetStubNode(STUB_EXECV);
    ASSERT_NE(node != nullptr, 0);
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        // set cold start flags
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_COLD_BOOT);

        ret = -1;
        node->flags |= STUB_NEED_CHECK;
        node->arg = reinterpret_cast<void *>(ExecvTimeoutStub);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGI("AppSpawnClientSendMsg result %{public}d ", ret);
        if (ret == 0 && result.pid > 0) {
            APPSPAWN_LOGI("Kill pid %{public}d ", result.pid);
            kill(result.pid, SIGKILL);
        }
        ret = 0;
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    node->flags &= ~STUB_NEED_CHECK;
    ASSERT_EQ(ret, 0);
}

static int TestBase64(const char *data)
{
    uint32_t outLen = 0;
    uint32_t inLen = strlen(data);
    char *encodeData = nullptr;
    uint8_t *result = nullptr;
    int ret = -1;
    do {
        encodeData = Base64Encode(reinterpret_cast<const uint8_t *>(data), inLen);
        APPSPAWN_CHECK(encodeData != nullptr, break, "Failed encode %{public}s", data);
        result = Base64Decode(encodeData, strlen(encodeData), &outLen);
        APPSPAWN_CHECK(result != nullptr, break, "Failed decode %{public}s", data);
        APPSPAWN_CHECK(outLen == inLen, break, "Failed len %{public}s %{public}d %{public}d", data, outLen, inLen);
        APPSPAWN_CHECK(memcmp(reinterpret_cast<char *>(result), data, outLen) == 0,
            break, "result %{public}s %{public}s", data, result);
        ret = 0;
    } while (0);
    if (encodeData) {
        free(encodeData);
    }
    if (result) {
        free(result);
    }
    return ret;
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_001, TestSize.Level0)
{
    const char *data = "a";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_002, TestSize.Level0)
{
    const char *data = "ab";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_003, TestSize.Level0)
{
    const char *data = "abc";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_004, TestSize.Level0)
{
    const char *data = "abcd";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_005, TestSize.Level0)
{
    const char *data = "abcde";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_006, TestSize.Level0)
{
    const char *data = "abcdedf";
    int ret = TestBase64(data);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_007, TestSize.Level0)
{
    const char *data = "abcdedf";
    uint32_t outLen = 0;
    uint8_t *result = Base64Decode(data, strlen(data), &outLen);
    ASSERT_EQ(result == nullptr, 1);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_008, TestSize.Level0)
{
    const char *data = "abcdedf";
    uint32_t outLen = 0;
    uint8_t *result = Base64Decode(data, strlen(data) + 1, &outLen);
    ASSERT_EQ(result == nullptr, 1);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_009, TestSize.Level0)
{
    const char *data = "abcdedf{";
    uint32_t outLen = 0;
    uint8_t *result = Base64Decode(data, strlen(data), &outLen);
    ASSERT_EQ(result == nullptr, 1);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_010, TestSize.Level0)
{
    const char *data = "*abcdedf{";
    uint32_t outLen = 0;
    uint8_t *result = Base64Decode(data, strlen(data), &outLen);
    ASSERT_EQ(result == nullptr, 1);
}

/**
 * @brief 测试base64
 *
 */
HWTEST(AppSpawnColdRunTest, App_Spawn_Base64_011, TestSize.Level0)
{
    const char *data = "a.bcdedf";
    uint32_t outLen = 0;
    uint8_t *result = Base64Decode(data, strlen(data), &outLen);
    ASSERT_EQ(result == nullptr, 1);
    SetDumpFlags(0);
}
}  // namespace OHOS
