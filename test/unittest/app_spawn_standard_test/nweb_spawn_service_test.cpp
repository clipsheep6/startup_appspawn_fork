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

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "appspawn_modulemgr.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "parameter.h"
#include "sandbox_utils.h"
#include "securec.h"

#include "appspawn_client.h"
#include "app_spawn_test_helper.h"
#include "app_spawn_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using nlohmann::json;

namespace OHOS {
using AddTlvFunction = std::function<int(uint8_t *buffer, uint32_t bufferLen, uint32_t &realLen, uint32_t &tlvCount)>;
class NWebSpawnServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    AppSpawnTestHelper testHelper_;
};

void NWebSpawnServiceTest::SetUpTestCase()
{}

void NWebSpawnServiceTest::TearDownTestCase()
{}

void NWebSpawnServiceTest::SetUp()
{}

void NWebSpawnServiceTest::TearDown()
{}

/**
 * @brief 基本流程测试，启动nwebspawn 处理
 *
 */
HWTEST(NWebSpawnServiceTest, NWeb_Spawn_001, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode nwebspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("NWeb_Spawn_001 recv result %{public}d", ret);
        if (ret != 0 || result.pid == 0) {
            ret = -1;
            break;
        }
        // stop child and termination
        APPSPAWN_LOGI("NWeb_Spawn_001 Kill pid %{public}d ", result.pid);
        kill(result.pid, SIGKILL);

        usleep(2000); // wait，to get exit status
        // MSG_GET_RENDER_TERMINATION_STATUS
        ret = AppSpawnReqCreate(clientHandle, MSG_GET_RENDER_TERMINATION_STATUS, "com.ohos.dlpmanager", &reqHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create req %{public}s", NWEBSPAWN_SERVER_NAME);
        ret = AppSpawnReqSetTerminationPid(clientHandle, reqHandle, result.pid);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create req %{public}s", NWEBSPAWN_SERVER_NAME);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("Send MSG_GET_RENDER_TERMINATION_STATUS %{public}d", ret);
        ret = 0;
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_002, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode nwebspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        // 发送消息到nweb spawn
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("NWeb_Spawn_002 recv result %{public}d", ret);
        if (ret != 0 || result.pid == 0) {
            ret = -1;
            break;
        }
        // MSG_GET_RENDER_TERMINATION_STATUS
        reqHandle = testServer.CreateMsg(clientHandle, MSG_GET_RENDER_TERMINATION_STATUS, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("Send MSG_GET_RENDER_TERMINATION_STATUS %{public}d", ret);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_003, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode nwebspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_KEEPALIVE
        AppSpawnReqMgr *reqMgr = reinterpret_cast<AppSpawnReqMgr *>(clientHandle);
        APPSPAWN_CHECK(reqMgr != nullptr, ret = -1; break, "Invalid reqMgr");
        pthread_mutex_lock(&reqMgr->mutex);
        AddKeepMsgToSendQueue(reqMgr);
        pthread_cond_signal(&reqMgr->notifyMsg);
        pthread_mutex_unlock(&reqMgr->mutex);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_004, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode nwebspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_DUMP
        AppSpawnResult result = {};
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_DUMP, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("Send MSG_DUMP %{public}d", ret);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_005, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode nwebspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", NWEBSPAWN_SERVER_NAME);
        // MAX_TYPE_INVALID
        AppSpawnResult result = {};
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MAX_TYPE_INVALID, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("Send MAX_TYPE_INVALID %{public}d", ret);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_NE(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_Child_001, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", NWEBSPAWN_SERVER_NAME);
        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(NWEBSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        PreloadHookExecute(content);  // 预加载，解析sandbox

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);

        // spawn
        AppSpawnForkArg arg;
        arg.client = &property->client;
        arg.content = content;
        ret = CloneAppSpawn(reinterpret_cast<void *>(&arg));
        ASSERT_EQ(ret, 0);
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_Child_002, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", NWEBSPAWN_SERVER_NAME);
        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(NWEBSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        PreloadHookExecute(content);  // 预加载，解析sandbox

        ret = APPSPAWN_INVALID_ARG;
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ASANENABLED);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);

        // spawn
        AppSpawnForkArg arg;
        arg.client = &property->client;
        arg.content = content;
        ret = CloneAppSpawn(reinterpret_cast<void *>(&arg));
        ASSERT_EQ(ret, 0);
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}


HWTEST(NWebSpawnServiceTest, NWeb_Spawn_Child_004, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req");
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(NWEBSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        PreloadHookExecute(content);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        // spawn
        AppSpawnForkArg arg;
        arg.client = &property->client;
        arg.content = content;
        ret = CloneAppSpawn(reinterpret_cast<void *>(&arg));
        ASSERT_EQ(ret, 0);
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(NWebSpawnServiceTest, NWeb_Spawn_Child_005, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", NWEBSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and render
        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req");
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(NWEBSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);

        PreloadHookExecute(content);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        // spawn prepare process
        AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, content, &property->client);
        // spawn
        AppSpawnForkArg arg;
        arg.client = &property->client;
        arg.content = content;
        ret = CloneAppSpawn(reinterpret_cast<void *>(&arg));
        ASSERT_EQ(ret, 0);
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}
}  // namespace OHOS
