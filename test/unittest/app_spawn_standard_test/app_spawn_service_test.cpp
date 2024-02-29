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

#include "app_spawn_test_helper.h"
#include "app_spawn_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using nlohmann::json;

namespace OHOS {
class AppSpawnServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    AppSpawnTestHelper testHelper_;
};

void AppSpawnServiceTest::SetUpTestCase()
{}

void AppSpawnServiceTest::TearDownTestCase()
{}

void AppSpawnServiceTest::SetUp()
{}

void AppSpawnServiceTest::TearDown()
{}

HWTEST(AppSpawnServiceTest, App_Spawn_001, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);

        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, break, "Failed to send msg %{public}d", ret);
        if (ret == 0 && result.pid > 0) {
            APPSPAWN_LOGI("App_Spawn_Msg_001 Kill pid %{public}d ", result.pid);
            kill(result.pid, SIGKILL);
        }
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_002, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("APP_Spawn_001 recv result %{public}d", ret);
        if (ret != 0 || result.pid == 0) {
            ret = -1;
            break;
        }
        // stop child and termination
        APPSPAWN_LOGI("APP_Spawn_001 Kill pid %{public}d ", result.pid);
        kill(result.pid, SIGKILL);
        // MSG_GET_RENDER_TERMINATION_STATUS
        reqHandle = testServer.CreateMsg(clientHandle, MSG_GET_RENDER_TERMINATION_STATUS, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_LOGV("Send MSG_GET_RENDER_TERMINATION_STATUS %{public}d", ret);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_003, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_DUMP, 0);

        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, break, "Failed to send msg %{public}d", ret);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_004, TestSize.Level0)
{
    OHOS::AppSpawnTestServer *testServer = new OHOS::AppSpawnTestServer("appspawn -mode appspawn");
    testServer->Start(nullptr);
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create client %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer->CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        // kill nwebspawn
        APPSPAWN_LOGV("App_Spawn_004 Kill nwebspawn");
        usleep(20000);
        testServer->KillNWebSpawnServer();
        usleep(20000);
    } while (0);
    testServer->Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
    delete testServer;
}

HWTEST(AppSpawnServiceTest, App_Spawn_Msg_002, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    // 没有tlv的消息，返回错误
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        std::vector<uint8_t> buffer(sizeof(AppSpawnResponseMsg));
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer.data(), msgLen);
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // recv
        APPSPAWN_LOGV("Start recv ... ");
        len = read(socketId, buffer.data(), buffer.size());
        APPSPAWN_CHECK(len >= static_cast<int>(sizeof(AppSpawnResponseMsg)), ret = -1;
            break, "Failed to recv msg %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnResponseMsg *respMsg = reinterpret_cast<AppSpawnResponseMsg *>(buffer.data());
        APPSPAWN_LOGV("Recv msg %{public}s result: %{public}d", respMsg->msgHdr.processName, respMsg->result.result);
        ret = respMsg->result.result;
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_NE(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_Msg_003, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        // 消息不完整，断开连接
        std::vector<uint8_t> buffer(sizeof(AppSpawnResponseMsg));
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer.data(), msgLen - 10);  // 10
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // recv timeout
        len = read(socketId, buffer.data(), buffer.size());
        APPSPAWN_CHECK(len == 0, ret = -1; break, "Failed to recv msg len: %{public}d", len);
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_Msg_004, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        // 测试异常tlv
        std::vector<uint8_t> buffer(sizeof(AppSpawnResponseMsg));
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer.data(), msgLen);
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // recv
        len = read(socketId, buffer.data(), buffer.size());
        APPSPAWN_CHECK(len >= static_cast<int>(sizeof(AppSpawnResponseMsg)), ret = -1;
            break, "Failed to recv msg %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnResponseMsg *respMsg = reinterpret_cast<AppSpawnResponseMsg *>(buffer.data());
        APPSPAWN_LOGV("Recv msg %{public}s result: %{public}d", respMsg->msgHdr.processName, respMsg->result.result);
        ret = respMsg->result.result;
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_NE(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_Msg_005, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        // 测试小包发送
        std::vector<uint8_t> buffer(1024, 0);  // 1024 1k
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        // 分片发送
        uint32_t sendStep = OHOS::AppSpawnTestHelper::GenRandom() % 70; // 70 一次发送的字节数
        sendStep = (sendStep < 20) ? 33 : sendStep; // 20 33 一次发送的字节数
        APPSPAWN_LOGV("App_Spawn_Msg_005 msgLen %{public}u sendStep: %{public}u", msgLen, sendStep);
        uint32_t currIndex = 0;
        int len = 0;
        do {
            if ((currIndex + sendStep) > msgLen) {
                break;
            }
            len = write(socketId, buffer.data() + currIndex, sendStep);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
            usleep(2000); // wait recv
            currIndex += sendStep;
        } while (1);
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        if (msgLen > currIndex) {
            len = write(socketId, buffer.data() + currIndex, msgLen - currIndex);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        }

        // recv
        len = read(socketId, buffer.data(), buffer.size());
        APPSPAWN_CHECK(len >= static_cast<int>(sizeof(AppSpawnResponseMsg)), ret = -1;
            break, "Failed to recv msg %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnResponseMsg *respMsg = reinterpret_cast<AppSpawnResponseMsg *>(buffer.data());
        APPSPAWN_LOGV("Recv msg %{public}s result: %{public}d", respMsg->msgHdr.processName, respMsg->result.result);
        ret = respMsg->result.result;
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_Msg_006, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        // 测试2个消息一起发送
        std::vector<uint8_t> buffer1(1024);  // 1024
        std::vector<uint8_t> buffer2(1024);  // 1024
        uint32_t msgLen1 = 0;
        uint32_t msgLen2 = 0;
        ret = testServer.CreateSendMsg(buffer1, MSG_APP_SPAWN, msgLen1, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());
        ret = testServer.CreateSendMsg(buffer2, MSG_APP_SPAWN, msgLen2, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer1.data(), msgLen1);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        len = write(socketId, buffer2.data(), msgLen2);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // recv
        len = read(socketId, buffer1.data(), buffer1.size());
        APPSPAWN_CHECK(len >= static_cast<int>(sizeof(AppSpawnResponseMsg)), ret = -1;
            break, "Failed to recv msg %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnResponseMsg *respMsg = reinterpret_cast<AppSpawnResponseMsg *>(buffer1.data());
        APPSPAWN_LOGV("Recv msg %{public}s result: %{public}d", respMsg->msgHdr.processName, respMsg->result.result);
        ret = respMsg->result.result;
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试dump
 *
 */
HWTEST(AppSpawnServiceTest, App_Spawn_Msg_007, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);

        std::vector<uint8_t> buffer1(1024);  // 1024
        std::vector<uint8_t> buffer2(1024);  // 1024
        uint32_t msgLen1 = 0;
        uint32_t msgLen2 = 0;
        ret = testServer.CreateSendMsg(buffer1, MSG_APP_SPAWN, msgLen1, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());
        ret = testServer.CreateSendMsg(buffer2, MSG_DUMP, msgLen2, {});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer1.data(), msgLen1);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        len = write(socketId, buffer2.data(), msgLen2);
            APPSPAWN_CHECK(len > 0, break,
                "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // recv
        len = read(socketId, buffer1.data(), buffer1.size());
        APPSPAWN_CHECK(len >= static_cast<int>(sizeof(AppSpawnResponseMsg)), ret = -1;
            break, "Failed to recv msg %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnResponseMsg *respMsg = reinterpret_cast<AppSpawnResponseMsg *>(buffer1.data());
        APPSPAWN_LOGV("Recv msg %{public}s result: %{public}d", respMsg->msgHdr.processName, respMsg->result.result);
        ret = respMsg->result.result;
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试连接中断
 *
 */
HWTEST(AppSpawnServiceTest, App_Spawn_Msg_008, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);
        std::vector<uint8_t> buffer(1024, 0);  // 1024 1k
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());

        int len = write(socketId, buffer.data(), msgLen);
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        // close socket
        APPSPAWN_LOGV("CloseClientSocket");
        CloseClientSocket(socketId);
        socketId = -1;
        usleep(20000);
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 发送不完整报文，等待超时
 *
 */
HWTEST(AppSpawnServiceTest, App_Spawn_Msg_009, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn");
    testServer.Start(nullptr);
    int ret = 0;
    int socketId = -1;
    do {
        socketId = testServer.CreateSocket();
        APPSPAWN_CHECK(socketId >= 0, break, "Failed to create socket %{public}s", APPSPAWN_SERVER_NAME);
        std::vector<uint8_t> buffer(1024, 0);  // 1024 1k
        uint32_t msgLen = 0;
        ret = testServer.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {AppSpawnTestHelper::AddBaseTlv});
        APPSPAWN_CHECK(ret == 0, break,
            "Failed to create msg %{public}s", testServer.GetDefaultTestAppBundleName());
        int len = write(socketId, buffer.data(), msgLen - 20); // 20 test
        APPSPAWN_CHECK(len > 0, break,
            "Failed to send msg %{public}s", testServer.GetDefaultTestAppBundleName());
        usleep(500000); // 500000 need to wait server timeout
        // recv
        len = read(socketId, buffer.data(), buffer.size());
        APPSPAWN_CHECK(len == 0, ret = -1; break, "Can not receive timeout ");
    } while (0);
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    testServer.Stop();
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnServiceTest, App_Spawn_Child_001, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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

HWTEST(AppSpawnServiceTest, App_Spawn_Child_002, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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

HWTEST(AppSpawnServiceTest, App_Spawn_Child_003, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);

        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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

HWTEST(AppSpawnServiceTest, App_Spawn_Child_004, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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

HWTEST(AppSpawnServiceTest, App_Spawn_Child_005, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and render
        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_GWP_ENABLED_NORMAL);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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

HWTEST(AppSpawnServiceTest, App_Spawn_Child_006, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnContent *content = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        // MSG_SPAWN_NATIVE_PROCESS and no render cmd
        testHelper_.SetTestUid(10010029); // 10010029
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_DEBUGGABLE);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_NATIVEDEBUG);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_BUNDLE_RESOURCES);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_ACCESS_BUNDLE_DIR);

        char path[PATH_MAX] = {};
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
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
