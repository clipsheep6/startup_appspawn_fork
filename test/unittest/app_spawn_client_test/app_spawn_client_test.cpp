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

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "parameter.h"
#include "sandbox_utils.h"
#include "securec.h"

#include "appspawn_client.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "app_spawn_test_helper.h"
#include "app_spawn_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

#define TEST_PID 100

class AppSpawnClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
public:
    AppSpawnTestHelper testHelper_;
};

/**
 * @brief 测试服务端报文不完整，关闭连接。客户端超时
 * 消息测试时，不能在中间执行assert，必须执行stop后执行assert检查，否则会导致消息异常
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Communication_001, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn", false);
    testServer.Start([](TestConnection *connection, const uint8_t *buffer, uint32_t buffLen)
        {
            LE_CloseStreamTask(LE_GetDefaultLoop(), connection->stream);
        });
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, APPSPAWN_TIMEOUT);
}

/**
 * @brief 测试收到报文后，消息错误，直接回复
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Communication_002, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn", false);
    testServer.Start([](TestConnection *connection, const uint8_t *buffer, uint32_t buffLen)
        {
            connection->SendResponse(
                reinterpret_cast<AppSpawnMsg *>(const_cast<uint8_t *>(buffer)), APPSPAWN_INVALID_MSG, 0);
        }, 3000); // 3000 3s
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);

        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, APPSPAWN_INVALID_MSG);
}

/**
 * @brief 测试收到keep消息，不回复，客户端超时
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Communication_003, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn", false);
    testServer.Start([](TestConnection *connection, const uint8_t *buffer, uint32_t buffLen)
        {
            AppSpawnMsg *msg = reinterpret_cast<AppSpawnMsg *>(const_cast<uint8_t *>(buffer));
            if (msg->msgType == MSG_APP_SPAWN) {
                connection->SendResponse(msg, 0, TEST_PID);
                return;
            }
        }, 5000); // 5000 timeout
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, ret = -1; break, "Failed to send msg");
        APPSPAWN_CHECK(result.pid == TEST_PID, ret = -1; break, "Failed to get pid");

        APPSPAWN_LOGV("AppSpawnClientTest send keep msg now ...");
        AppSpawnReqMgr *reqMgr = reinterpret_cast<AppSpawnReqMgr *>(clientHandle);
        APPSPAWN_CHECK(reqMgr != nullptr, ret = -1; break, "Invalid reqMgr");
        pthread_mutex_lock(&reqMgr->mutex);
        AddKeepMsgToSendQueue(reqMgr);
        pthread_cond_signal(&reqMgr->notifyMsg);
        pthread_mutex_unlock(&reqMgr->mutex);

        sleep(1); // 连接断开，等待后重新连接
        reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, ret = -1; break, "Failed to send msg");
        APPSPAWN_CHECK(result.pid == TEST_PID, ret = -1; break, "Failed to get pid");
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试收到keep消息，回复
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Communication_004, TestSize.Level0)
{
    OHOS::AppSpawnTestServer testServer("appspawn -mode appspawn", false);
    testServer.Start([](TestConnection *connection, const uint8_t *buffer, uint32_t buffLen)
        {
            AppSpawnMsg *msg = reinterpret_cast<AppSpawnMsg *>(const_cast<uint8_t *>(buffer));
            connection->SendResponse(msg, 0, TEST_PID); // TEST_PID
        }, 5000);  // 5000 timeout
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqHandle reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        AppSpawnResult result = {};
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, ret = -1; break, "Failed to send msg");
        APPSPAWN_CHECK(result.pid == TEST_PID, ret = -1; break, "Failed to get pid");

        APPSPAWN_LOGV("AppSpawnClientTest send keep msg now ...");
        AppSpawnReqMgr *reqMgr = reinterpret_cast<AppSpawnReqMgr *>(clientHandle);
        APPSPAWN_CHECK(reqMgr != nullptr, ret = -1; break, "Invalid reqMgr");
        pthread_mutex_lock(&reqMgr->mutex);
        AddKeepMsgToSendQueue(reqMgr);
        pthread_cond_signal(&reqMgr->notifyMsg);
        pthread_mutex_unlock(&reqMgr->mutex);

        sleep(1);
        reqHandle = testServer.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
        ret = AppSpawnClientSendMsg(clientHandle, reqHandle, &result);
        APPSPAWN_CHECK(ret == 0, ret = -1; break, "Failed to send msg");
        APPSPAWN_CHECK(result.pid == TEST_PID, ret = -1; break, "Failed to get pid");
    } while (0);
    testServer.Stop();
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试消息构建，msg flags
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_001, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        ret = AppSpawnReqCreate(clientHandle, MSG_APP_SPAWN, "com.ohos.dlpmanager", &reqHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // flags test
        const uint32_t testFlags[] = {10, 20, 31, 32, 34, MAX_FLAGS_INDEX };
        uint32_t max = sizeof(testFlags) / sizeof(testFlags[0]);
        for (size_t i = 0; i < max; i++) {
            ret = AppSpawnReqSetAppFlag(clientHandle, reqHandle, testFlags[i]);
            ASSERT_EQ(ret, 0);
        }
        ret = AppSpawnReqSetAppFlag(clientHandle, reqHandle, MAX_FLAGS_INDEX + 1);
        ASSERT_NE(ret, 0);

        ret = APPSPAWN_INVALID_ARG;
        AppSpawnReqNode *reqNode = GetReqNode(clientHandle, reqHandle, MSG_STATE_COLLECTION);
        APPSPAWN_CHECK(reqNode != nullptr, break, "Invalid reqNode");
        APPSPAWN_CHECK(reqNode->msgFlags != nullptr, break, "Invalid reqNode");
        uint32_t maxUnit = (MAX_FLAGS_INDEX % 32)  == 0 ? MAX_FLAGS_INDEX / 32 : MAX_FLAGS_INDEX / 32 + 1; // 32 bits
        APPSPAWN_CHECK(reqNode->msgFlags->count == maxUnit,
            break, "Invalid reqNode %{public}d", reqNode->msgFlags->count);

        for (size_t i = 0; i < max; i++) {
            uint32_t index = testFlags[i] / 32; // 32 bits
            uint32_t bits = 1 << testFlags[i] % 32; // 32 bits
            APPSPAWN_LOGV("AppSpawnClientTest index %{public}u bits 0x%{public}x", index, bits);
            uint32_t result = (reqNode->msgFlags->flags[index] & bits) == bits;
            ASSERT_EQ(result == 1, 1);
        }
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，dac 测试
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_002, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        void *tlvValue = GetAppProperty(property, TLV_DAC_INFO);
        AppDacInfo *info = static_cast<AppDacInfo *>(tlvValue);
        APPSPAWN_CHECK(info != nullptr, break, "Can not find dac info in msg");
        APPSPAWN_CHECK(info->uid == testHelper_.GetTestUid(), break, "Invalid uid %{public}d", info->uid);
        APPSPAWN_CHECK(info->gid == testHelper_.GetTestGid(), break, "Invalid gid %{public}d", info->gid);
        APPSPAWN_CHECK(info->gidCount == 2, break, "Invalid gidCount %{public}d", info->gidCount); // 2 default
        APPSPAWN_CHECK(info->gidTable[1] == testHelper_.GetTestGidGroup() + 1,
            break, "Invalid uid %{public}d", info->gidTable[1]);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，bundle name 测试
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_003, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        void *tlvValue = GetAppProperty(property, TLV_BUNDLE_INFO);
        AppSpawnMsgBundleInfo *info = static_cast<AppSpawnMsgBundleInfo *>(tlvValue);
        APPSPAWN_CHECK(info != nullptr, break, "Can not find dac info in msg");
        APPSPAWN_CHECK(info->bundleIndex == testHelper_.GetTestBundleIndex(),
            break, "Invalid bundleIndex %{public}d", info->bundleIndex);
        APPSPAWN_LOGV("info->bundleName %{public}s", info->bundleName);
        APPSPAWN_CHECK(strcmp(info->bundleName, testHelper_.GetDefaultTestAppBundleName()) == 0,
            break, "Invalid bundleName %{public}s", info->bundleName);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，render cmd
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_004, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // save render cmd to req
        AppRenderCmd info = {};
        (void)strcpy_s(info.renderCmd, sizeof(info.renderCmd), "test 222222222222222222222222222222222222222222222222 \
            222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 \
            333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333334456789");
        ret = AppSpawnReqSetAppRenderCmd(clientHandle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add render %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        void *tlvValue = GetAppProperty(property, TLV_RENDER_CMD);
        AppSpawnMsgRenderCmd *renderCmd = static_cast<AppSpawnMsgRenderCmd *>(tlvValue);
        APPSPAWN_CHECK(renderCmd != nullptr, break, "Can not find render cmd in msg");
        APPSPAWN_LOGV("info->bundleName %{public}s", renderCmd->renderCmd);
        APPSPAWN_CHECK(strcmp(renderCmd->renderCmd, info.renderCmd) == 0,
            break, "Invalid renderCmd %{public}s", info.renderCmd);
        ret = 0;
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试消息构建，ownerId cmd
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_005, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // save owner to req
        AppOwnerId info = {};
        (void)strcpy_s(info.ownerId, sizeof(info.ownerId), "test 222222222222222222222222222222222222222222222222 \
            222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 \
            333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333334456789");
        ret = AppSpawnReqSetAppOwnerId(clientHandle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add owner %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        void *tlvValue = GetAppProperty(property, TLV_OWNER_INFO);
        AppSpawnMsgOwnerId *owner = static_cast<AppSpawnMsgOwnerId *>(tlvValue);
        APPSPAWN_CHECK(owner != nullptr, break, "Can not find owner cmd in msg");
        APPSPAWN_LOGV("owner->ownerId %{public}s", owner->ownerId);
        APPSPAWN_CHECK(strcmp(owner->ownerId, info.ownerId) == 0,
            break, "Invalid ownerId %{public}s", info.ownerId);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，internet permission
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_006, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppInternetPermissionInfo info = {};
        info.setAllowInternet = 101; // 101 test
        info.allowInternet = 102; // 102 test
        ret = AppSpawnReqSetAppInternetPermissionInfo(clientHandle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add owner %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        void *tlvValue = GetAppProperty(property, TLV_INTERNET_INFO);
        AppInternetPermissionInfo *interInfo = static_cast<AppInternetPermissionInfo *>(tlvValue);
        APPSPAWN_CHECK(interInfo != nullptr, break, "Can not find interInfo in msg");
        APPSPAWN_CHECK(info.setAllowInternet == interInfo->setAllowInternet,
            break, "Invalid setAllowInternet %{public}d", info.setAllowInternet);
        APPSPAWN_CHECK(info.allowInternet == interInfo->allowInternet,
            break, "Invalid allowInternet %{public}d", info.allowInternet);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，domain info
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_007, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppDomainInfo info = {};
        info.hapFlags = 1; // 1 test
        (void)strcpy_s(info.apl, sizeof(info.apl), "system_core");
        ret = AppSpawnReqSetAppDomainInfo(clientHandle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add domain %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        void *tlvValue = GetAppProperty(property, TLV_DOMAIN_INFO);
        AppSpawnMsgDomainInfo *domainInfo = static_cast<AppSpawnMsgDomainInfo *>(tlvValue);
        APPSPAWN_CHECK(domainInfo != nullptr, break, "Can not find owner cmd in msg");
        APPSPAWN_CHECK(info.hapFlags == domainInfo->hapFlags,
            break, "Invalid hapFlags %{public}d", info.hapFlags);
        APPSPAWN_CHECK(strcmp(domainInfo->apl, info.apl) == 0, break, "Invalid apl %{public}s", domainInfo->apl);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 测试消息构建，测试扩展tlv
 *
 */
HWTEST(AppSpawnClientTest, App_Client_Msg_008, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    const char *tlvName = "tlv-name-2";
    const uint32_t testDataLen = 7416; // 7300
    AppProperty *property = nullptr;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        std::vector<char> testData(testDataLen, '1');
        testData.push_back('1');
        testData.push_back('2');
        testData.push_back('3');
        testData.push_back('4');
        testData.push_back('5');
        testData.push_back('6');
        testData.push_back('7');
        testData.push_back('8');
        testData.push_back('9');
        testData.push_back('\0');
        ret = AppSpawnReqAddExtInfo(clientHandle, reqHandle, tlvName,
            reinterpret_cast<uint8_t *>(const_cast<char *>(testData.data())), testData.size());
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", APPSPAWN_SERVER_NAME);

        AppSpawnMsgAccessToken token = {1234, 12345678}; // 1234, 12345678
        ret = AppSpawnReqSetAppAccessToken(clientHandle, reqHandle, &token);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add access token %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        uint32_t tlvLen = 0;
        uint8_t *tlvValue = GetAppPropertyEx(property, tlvName, &tlvLen);
        APPSPAWN_CHECK(tlvValue != nullptr, break, "Can not find tlv in msg");
        APPSPAWN_CHECK(tlvLen == testData.size(), break, "Invalid tlv len %{public}u", tlvLen);
        APPSPAWN_CHECK(strcmp(reinterpret_cast<char *>(tlvValue), testData.data()) == 0,
            break, "Invalid ext tlv %{public}s ", reinterpret_cast<char *>(tlvValue + testDataLen));
        ret = 0;
    } while (0);
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnClientTest, App_Client_Msg_009, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, ret = -1;
            break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppDomainInfo info = {};
        info.hapFlags = 1; // 1 test
        (void)strcpy_s(info.apl, sizeof(info.apl), "system_core");
        ret = AppSpawnReqSetAppDomainInfo(clientHandle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add domain %{public}s", APPSPAWN_SERVER_NAME);
    } while (0);
    ASSERT_EQ(ret, 0);
    AppSpawnReqDestroy(clientHandle, reqHandle);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnClientTest, App_Client_Msg_010, TestSize.Level0)
{
    int ret = 0;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    const char *bundleName = "com.ohos.medialibrary.medialibrarydata";
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, ret = -1;
            break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        AppDacInfo dacInfo = {};
        dacInfo.uid = 20010029; // 20010029 test data
        dacInfo.gid = 20010029; // 20010029 test data
        dacInfo.gidCount = 2;
        dacInfo.gidTable[0] = 20010029; // 20010029 test data
        dacInfo.gidTable[1] = 20010029 + 1; // 20010029 test data
        (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
        ret = AppSpawnReqSetAppDacInfo(clientHandle, reqHandle, &dacInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add dac %{public}s", APPSPAWN_SERVER_NAME);
    } while (0);
    ASSERT_EQ(ret, 0);
    AppSpawnReqDestroy(clientHandle, reqHandle);
    AppSpawnClientDestroy(clientHandle);
}