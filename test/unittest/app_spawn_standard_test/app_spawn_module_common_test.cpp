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

#include "appspawn_adapter.h"
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
class AppSpawnModuleCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST(AppSpawnModuleCommonTest, AccessToken_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    // no tlv in property
    ret = SetAppAccessToken(mgr, property);
    ASSERT_NE(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, AccessToken_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppAccessToken(reqHandle, 12345678);  // 12345678
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetAppAccessToken(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, AccessToken_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppAccessToken(reqHandle, 12345678);  // 12345678
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetAppAccessToken(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SelinuxCon_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    // no tlv in property
    ret = SetSelinuxCon(mgr, property);
    ASSERT_NE(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SelinuxCon_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    // no tlv in property
    ret = SetSelinuxCon(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SelinuxCon_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    // no tlv in property
    ret = SetSelinuxCon(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SelinuxCon_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);
    property->client.flags = 0;

    // no tlv in property
    ret = SetSelinuxCon(mgr, property);
    ASSERT_EQ(ret, APPSPAWN_NATIVE_NOT_SUPPORT);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SelinuxCon_005, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);
    property->client.flags = APP_DEVELOPER_MODE;

    // no tlv in property
    ret = SetSelinuxCon(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SeccompPolicy_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetUidGidFilter(mgr);
    ASSERT_EQ(ret, 0);
    ret = SetSeccompFilter(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SeccompPolicy_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetUidGidFilter(mgr);
    ASSERT_EQ(ret, 0);
    ret = SetSeccompFilter(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, SeccompPolicy_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
    ASSERT_EQ(ret, 0);

    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    SetSeccompPolicyResult(false);
    ret = SetUidGidFilter(mgr);
    ASSERT_NE(ret, 0);
    ret = SetSeccompFilter(mgr, property);
    ASSERT_NE(ret, 0);

    SetSeccompPolicyResult(true);
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, InternetPermission_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetInternetPermission(property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, InternetPermission_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgSetAppInternetPermissionInfo(reqHandle, 0, 1);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetInternetPermission(property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, EnvInfo_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetEnvInfo(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, EnvInfo_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_ENV, "{}");
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetEnvInfo(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, EnvInfo_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // 错误的json
    const std::string env = "{[ \
        { \"name\" : \"test-001\", \"value\" : \"test-value-001\" }, \
        { \"name\" : \"test-002\", \"value\" : \"test-value-002\" } \
    ]}";
    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_ENV, env.c_str());
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetEnvInfo(mgr, property);
    ASSERT_NE(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, EnvInfo_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    const std::string env = "{\"tsanEnabled\":\"0\"} ";
    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_ENV, env.c_str());
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = SetEnvInfo(mgr, property);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, PID_NS_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    mgr->content.sandboxNsFlags = 0;
    ret = PreLoadEnablePidNs(mgr);
    ASSERT_EQ(ret, 0);
    ret = PreLoadEnablePidNs(nullptr);
    ASSERT_NE(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, PID_NS_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    mgr->content.sandboxNsFlags = 0;
    pid_t pid = GetPidByName("appspawn");
    ASSERT_NE(pid, 0);
    pid = GetPidByName(nullptr);
    ASSERT_EQ(pid, -1);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, PID_NS_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    mgr->content.sandboxNsFlags = CLONE_NEWPID;
    ret = PreLoadEnablePidNs(mgr);
    ASSERT_EQ(ret, 0);

    mgr->content.sandboxNsFlags = 0;
    ret = AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);
    ret = AppSpawnHookExecute(STAGE_PARENT_POST_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, PID_NS_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    mgr->content.sandboxNsFlags = CLONE_NEWPID;
    ret = PreLoadEnablePidNs(mgr);
    ASSERT_EQ(ret, 0);

    ret = AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);
    ret = AppSpawnHookExecute(STAGE_PARENT_POST_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    SetDeveloperMode(false);
    ret = AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);
    SetDeveloperMode(true);
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = AppSpawnHookExecute(STAGE_CHILD_PRE_COLDBOOT, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = INVALID_REQ_HANDLE;
    ret = AppSpawnReqMsgCreate(MSG_APP_SPAWN, "test.com", &reqHandle);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    // no dac info in msg
    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = INVALID_REQ_HANDLE;
    ret = AppSpawnReqMsgCreate(MSG_APP_SPAWN, "test.com", &reqHandle);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppDacInfo dacInfo = {};
    dacInfo.uid = 0;       // 20010029 test
    dacInfo.gid = 20010029;       // 20010029 test
    dacInfo.gidCount = 2;  // 2 count
    dacInfo.gidTable[0] = 20010029;       // 20010029 test
    dacInfo.gidTable[1] = 20010029;       // 20010029 test
    (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
    ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_005, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = INVALID_REQ_HANDLE;
    ret = AppSpawnReqMsgCreate(MSG_APP_SPAWN, "test.com", &reqHandle);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppDacInfo dacInfo = {};
    dacInfo.uid = 1000001;       // 1000001 test
    dacInfo.gid = 1000001;       // 1000001 test
    dacInfo.gidCount = 2;  // 2 count
    dacInfo.gidTable[0] = 1000001;       // 1000001 test
    dacInfo.gidTable[1] = 1000001;       // 1000001 test
    (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
    ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnModuleCommonTest, Common_006, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    ASSERT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = INVALID_REQ_HANDLE;
    ret = AppSpawnReqMsgCreate(MSG_APP_SPAWN, "test.com", &reqHandle);
    ASSERT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    // not set sandbox
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_NO_SANDBOX);
    AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_DEBUGGABLE);
    AppDacInfo dacInfo = {};
    dacInfo.uid = 1000001;       // 1000001 test
    dacInfo.gid = 1000001;       // 1000001 test
    dacInfo.gidCount = 2;  // 2 count
    dacInfo.gidTable[0] = 1000001;       // 1000001 test
    dacInfo.gidTable[1] = 1000001;       // 1000001 test
    (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
    ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(property != nullptr, 1);

    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}
}  // namespace OHOS
