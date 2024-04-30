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
#include <cstdbool>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_adapter.h"
#include "appspawn_manager.h"
#include "appspawn_modulemgr.h"
#include "appspawn_permission.h"
#include "appspawn_sandbox.h"
#include "appspawn_server.h"
#include "appspawn_utils.h"
#include "cJSON.h"
#include "json_utils.h"
#include "nlohmann/json.hpp"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

using nlohmann::json;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
static AppSpawnTestHelper g_testHelper;
class AppSpawnSandboxExpandTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        StubNode *stub = GetStubNode(STUB_MOUNT);
        if (stub) {
            stub->flags &= ~STUB_NEED_CHECK;
        }
    }
    void SetUp() {}
    void TearDown() {}
};

/**
 * @brief 测试Variable 变量替换 <currentUserId> <PackageName_index>
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_001, TestSize.Level0)
{
    AddDefaultVariable();
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *real = "/data/app/el2/100/log/com.example.myapplication_100";
    const char *value = GetSandboxRealVar(context, 0,
        "/data/app/el2/<currentUserId>/log/<PackageName_index>", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    APPSPAWN_LOGV("real %{public}s", real);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试变量<lib>
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_002, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<lib>/module", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
#ifdef APPSPAWN_64
    ASSERT_EQ(strcmp(value, "/system/lib64/module") == 0, 1);
#else
    ASSERT_EQ(strcmp(value, "/system/lib/module") == 0, 1);
#endif
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试系统参数变量<param:test.variable.001>
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_003, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *real = "/system/test.variable.001/test001";
    const char *value = GetSandboxRealVar(context, 0, "/system/<param:test.variable.001>/test001", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

static int TestVariableReplace(const SandboxContext *context,
    const char *buffer, uint32_t bufferLen, uint32_t *realLen, const VarExtraData *extraData)
{
    int len = sprintf_s((char *)buffer, bufferLen, "%s", "Test-value-001.Test-value-002.Test-value-003.Test-value-004");
    APPSPAWN_CHECK(len > 0 && ((uint32_t)len < bufferLen),
        return -1, "Failed to format path app: %{public}s", context->bundleName);
    *realLen = (uint32_t)len;
    return 0;
}

/**
 * @brief 测试注册变量，和替换
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_004, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    AddVariableReplaceHandler("<Test-Var-001>", TestVariableReplace);

    const char *real = "/system/Test-value-001.Test-value-002.Test-value-003.Test-value-004/test001";
    const char *value = GetSandboxRealVar(context, 0, "/system/<Test-Var-001>/test001", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试dep-path 变量替换
 *
 */
static VarExtraData *TestGetVarExtraData(const SandboxContext *context, uint32_t sandboxTag,
    const PathMountNode *depNode)
{
    static VarExtraData extraData;
    (void)memset_s(&extraData, sizeof(extraData), 0, sizeof(extraData));
    extraData.sandboxTag = sandboxTag;
    if (sandboxTag == SANDBOX_TAG_NAME_GROUP) {
        extraData.data.depNode = (PathMountNode *)depNode;
    }
    return &extraData;
}

static inline void TestSetMountPathOperation(uint32_t *operation, uint32_t index)
{
    *operation |= (1 << index);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_005, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    PathMountNode pathNode;
    pathNode.source = const_cast<char *>("/data/app/el2/<currentUserId>/base");
    pathNode.target = const_cast<char *>("/data/storage/el2");
    pathNode.category = MOUNT_TMP_SHRED;
    VarExtraData *extraData = TestGetVarExtraData(context, SANDBOX_TAG_NAME_GROUP, &pathNode);
    const char *real = "/data/storage/el2/base";
    TestSetMountPathOperation(&extraData->operation, MOUNT_PATH_OP_REPLACE_BY_SANDBOX);
    const char *value = GetSandboxRealVar(context, 0, "<deps-path>/base", nullptr, extraData);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试dep-path 变量替换
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_006, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    PathMountNode pathNode;
    pathNode.source = const_cast<char *>("/data/app/el2/<currentUserId>/base");
    pathNode.target = const_cast<char *>("/data/storage/el2");
    pathNode.category = MOUNT_TMP_SHRED;
    VarExtraData *extraData = TestGetVarExtraData(context, SANDBOX_TAG_NAME_GROUP, &pathNode);
    const char *real = "/data/app/el2/100/base/base";
    const char *value = GetSandboxRealVar(context, 0, "<deps-path>/base", nullptr, extraData);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试dep-src-path 变量替换
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_007, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    PathMountNode pathNode;
    pathNode.source = const_cast<char *>("/data/app/el2/<currentUserId>/base");
    pathNode.target = const_cast<char *>("/data/storage/el2");
    pathNode.category = MOUNT_TMP_SHRED;
    VarExtraData *extraData = TestGetVarExtraData(context, SANDBOX_TAG_NAME_GROUP, &pathNode);
    const char *real = "/data/app/el2/100/base/base";
    const char *value = GetSandboxRealVar(context, 0, "<deps-src-path>/base", nullptr, extraData);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试dep-sandbox-path 变量替换
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_008, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    PathMountNode pathNode;
    pathNode.source = const_cast<char *>("/data/app/el2/<currentUserId>/base");
    pathNode.target = const_cast<char *>("/data/storage/el2");
    pathNode.category = MOUNT_TMP_SHRED;
    VarExtraData *extraData = TestGetVarExtraData(context, SANDBOX_TAG_NAME_GROUP, &pathNode);
    const char *real = "/data/storage/el2/base";
    const char *value = GetSandboxRealVar(context, 0, "<deps-sandbox-path>/base", nullptr, extraData);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

/**
 * @brief 测试不存在的变量替换
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Variable_009, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *real = "<deps-test-path>/base";
    const char *value = GetSandboxRealVar(context, 0, "<deps-test-path>/base", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, real) == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Permission_01, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);
        sandbox->extData.dumpNode(&sandbox->extData);

        AppSpawnTestHelper testHelper;
        const std::vector<const char *> &permissions = testHelper.GetPermissions();
        for (auto permission : permissions) {
            const SandboxPermissionNode *node = GetPermissionNodeInQueue(&sandbox->permissionQueue, permission);
            APPSPAWN_CHECK(node != nullptr && strcmp(node->section.name, permission) == 0,
                break, "Failed to permission %{public}s", permission);
            const SandboxPermissionNode *node2 =
                GetPermissionNodeInQueueByIndex(&sandbox->permissionQueue, node->permissionIndex);
            APPSPAWN_CHECK(node2 != nullptr && strcmp(node->section.name, node2->section.name) == 0,
                break, "Failed to permission %{public}s", permission);
        }
        const char *permission = "ohos.permission.XXXXX";
        const SandboxPermissionNode *node = GetPermissionNodeInQueue(&sandbox->permissionQueue, permission);
        APPSPAWN_CHECK_ONLY_EXPER(node == nullptr, break);
        node = GetPermissionNodeInQueue(nullptr, permission);
        APPSPAWN_CHECK_ONLY_EXPER(node == nullptr, break);
        ret = 0;
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

static int ProcessTestExpandConfig(const SandboxContext *context,
    const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)GetAppSpawnMsgExtInfo(context->message, name, &size);
    if (size == 0 || extInfo == NULL) {
        return 0;
    }
    return 0;
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_ExpandCfg_01, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);
        // add default
        AddDefaultExpandAppSandboxConfigHandle();
        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // add expand info to msg
        const char hspListStr[] = "[{ \
                \"bundle-name\" : \"test.bundle1\", \
                \"module-name\" : \"module1\",  \
                \"version\" : \"v10001\"  \
            }, { \
                \"bundle-name\" : \"test.bundle2\",\
                \"module-name\" : \"module2\",\
                \"version\" : \"v10002\"\
            }]";
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "HspList", hspListStr);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", hspListStr);

        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_ExpandCfg_02, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);

        // add default
        AddDefaultExpandAppSandboxConfigHandle();
        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // add expand info to msg
        const char dataGroupInfoListStr[] = "[{ \
            \"data-group-id\":\"1234abcd5678efgh\", \
            \"data-dir\":\"/data/app/el2/100/group/091a68a9-2cc9-4279-8849-28631b598975\", \
            \"data-gid\":\"20100001\", \
            \"data-uuid\" : \"091a68a9-2cc9-4279-8849-28631b598975\" \
        }, { \
            \"data-group-id\":\"abcduiop1234\", \
            \"data-dir\":\"/data/app/el2/100/group/ce876162-fe69-45d3-aa8e-411a047af564\", \
            \"data-gid\":\"20100002\", \
            \"data-uuid\" : \"ce876162-fe69-45d3-aa8e-411a047af564\" \
        }]";
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "DataGroup", dataGroupInfoListStr);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", dataGroupInfoListStr);

        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_ExpandCfg_03, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);

        // add default
        AddDefaultVariable();
        AddDefaultExpandAppSandboxConfigHandle();

        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_OVERLAY);
        // add expand info to msg
        const char *overlayInfo = "[{ \
            \"overlay-path\" : \"/data/app/el1/bundle/public/com.ohos.demo001/feature.hsp\" \
        }, { \
            \"overlay-path\" : \"/data/app/el1/bundle/public/com.ohos.demo001/feature.hsp\" \
        }, { \
            \"overlay-path\" : \"/data/app/el1/bundle/public/com.ohos.demo003/feature.hsp\" \
        }]";
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "Overlay", overlayInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", overlayInfo);

        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_ExpandCfg_04, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);

        // add test
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        ret = RegisterExpandSandboxCfgHandler("test-cfg", EXPAND_CFG_HANDLER_PRIO_START, ProcessTestExpandConfig);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ret = RegisterExpandSandboxCfgHandler("test-cfg", EXPAND_CFG_HANDLER_PRIO_START, ProcessTestExpandConfig);
        APPSPAWN_CHECK_ONLY_EXPER(ret == APPSPAWN_NODE_EXIST, break);

        // create msg
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // add expand info to msg
        const char *testInfo = "\"app-base\":[{ \
            \"sandbox-root\" : \"/mnt/sandbox/<currentUserId>/<PackageName>\", \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/config\", \
                \"sandbox-path\" : \"/config\", \
                \"sandbox-flags\" : [ \"bind\", \"rec\" ], \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"sandbox-flags-customized\": [ \"MS_NODEV\", \"MS_RDONLY\" ], \
                \"dac-override-sensitive\": \"true\", \
                \"mount-shared-flag\" : \"true\", \
                \"app-apl-name\" : \"system\", \
                \"fs-type\": \"sharefs\", \
                \"options\": \"support_overwrite=1\" \
            }], \
            \"symbol-links\" : [] \
        }]";

        ret = AppSpawnReqMsgAddExtInfo(reqHandle, "test-cfg",
            reinterpret_cast<uint8_t *>(const_cast<char *>(testInfo)), strlen(testInfo) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", testInfo);

        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 测试app extension
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_001, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // set APP_FLAGS_ISOLATED_SANDBOX
        ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ISOLATED_SANDBOX);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_002, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // set APP_FLAGS_ISOLATED_SANDBOX
        ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ISOLATED_SANDBOX);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        sandbox->sandboxNsFlags = CLONE_NEWPID;  // only pid
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_003, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        // set APP_FLAGS_ISOLATED_SANDBOX
        ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_ISOLATED_SANDBOX);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        const char dataGroupInfoListStr[] = "[{ \
            \"data-group-id\":\"1234abcd5678efgh\", \
            \"data-dir\":\"/data/app/el2/100/group/091a68a9-2cc9-4279-8849-28631b598975\", \
            \"data-gid\":\"20100001\", \
            \"data-uuid\" : \"091a68a9-2cc9-4279-8849-28631b598975\" \
        }, { \
            \"data-group-id\":\"abcduiop1234\", \
            \"data-dir\":\"/data/app/el2/100/group/ce876162-fe69-45d3-aa8e-411a047af564\", \
            \"data-gid\":\"20100002\", \
            \"data-uuid\" : \"ce876162-fe69-45d3-aa8e-411a047af564\" \
        }]";
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "DataGroup", dataGroupInfoListStr);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", dataGroupInfoListStr);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_004, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);
    ASSERT_EQ(strcmp(value, "/system/com.example.myapplication/module") == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_005, TestSize.Level0)
{
    AppSpawningCtx *spawningCtx = TestCreateAppSpawningCtx();
    ASSERT_EQ(spawningCtx != nullptr, 1);
    int ret = SetAppSpawnMsgFlag(spawningCtx->message, TLV_MSG_FLAGS, APP_FLAGS_CLONE_ENABLE);
    ASSERT_EQ(ret, 0);
    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);  // clone/packageName/bundleIndex
    ASSERT_EQ(strcmp(value, "/system/clone/com.example.myapplication/100/module") == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_006, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    ASSERT_EQ(reqHandle != nullptr, 1);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_EXTENSION, "test001");
    ASSERT_EQ(ret, 0);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_EXTENSION_SANDBOX);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *spawningCtx = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(spawningCtx != nullptr, 1);

    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);  // extension/packageName/<extensionType>
    ASSERT_EQ(strcmp(value, "/system/extension/com.example.myapplication/test001/module") == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_007, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    ASSERT_EQ(reqHandle != nullptr, 1);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_EXTENSION, "test001");
    ASSERT_EQ(ret, 0);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_EXTENSION_SANDBOX);
    ASSERT_EQ(ret, 0);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_CLONE_ENABLE);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *spawningCtx = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(spawningCtx != nullptr, 1);

    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    APPSPAWN_LOGV("value %{public}s", value);
    ASSERT_EQ(value != nullptr, 1);  // clone/extension/packageName/bundleIndex/<extensionType>
    ASSERT_EQ(strcmp(value, "/system/clone/extension/com.example.myapplication/100/test001/module") == 0, 1);
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_008, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    ASSERT_EQ(reqHandle != nullptr, 1);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_EXTENSION_SANDBOX);
    ASSERT_EQ(ret, 0);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_CLONE_ENABLE);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *spawningCtx = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(spawningCtx != nullptr, 1);

    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    ASSERT_EQ(value == nullptr, 1);

    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_009, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    ASSERT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    ASSERT_EQ(reqHandle != nullptr, 1);
    ret = AppSpawnReqMsgSetAppFlag(reqHandle, APP_FLAGS_EXTENSION_SANDBOX);
    ASSERT_EQ(ret, 0);
    AppSpawningCtx *spawningCtx = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    ASSERT_EQ(spawningCtx != nullptr, 1);

    SandboxContext *context = TestGetSandboxContext(spawningCtx, 0);
    ASSERT_EQ(context != nullptr, 1);

    const char *value = GetSandboxRealVar(context, 0, "/system/<VariablePackageName>/module", nullptr, nullptr);
    ASSERT_EQ(value == nullptr, 1);

    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(spawningCtx);
    AppSpawnClientDestroy(clientHandle);
}

/**
 * @brief 没有APP_FLAGS_ISOLATED_SANDBOX， 有CLONE_NEWNET
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Sandbox_AppExtension_010, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqMsgHandle reqHandle = 0;
    AppSpawningCtx *property = nullptr;
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_ARG_INVALID;
        property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        sandbox->sandboxNsFlags = CLONE_NEWNET;
        ret = MountSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    DeleteAppSpawningCtx(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

/**
 * @brief env 扩展的构建和处理
 *
 */
static std::string DumpAppEnvToJson(const std::map<std::string, std::string> &appEnv)
{
    nlohmann::json appEnvJson;
    for (const auto &[envName, envValue] : appEnv) {
        appEnvJson[envName] = envValue;
    }
    APPSPAWN_LOGV("appEnvJson %{public}s", appEnvJson.dump().c_str());
    return appEnvJson.dump();
}

/**
 * @brief 从ams构建消息开始到处理的全流程
 *
 */
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Expand_EnvInfo_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);

    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    EXPECT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);

    std::map<std::string, std::string> appEnv;
    appEnv.insert({"test-001", "001"});
    appEnv.insert({"test-002", "002"});
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_APP_ENV, DumpAppEnvToJson(appEnv).c_str());
    EXPECT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    EXPECT_EQ(property != nullptr, 1);

    ret = SetEnvInfo(mgr, property);
    EXPECT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

static std::string DumpHspListToJson(const char *name, const char *module, uint32_t version)
{
    nlohmann::json hspListJson;
    for (int i = 0; i < 5; i++) { // 5 test
        nlohmann::json node;
        node["bundle-name"] = name;
        node["module-name"] = module + std::to_string(i);
        node["version"] = "v" + std::to_string(version + i);
        hspListJson.emplace_back(node);
    }
    APPSPAWN_LOGV("hspListJson %{public}s", hspListJson.dump().c_str());
    return hspListJson.dump();
}
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Expand_Hsp_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    ASSERT_EQ(ret, 0);

    AppSpawnClientHandle clientHandle = nullptr;
    ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    EXPECT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_HSP_LIST,
        DumpHspListToJson("com.example.myapplication", "module-test-00", 100).c_str()); // 100 test
    EXPECT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    EXPECT_EQ(property != nullptr, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el1/bundle/public/com.example.myapplication/v101/module-test-001";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el2/group/com.example.myapplication/module-test-001";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    SandboxContext *context = TestGetSandboxContext(property, 0);
    ASSERT_EQ(context != nullptr, 1);
    ret = ProcessExpandAppSandboxConfig(context, sandbox, MSG_EXT_NAME_HSP_LIST);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    DeleteSandboxContext(context);
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

static std::string DumpDataGroupInfoListToJson(const char *dataGroupId, uint32_t userId, uint32_t gid, const char *uuid)
{
    const std::string JSON_DATA_APP = "/data/app/el2/";
    const std::string JSON_GROUP = "/group/";

    nlohmann::json dataGroupInfoListJson;
    for (uint32_t i = 0; i < 5; i++) { // 5 test
        nlohmann::json node;
        std::string dir = JSON_DATA_APP + std::to_string(userId + i) + JSON_GROUP + uuid;
        node["data-group-id"] = dataGroupId;
        node["data-gid"] = std::to_string(gid);
        node["data-dir"] = dir;
        node["data-uuid"] = uuid;
        dataGroupInfoListJson.emplace_back(node);
    }
    APPSPAWN_LOGV("dataGroupInfoListJson %{public}s", dataGroupInfoListJson.dump().c_str());
    return dataGroupInfoListJson.dump();
}
HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Expand_DataGroup_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    ASSERT_EQ(ret, 0);

    AppSpawnClientHandle clientHandle = nullptr;
    ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    EXPECT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_DATA_GROUP,
        DumpDataGroupInfoListToJson("www.wwww", 1001, 1001, "xxxx.xxxx.xxxx.xxxx").c_str());
    EXPECT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    EXPECT_EQ(property != nullptr, 1);

    // set check point
    MountArg args = {};
    // JSON_DATA_APP + std::to_string(userId + i) + JSON_GROUP + uuid;
    args.originPath = "/data/app/el2/1001/group/xxxx.xxxx.xxxx.xxxx";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el2/group/xxxx.xxxx.xxxx.xxxx";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    SandboxContext *context = TestGetSandboxContext(property, 0);
    ASSERT_EQ(context != nullptr, 1);
    ret = ProcessExpandAppSandboxConfig(context, sandbox, MSG_EXT_NAME_DATA_GROUP);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    DeleteSandboxContext(context);
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}

static std::string DumpOverlayInfoToJson(const std::string &overlayInfo)
{
    nlohmann::json overlayJson;
    std::string::size_type pos;
    std::string str = overlayInfo;
    str += "|";
    size_t size = str.size();
    for (unsigned int i = 0; i < size; i++) {
        pos = str.find("|", i);
        if (pos < size) {
            nlohmann::json node;
            std::string s = str.substr(i, pos - i);
            node["overlay-path"] = s;
            i = pos;
            overlayJson.emplace_back(node);
        }
    }
    APPSPAWN_LOGV("overlayInfo %{public}s", overlayJson.dump().c_str());
    return overlayJson.dump();
}

HWTEST(AppSpawnSandboxExpandTest, App_Spawn_Expand_Overlay_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    ASSERT_EQ(ret, 0);

    AppSpawnClientHandle clientHandle = nullptr;
    ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);
    AppSpawnReqMsgHandle reqHandle = g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    EXPECT_EQ(reqHandle != INVALID_REQ_HANDLE, 1);
    std::string overlayInfo = "/data/app/el1/bundle/public/com.ohos.demo001/feature.hsp| "
            "/data/app/el1/bundle/public/com.ohos.demo002/feature.hsp";
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_OVERLAY, DumpOverlayInfoToJson(overlayInfo).c_str());
    EXPECT_EQ(ret, 0);
    AppSpawningCtx *property = g_testHelper.GetAppProperty(clientHandle, reqHandle);
    EXPECT_EQ(property != nullptr, 1);

    // set check point
    MountArg args = {};
    // /data/app/el1/bundle/public/com.ohos.demo001/feature.hsp;
    args.originPath = "/data/app/el1/bundle/public/com.ohos.demo001";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/overlay/feature.hsp";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SHARED;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    SandboxContext *context = TestGetSandboxContext(property, 0);
    ASSERT_EQ(context != nullptr, 1);
    ret = ProcessExpandAppSandboxConfig(context, sandbox, MSG_EXT_NAME_OVERLAY);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    DeleteSandboxContext(context);
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
    AppSpawnClientDestroy(clientHandle);
}
}  // namespace OHOS
