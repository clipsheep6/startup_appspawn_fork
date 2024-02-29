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
#include <memory>
#include <string>
#include <gtest/gtest.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_sandbox.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "nlohmann/json.hpp"
#include "sandbox_utils.h"

#include "app_spawn_test_helper.h"
#include "appspawn_mount_permission.h"
#include "app_spawn_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppSpawn;
using nlohmann::json;

namespace OHOS {
static const std::string g_commonConfig = "{ \
    \"common\":[{ \
        \"top-sandbox-switch\": \"ON\", \
        \"app-base\":[{ \
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
        }] \
    }], \
    \"individual\": [] \
}";

static const std::string g_individualConfig = "{ \
    \"individual\":[{ \
        \"__internal__.com.ohos.render\" : [{ \
            \"sandbox-root\" : \"/mnt/sandbox/com.ohos.render/<PackageName>\", \
            \"sandbox-switch\": \"ON\", \
            \"sandbox-shared\" : \"true\", \
            \"sandbox-ns-flags\" : [ \"pid\", \"net\" ], \
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
            \"symbol-links\" : [{ \
                    \"target-name\" : \"/system/etc\", \
                    \"link-name\" : \"/etc\", \
                    \"check-action-status\": \"false\", \
                    \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \" \
                } \
            ] \
        }], \
        \"com.ohos.dlpmanager\" : [{ \
            \"sandbox-switch\": \"ON\", \
            \"sandbox-shared\" : \"true\", \
            \"mount-paths\" : [{ \
                    \"src-path\" : \"/mnt/data/<currentUserId>\", \
                    \"sandbox-path\" : \"/mnt/data\", \
                    \"sandbox-flags\" : [\"bind\", \"rec\" ], \
                    \"mount-shared-flag\" : \"true\", \
                    \"check-action-status\": \"true\" \
                }, { \
                    \"src-path\" : \"/dev/fuse\", \
                    \"sandbox-path\" : \"/mnt/data/fuse\", \
                    \"sandbox-flags\" : [\"MS_NOSUID\", \"MS_NODEV\", \"MS_NOEXEC\", \"MS_NOATIME\", \"MS_LAZYTIME\" ],\
                    \"fs-type\": \"fuse\", \
                    \"check-action-status\": \"true\" \
                }],\
            \"symbol-links\" : [] \
        }] \
    }] \
}";

static const std::string g_permissionConfig = "{ \
        \"permission\":[{ \
            \"ohos.permission.FILE_ACCESS_MANAGER\":[{ \
                \"sandbox-switch\": \"ON\", \
                \"gids\": [1006, 1008], \
                \"sandbox-ns-flags\" : [ \"pid\", \"net\" ], \
                    \"mount-paths\" : [{ \
                    \"src-path\" : \"/config\", \
                    \"sandbox-path\" : \"/data/app/el1/<currentUserId>/database/<PackageName_index>\", \
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
                \"symbol-links\" : [{ \
                        \"target-name\" : \"/system/etc\", \
                        \"link-name\" : \"/etc\", \
                        \"check-action-status\": \"false\", \
                        \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \" \
                    } \
                ] \
            }] \
        }] \
    }";

static const std::string g_flagsPointConfig = "{ \
    \"individual\":[{ \
        \"ohos.samples.ecg\" : [{ \
            \"sandbox-switch\": \"ON\", \
            \"sandbox-shared\" : \"true\", \
            \"mount-paths\" : [], \
            \"flags-point\" : [{ \
                    \"flags\": \"DLP_MANAGER\", \
                    \"sandbox-root\" : \"/mnt/sandbox/com.ohos.render/<PackageName>\", \
                    \"mount-paths\" : [{ \
                        \"src-path\" : \"/data/app/el1/bundle/public/\", \
                        \"sandbox-path\" : \"/data/bundles/\", \
                        \"sandbox-flags\" : [ \"bind\", \"rec\" ], \
                        \"check-action-status\": \"true\", \
                        \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                        \"sandbox-flags-customized\": [ \"MS_NODEV\", \"MS_RDONLY\" ], \
                        \"dac-override-sensitive\": \"true\", \
                        \"mount-shared-flag\" : \"true\", \
                        \"app-apl-name\" : \"system\", \
                        \"fs-type\": \"sharefs\", \
                        \"options\": \"support_overwrite=1\" \
                        }\
                    ]}, { \
                    \"flags\": \"START_FLAGS_BACKUP\", \
                    \"mount-paths\" : [{ \
                        \"src-path\" : \"/data/app/el1/bundle/public/\", \
                        \"sandbox-path\" : \"/data/bundles/\", \
                        \"sandbox-flags\" : [ \"bind\", \"rec\" ], \
                        \"check-action-status\": \"true\" \
                        } \
                    ]} \
            ], \
            \"symbol-links\" : [] \
        }] \
    }] \
}";

static const std::string g_testConfig = "{ \
    \"common\":[{ \
        \"top-sandbox-switch\": \"ON\", \
        \"app-base\":[{ \
            \"sandbox-root\" : \"/mnt/sandbox/<currentUserId>/<PackageName>\", \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/el2/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"/data/storage/el2/base\", \
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
        }] \
    }], \
    \"individual\": [] \
}";

namespace AppSpawn {
class SandboxLoad {
public:
    static int DecodeAppSandboxConfig(AppSpawnSandbox &sandbox, const nlohmann::json &appSandboxConfig);
};

static inline PathMountNode *GetFirstPathNodeInQueue(const SandboxSection *section)
{
    ListNode *node = section->front.next;
    if (node == &section->front) {
        return NULL;
    }
    SandboxPrivateNode *privateNode = reinterpret_cast<SandboxPrivateNode *>(ListEntry(node, SandboxNode, node));
    node = privateNode->section.front.next;
    if (node == &privateNode->section.front) {
        return NULL;
    }
    return reinterpret_cast<PathMountNode *>(ListEntry(node, SandboxNode, node));
}

static inline PathMountNode *GetNextPathNode(const SandboxSection *section, PathMountNode *pathNode)
{
    if (pathNode->sandboxNode.node.next == &section->front) {
        return NULL;
    }
    return reinterpret_cast<PathMountNode *>(ListEntry(pathNode->sandboxNode.node.next, SandboxNode, node));
}

static inline SandboxNode *GetFirstSectionNode(const SandboxSection *section)
{
    ListNode *node = section->front.next;
    if (node == &section->front) {
        return NULL;
    }
    return reinterpret_cast<SandboxNode *>(ListEntry(node, SandboxNode, node));
}

}  // namespace AppSpawn
class AppSpawnSandboxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    AppSpawnTestHelper testHelper_;
};

void AppSpawnSandboxTest::SetUpTestCase()
{}

void AppSpawnSandboxTest::TearDownTestCase()
{}

void AppSpawnSandboxTest::SetUp()
{}

void AppSpawnSandboxTest::TearDown()
{}


HWTEST(AppSpawnSandboxTest, App_Spawn_Permission_01, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);
        sandbox->extData.dumpNode(&sandbox->extData);

        AppSpawnTestHelper testHelper;
        const std::vector<const char *> &permissions = testHelper.GetPermissions();
        for (auto permission : permissions) {
            const SandboxPermissionNode *node = GetPermissionNode(permission);
            APPSPAWN_CHECK(node != nullptr && strcmp(node->name, permission) == 0,
                break, "Failed to permission %{public}s", permission);
            const SandboxPermissionNode *node2 = GetPermissionNodeByIndex(node->permissionIndex);
            APPSPAWN_CHECK(node2 != nullptr && strcmp(node->name, node2->name) == 0,
                break, "Failed to permission %{public}s", permission);
        }
        const char *permission = "ohos.permission.XXXXX";
        const SandboxPermissionNode *node = GetPermissionNode(permission);
        APPSPAWN_CHECK_ONLY_EXPER(node == nullptr, break);
        node = GetPermissionNode(nullptr);
        APPSPAWN_CHECK_ONLY_EXPER(node == nullptr, break);
        ret = 0;
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

static int ProcessTestExpandConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)GetAppPropertyEx(context->property, name, &size);
    if (size == 0 || extInfo == NULL) {
        return 0;
    }
    return 0;
}

HWTEST(AppSpawnSandboxTest, App_Spawn_ExpandCfg_01, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);

        //add default
        AddDefaultExpandAppSandboxConfigHandle();

        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // add expand info to msg
        const char hspListStr[] = "{ \
            \"bundles\":[\"test.bundle1\", \"test.bundle2\"], \
            \"modules\":[\"module1\", \"module2\"], \
            \"versions\":[\"v10001\", \"v10002\"] \
        }";
        ret = AppSpawnReqAddExtInfo(clientHandle, reqHandle, "HspList",
            reinterpret_cast<uint8_t *>(const_cast<char *>(hspListStr)), strlen(hspListStr) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", hspListStr);

        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);
        ret = SetSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}


HWTEST(AppSpawnSandboxTest, App_Spawn_ExpandCfg_02, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);

        //add default
        AddDefaultExpandAppSandboxConfigHandle();
        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // add expand info to msg
        const char dataGroupInfoListStr[] = "{ \
            \"dataGroupId\":[\"1234abcd5678efgh\", \"abcduiop1234\"], \
            \"dir\":[\"/data/app/el2/100/group/091a68a9-2cc9-4279-8849-28631b598975\", \
                     \"/data/app/el2/100/group/ce876162-fe69-45d3-aa8e-411a047af564\"], \
            \"gid\":[\"20100001\", \"20100002\"] \
        }";
        ret = AppSpawnReqAddExtInfo(clientHandle, reqHandle, "DataGroup",
            reinterpret_cast<uint8_t *>(const_cast<char *>(dataGroupInfoListStr)), strlen(dataGroupInfoListStr) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", dataGroupInfoListStr);

        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);
        ret = SetSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_ExpandCfg_03, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {

        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);

        //add default
        AddDefaultExpandAppSandboxConfigHandle();

        // create msg
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        AppSpawnReqSetAppFlag(clientHandle, reqHandle, APP_FLAGS_OVERLAY);
        // add expand info to msg
        const char *overlayInfo = "/data/app/el1/bundle/public/com.ohos.demo/feature.hsp| "
            "/data/app/el1/bundle/public/com.ohos.demo/feature.hsp";

        ret = AppSpawnReqAddExtInfo(clientHandle, reqHandle, "Overlay",
            reinterpret_cast<uint8_t *>(const_cast<char *>(overlayInfo)), strlen(overlayInfo) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", overlayInfo);

        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);
        ret = SetSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}


HWTEST(AppSpawnSandboxTest, App_Spawn_ExpandCfg_04, TestSize.Level0)
{
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);

        // add test
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        ret = RegisterExpandSandboxCfgHandler("test-cfg", EXPAND_CFG_HANDLER_PRIO_START, ProcessTestExpandConfig);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ret = RegisterExpandSandboxCfgHandler("test-cfg", EXPAND_CFG_HANDLER_PRIO_START, ProcessTestExpandConfig);
        APPSPAWN_CHECK_ONLY_EXPER(ret == APPSPAWN_NODE_EXIST, break);

        // create msg
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_SPAWN_NATIVE_PROCESS, 0);
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

        ret = AppSpawnReqAddExtInfo(clientHandle, reqHandle, "test-cfg",
            reinterpret_cast<uint8_t *>(const_cast<char *>(testInfo)), strlen(testInfo) + 1);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", testInfo);

        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);
        ret = SetSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_01, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox);
        sandbox->extData.dumpNode(&sandbox->extData);
        ret = 0;
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_02, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        nlohmann::json config = nlohmann::json::parse(g_commonConfig.c_str());
        AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_LOGV("sandbox->section.rootPath: %{public}s", sandbox->section.rootPath);
        ASSERT_EQ(sandbox->topSandboxSwitch == 1, 1);
        ASSERT_EQ(strcmp(sandbox->section.rootPath, "/mnt/sandbox/<currentUserId>/<PackageName>"), 0);
        // check mount path
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSectionNode(&sandbox->section));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->mountFlags & (MS_BIND | MS_REC)) == (MS_BIND | MS_REC), 1);
        ASSERT_EQ((pathNode->mountFlags & MS_RDONLY) == MS_RDONLY, 0);  // not set
        ASSERT_EQ((pathNode->customizedFlags & (MS_NODEV | MS_RDONLY)) == (MS_NODEV | MS_RDONLY), 1);
        ASSERT_EQ((pathNode->customizedFlags & MS_REMOUNT) == MS_REMOUNT, 0);  // not set

        ASSERT_EQ(pathNode->dacOverrideSensitive == 1, 1);
        ASSERT_EQ(pathNode->mountSharedFlag == 1, 1);

        ASSERT_EQ(pathNode->options != nullptr, 1);
        ASSERT_EQ(pathNode->fsType != nullptr, 1);
        ASSERT_EQ(pathNode->appAplName != nullptr, 1);
        ASSERT_EQ(strcmp(pathNode->options, "support_overwrite=1"), 0);
        ASSERT_EQ(strcmp(pathNode->fsType, "sharefs"), 0);
        ASSERT_EQ(strcmp(pathNode->appAplName, "system"), 0);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_03, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        nlohmann::json config = nlohmann::json::parse(g_individualConfig.c_str());
        AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 0, 1);  // not set
        ASSERT_EQ((sandbox->sandboxNsFlags[1] & (CLONE_NEWPID | CLONE_NEWNET)) == (CLONE_NEWPID | CLONE_NEWNET), 1);

        // check private section
        SandboxPrivateNode *privateNode =
            reinterpret_cast<SandboxPrivateNode *>(GetFirstSectionNode(&sandbox->privateNodeQueue));
        ASSERT_EQ(privateNode != NULL, 1);
        ASSERT_EQ(strcmp(privateNode->name, "__internal__.com.ohos.render"), 0);
        ASSERT_EQ(privateNode->section.rootPath != nullptr, 1);
        ASSERT_EQ(strcmp(privateNode->section.rootPath, "/mnt/sandbox/com.ohos.render/<PackageName>"), 0);
        ASSERT_EQ((privateNode->section.sandboxShared == 1) && (privateNode->section.sandboxSwitch == 1), 1);

        // check path node
        PathMountNode *pathNode = GetFirstPathNodeInQueue(&sandbox->privateNodeQueue);
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->mountFlags & (MS_BIND | MS_REC)) == (MS_BIND | MS_REC), 1);
        ASSERT_EQ((pathNode->mountFlags & MS_RDONLY) == MS_RDONLY, 0);  // not set
        ASSERT_EQ((pathNode->customizedFlags & (MS_NODEV | MS_RDONLY)) == (MS_NODEV | MS_RDONLY), 1);
        ASSERT_EQ((pathNode->customizedFlags & MS_REMOUNT) == MS_REMOUNT, 0);  // not set
        ASSERT_EQ((pathNode->dacOverrideSensitive == 1) && (pathNode->mountSharedFlag == 1), 1);

        ASSERT_EQ((pathNode->options != nullptr) && (strcmp(pathNode->options, "support_overwrite=1") == 0), 1);
        ASSERT_EQ((pathNode->fsType != nullptr) && (strcmp(pathNode->fsType, "sharefs") == 0), 1);
        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);
        // check symlink
        SymbolLinkNode *linkNode =
            reinterpret_cast<SymbolLinkNode *>(GetNextPathNode(&sandbox->privateNodeQueue, pathNode));
        ASSERT_EQ(linkNode != NULL, 1);
        ASSERT_EQ(linkNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((linkNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_04, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        nlohmann::json config = nlohmann::json::parse(g_permissionConfig.c_str());
        AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 0, 1);  // not set

        // check permission section
        SandboxPermissionNode *permissionNode =
            reinterpret_cast<SandboxPermissionNode *>(GetFirstSectionNode(&sandbox->permissionNodeQueue));
        ASSERT_EQ(permissionNode != nullptr, 1);
        ASSERT_EQ(permissionNode->name != nullptr, 1);
        ASSERT_EQ(strcmp(permissionNode->name, "ohos.permission.FILE_ACCESS_MANAGER"), 0);
        ASSERT_EQ(permissionNode->section.rootPath == nullptr, 1);  // use default root path

        // check path node
        PathMountNode *pathNode = GetFirstPathNodeInQueue(&sandbox->permissionNodeQueue);
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->mountFlags & (MS_BIND | MS_REC)) == (MS_BIND | MS_REC), 1);
        ASSERT_EQ((pathNode->mountFlags & MS_RDONLY) == MS_RDONLY, 0);  // not set
        ASSERT_EQ((pathNode->customizedFlags & (MS_NODEV | MS_RDONLY)) == (MS_NODEV | MS_RDONLY), 1);
        ASSERT_EQ((pathNode->customizedFlags & MS_REMOUNT) == MS_REMOUNT, 0);  // not set
        ASSERT_EQ((pathNode->dacOverrideSensitive == 1) && (pathNode->mountSharedFlag == 1), 1);
        ASSERT_EQ((pathNode->options != nullptr) && (strcmp(pathNode->options, "support_overwrite=1") == 0), 1);
        ASSERT_EQ((pathNode->fsType != nullptr) && (strcmp(pathNode->fsType, "sharefs") == 0), 1);
        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);

        // check symlink
        SymbolLinkNode *linkNode =
            reinterpret_cast<SymbolLinkNode *>(GetNextPathNode(&sandbox->permissionNodeQueue, pathNode));
        ASSERT_EQ(linkNode != NULL, 1);
        ASSERT_EQ(linkNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((linkNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_05, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        nlohmann::json config = nlohmann::json::parse(g_flagsPointConfig.c_str());
        AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 0, 1);  // not set
        ASSERT_EQ(sandbox->sandboxNsFlags[1] == 0, 1);

        // check private section
        SandboxPrivateNode *privateNode =
            reinterpret_cast<SandboxPrivateNode *>(GetFirstSectionNode(&sandbox->privateNodeQueue));
        ASSERT_EQ(privateNode != nullptr, 1);
        ASSERT_EQ(strcmp(privateNode->name, "ohos.samples.ecg"), 0);
        ASSERT_EQ(privateNode->section.rootPath == nullptr, 1);  // use default
        ASSERT_EQ((privateNode->section.sandboxShared == 1) && (privateNode->section.sandboxSwitch == 1), 1);
        ASSERT_EQ((privateNode->section.rootFlagsPath[1] != nullptr) &&
            (strcmp(privateNode->section.rootFlagsPath[1], "/mnt/sandbox/com.ohos.render/<PackageName>") == 0), 1);

        // check path node
        PathMountNode *pathNode = GetFirstPathNodeInQueue(&sandbox->privateNodeQueue);
        ASSERT_EQ(pathNode != nullptr, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 1, 1);  // set
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->mountFlags & (MS_BIND | MS_REC)) == (MS_BIND | MS_REC), 1);
        ASSERT_EQ((pathNode->mountFlags & MS_RDONLY) == MS_RDONLY, 0);  // not set
        ASSERT_EQ((pathNode->customizedFlags & (MS_NODEV | MS_RDONLY)) == (MS_NODEV | MS_RDONLY), 1);
        ASSERT_EQ((pathNode->customizedFlags & MS_REMOUNT) == MS_REMOUNT, 0);  // not set
        ASSERT_EQ((pathNode->dacOverrideSensitive == 1) && (pathNode->mountSharedFlag == 1), 1);
        ASSERT_EQ((pathNode->options != nullptr) && (strcmp(pathNode->options, "support_overwrite=1") == 0), 1);
        ASSERT_EQ((pathNode->fsType != nullptr) && (strcmp(pathNode->fsType, "sharefs") == 0), 1);
        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);
        ASSERT_EQ(TEST_FLAGS_BY_INDEX(pathNode->flagsPoint, APP_FLAGS_DLP_MANAGER), 1);

        // check other path node
        pathNode = GetNextPathNode(&sandbox->permissionNodeQueue, pathNode);
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 1, 1);
        ASSERT_EQ((pathNode->mountFlags & (MS_BIND | MS_REC)) == (MS_BIND | MS_REC), 1);
        ASSERT_EQ(TEST_FLAGS_BY_INDEX(pathNode->flagsPoint, APP_FLAGS_BACKUP_EXTENSION), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_10, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_commonConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.dlpmanager/config";
        args.fsType = "sharefs";
        args.mountFlags = MS_NODEV | MS_RDONLY;  // 当前条件走customizedFlags，这里设置为customizedFlags
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);

        ret = SetSandboxConfigs(sandbox, property, 0);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ASSERT_EQ(stub->result, 0);
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_11, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_commonConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.dlpmanager/config";
        args.fsType = "sharefs";
        args.mountFlags = MS_NODEV | MS_RDONLY;  // 当前条件走customizedFlags，这里设置为customizedFlags
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);

        // 执行失败, 但是不返回
        args.mountFlags = MS_NODEV;
        ret = SetSandboxConfigs(sandbox, property, 0);
        ASSERT_EQ(ret, 0);
        ASSERT_NE(stub->result, 0);
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_12, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_commonConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ListNode *node = sandbox->section.front.next;
        ASSERT_EQ(node != &sandbox->section.front, 1);
        PathMountNode *pathNode = (PathMountNode *)ListEntry(node, SandboxNode, node);
        pathNode->checkErrorFlag = 1;  // 设置错误检查

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.dlpmanager/config";
        args.fsType = "sharefs";
        args.mountFlags = MS_NODEV | MS_RDONLY;  // 当前条件走customizedFlags，这里设置为customizedFlags
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);

        // 执行失败, 返回错误
        args.mountFlags = MS_NODEV;
        ret = SetSandboxConfigs(sandbox, property, 0);
        ASSERT_NE(ret, 0);
        ASSERT_NE(stub->result, 0);
        ret = 0;
    } while (0);
    ASSERT_EQ(ret, 0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_13, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_individualConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/dev/fuse";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.dlpmanager/mnt/data/fuse";
        args.fsType = "fuse";
        args.mountFlags = MS_LAZYTIME | MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);

        ret = SetSandboxConfigs(sandbox, property, 0);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ASSERT_EQ(stub->result, 0);
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_14, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_individualConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/dev/fuse";
        args.destinationPath = "/home/axw/appspawn_ut/mnt/sandbox/100/com.ohos.dlpmanager/mnt/data/fuse";
        args.fsType = "fuse";
        args.mountFlags = MS_LAZYTIME | MS_NOATIME | MS_NODEV | MS_NOEXEC;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);
        ret = SetSandboxConfigs(sandbox, property, 0);
        ASSERT_NE(ret, 0);
        ASSERT_NE(stub->result, 0);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_15, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper_.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // 设置permission
        AppSpawnReqSeFlags(clientHandle, reqHandle, TLV_PERMISSION, 0x01);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper_.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_permissionConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.dlpmanager/"
            "data/app/el1/currentUser/database/com.ohos.dlpmanager_100";
        args.fsType = "sharefs";
        args.mountFlags = MS_NODEV | MS_RDONLY;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);
        ret = SetSandboxConfigs(sandbox, property, 0);
        ASSERT_EQ(ret, 0);  // do not check result
        ASSERT_EQ(stub->result != 0, 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_16, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        AppSpawnTestHelper testHelper;
        testHelper.SetProcessName("__internal__.com.ohos.render");
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);
        // 设置permission
        AppSpawnReqSeFlags(clientHandle, reqHandle, TLV_PERMISSION, 0x01);
        AppSpawnReqSeFlags(clientHandle, reqHandle, TLV_MSG_FLAGS, 0x01);

        ret = APPSPAWN_INVALID_ARG;
        property = testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_individualConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/com.ohos.render/__internal__.com.ohos.render/config";
        args.fsType = "sharefs";
        args.mountFlags = MS_NODEV | MS_RDONLY;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);
        ret = SetSandboxConfigs(sandbox, property, 1);
        ASSERT_EQ(ret, 0);  // do not check result
        ASSERT_EQ(stub->result, 0);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_17, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        AppSpawnTestHelper testHelper;
        testHelper.SetProcessName("__internal__.com.ohos.render");
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        property = testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_individualConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        PathMountNode *pathNode = GetFirstPathNodeInQueue(&sandbox->privateNodeQueue);
        ASSERT_EQ(pathNode != nullptr, 1);
        pathNode->checkErrorFlag = 1;

        // set check point
        MountArg args = {};
        args.originPath = "/config";
        args.destinationPath = "/mnt/sandbox/com.ohos.render/__internal__.com.ohos.render/config";
        args.fsType = "share";
        args.mountFlags = MS_NODEV | MS_RDONLY;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);
        ret = SetSandboxConfigs(sandbox, property, 1);
        ASSERT_NE(ret, 0);  // do not check result
        ASSERT_NE(stub->result, 0);
        ret = 0;
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
    ASSERT_EQ(ret, 0);
}


HWTEST(AppSpawnSandboxTest, App_Spawn_Sandbox_18, TestSize.Level0)
{
    AppSpawnSandbox *sandbox = nullptr;
    AppSpawnClientHandle clientHandle = nullptr;
    AppSpawnReqHandle reqHandle = 0;
    AppProperty *property = nullptr;
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);
    int ret = -1;
    do {
        AppSpawnTestHelper testHelper;
        testHelper.SetProcessName("com.ohos.tester");
        ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
        APPSPAWN_CHECK(ret == 0, break, "Failed to create reqMgr %{public}s", APPSPAWN_SERVER_NAME);
        reqHandle = testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 1);
        APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, break, "Failed to create req %{public}s", APPSPAWN_SERVER_NAME);

        property = testHelper.GetAppProperty(clientHandle, reqHandle);
        APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, ret = -1; break);

        AddDefaultVariable();
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        sandbox->appFullMountEnable = 1;
        nlohmann::json config = nlohmann::json::parse(g_testConfig.c_str());
        ret = AppSpawn::SandboxLoad::DecodeAppSandboxConfig(*sandbox, config);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSectionNode(&sandbox->section));
        APPSPAWN_CHECK_ONLY_EXPER(pathNode != nullptr, ret = -1; break);
        pathNode->checkErrorFlag = 1;

        // set check point
        MountArg args = {};
        args.originPath = "/data/app/el2/100/base/com.ohos.tester";
        args.destinationPath = "/mnt/sandbox/100/com.ohos.tester/data/storage/el2/base";
        args.fsType = "share";
        args.mountFlags = MS_NODEV | MS_RDONLY;
        stub->flags = STUB_NEED_CHECK;
        stub->arg = reinterpret_cast<void *>(&args);
        ret = SetSandboxConfigs(sandbox, property, 0);
    } while (0);
    if (sandbox) {
        AppSpawnSandboxFree(&sandbox->extData);
    }
    ASSERT_NE(ret, 0);  // do not check result
    ASSERT_NE(stub->result, 0);
    stub->flags &= ~STUB_NEED_CHECK;
    AppMgrDeleteAppProperty(property);
    AppSpawnClientDestroy(clientHandle);
}
}  // namespace OHOS
