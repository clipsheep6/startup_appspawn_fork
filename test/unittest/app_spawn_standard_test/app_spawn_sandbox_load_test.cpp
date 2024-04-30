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

#include "appspawn_manager.h"
#include "appspawn_modulemgr.h"
#include "appspawn_permission.h"
#include "appspawn_sandbox.h"
#include "appspawn_server.h"
#include "appspawn_utils.h"
#include "cJSON.h"
#include "json_utils.h"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static inline SandboxMountNode *GetNextSandboxMountPathNode(const SandboxSection *section, SandboxMountNode *pathNode)
{
    APPSPAWN_CHECK_ONLY_EXPER(section != nullptr && pathNode != nullptr, return nullptr);
    if (pathNode->node.next == &section->front) {
        return NULL;
    }
    return reinterpret_cast<SandboxMountNode *>(ListEntry(pathNode->node.next, SandboxMountNode, node));
}

static AppSpawnTestHelper g_testHelper;
class AppSpawnSandboxLoadTest : public testing::Test {
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
 * @brief 加载系统的sandbox文件
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_001, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        LoadAppSandboxConfig(sandbox, 0);
        sandbox->extData.dumpNode(&sandbox->extData);
        ret = 0;
    } while (0);
    if (sandbox != nullptr) {
        sandbox->extData.freeNode(&sandbox->extData);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 加载基础的sandbox配置，并检查结果
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_002, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
        ASSERT_EQ(ret, 0);
        APPSPAWN_LOGV("sandbox->rootPath: %{public}s", sandbox->rootPath);

        ASSERT_EQ(sandbox->topSandboxSwitch == 1, 1);
        ASSERT_EQ((sandbox->sandboxNsFlags & CLONE_NEWNET) == CLONE_NEWNET, 1);
        ASSERT_EQ(strcmp(sandbox->rootPath, "/mnt/sandbox/<currentUserId>/app-root"), 0);

        SandboxSection *section = GetSandboxSection(&sandbox->requiredQueue, "system-const");
        ASSERT_EQ(section != nullptr, 1);
        // check mount path
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSandboxMountNode(section));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_SHRED);
        pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_RDONLY);
        pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_EPFS);
        pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_DAC_OVERRIDE);
        pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_FUSE);
        ret = 0;
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 加载包名sandbox配置，并检查结果
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_003, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        ret = TestParseAppSandboxConfig(sandbox, GetSandboxPackageNameCfg());
        ASSERT_EQ(ret, 0);
        APPSPAWN_LOGV("sandbox->rootPath: %{public}s", sandbox->rootPath);

        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 0, 1);  // not set
        ASSERT_EQ((sandbox->sandboxNsFlags & CLONE_NEWNET) == CLONE_NEWNET, 1);

        // check private section
        SandboxPackageNameNode *sandboxNode = reinterpret_cast<SandboxPackageNameNode *>(
            GetSandboxSection(&sandbox->packageNameQueue, "test.example.ohos.com"));
        ASSERT_EQ(sandboxNode != NULL, 1);
        ASSERT_EQ(strcmp(sandboxNode->section.name, "test.example.ohos.com"), 0);
        ASSERT_EQ((sandboxNode->section.sandboxShared == 1) && (sandboxNode->section.sandboxSwitch == 1), 1);

        // check path node
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(
            GetFirstSandboxMountNode(&sandboxNode->section));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);

        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);
        // check symlink
        SymbolLinkNode *linkNode = reinterpret_cast<SymbolLinkNode *>(
            GetNextSandboxMountPathNode(&sandboxNode->section, &pathNode->sandboxNode));
        ASSERT_EQ(linkNode != NULL, 1);
        ASSERT_EQ(linkNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((linkNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 加载一个permission sandbox 配置。并检查配置解析是否正确
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_004, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);

        ret = TestParseAppSandboxConfig(sandbox, GetSandboxPermissionCfg());
        ASSERT_EQ(ret, 0);
        APPSPAWN_LOGV("sandbox->rootPath: %{public}s", sandbox->rootPath);
        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 1, 1);  // not set, default value 1

        // check permission section
        SandboxPermissionNode *permissionNode = reinterpret_cast<SandboxPermissionNode *>(
            GetSandboxSection(&sandbox->permissionQueue, "ohos.permission.FILE_ACCESS_MANAGER"));
        ASSERT_EQ(permissionNode != nullptr, 1);
        ASSERT_EQ(permissionNode->section.gidTable != nullptr, 1);
        ASSERT_EQ(permissionNode->section.gidCount, 2);
        ASSERT_EQ(permissionNode->section.gidTable[0], 1006);
        ASSERT_EQ(permissionNode->section.gidTable[1], 1008);
        ASSERT_EQ(strcmp(permissionNode->section.name, "ohos.permission.FILE_ACCESS_MANAGER"), 0);

        // check path node
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(
            GetFirstSandboxMountNode(&permissionNode->section));
        ASSERT_EQ(pathNode != NULL, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 1, 1);
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);

        // check symlink
        SymbolLinkNode *linkNode = reinterpret_cast<SymbolLinkNode *>(
            GetNextSandboxMountPathNode(&permissionNode->section, &pathNode->sandboxNode));
        ASSERT_EQ(linkNode != NULL, 1);
        ASSERT_EQ(linkNode->checkErrorFlag == 0, 1);
        ASSERT_EQ((linkNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 加载一个spawn-flags sandbox 配置。并检查配置解析是否正确
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_005, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxspawnFlagsCfg());
        ASSERT_EQ(ret, 0);
        // top check
        ASSERT_EQ(sandbox->topSandboxSwitch == 0, 1);  // not set

        // check private section
        SandboxFlagsNode *sandboxNode = reinterpret_cast<SandboxFlagsNode *>(
            GetSandboxSection(&sandbox->spawnFlagsQueue, "START_FLAGS_BACKUP"));
        ASSERT_EQ(sandboxNode != nullptr, 1);
        ASSERT_EQ(strcmp(sandboxNode->section.name, "START_FLAGS_BACKUP"), 0);
        // no set, check default
        ASSERT_EQ((sandboxNode->section.sandboxShared == 0) && (sandboxNode->section.sandboxSwitch == 1), 1);
        ASSERT_EQ(sandboxNode->flagIndex == APP_FLAGS_BACKUP_EXTENSION, 1);

        // check path node
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(
            GetFirstSandboxMountNode(&sandboxNode->section));
        ASSERT_EQ(pathNode != nullptr, 1);
        ASSERT_EQ(pathNode->checkErrorFlag == 1, 1);  // set
        ASSERT_EQ((pathNode->destMode & (S_IRUSR | S_IWOTH | S_IRWXU)) == (S_IRUSR | S_IWOTH | S_IRWXU), 1);
        ASSERT_EQ((pathNode->appAplName != nullptr) && (strcmp(pathNode->appAplName, "system") == 0), 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 加载一个name-group sandbox 配置。并检查配置解析是否正确
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_006, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    int ret = -1;
    do {
        sandbox = CreateAppSpawnSandbox();
        APPSPAWN_CHECK_ONLY_EXPER(sandbox != nullptr, break);
        ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
        ASSERT_EQ(ret, 0);
        // check private section
        SandboxNameGroupNode *sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(
            GetSandboxSection(&sandbox->nameGroupsQueue, "el5"));
        ASSERT_EQ(sandboxNode != nullptr, 1);
        ASSERT_EQ(strcmp(sandboxNode->section.name, "el5"), 0);
        // no set, check default
        ASSERT_EQ((sandboxNode->section.sandboxShared == 0) && (sandboxNode->section.sandboxSwitch == 1), 1);
        ASSERT_EQ(sandboxNode->depMode == MOUNT_MODE_NOT_EXIST, 1);
        ASSERT_EQ(sandboxNode->destType == SANDBOX_TAG_APP_VARIABLE, 1);
        ASSERT_EQ(sandboxNode->depNode != nullptr, 1);
        PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(sandboxNode->depNode);
        ASSERT_EQ(pathNode->category, MOUNT_TMP_SHRED);
        ASSERT_EQ(strcmp(pathNode->target, "/data/storage/el5") == 0, 1);

        // check path node
        pathNode = reinterpret_cast<PathMountNode *>(GetFirstSandboxMountNode(&sandboxNode->section));
        ASSERT_EQ(pathNode != nullptr, 1);
        ASSERT_EQ(strcmp(pathNode->source, "/data/app/el5/<currentUserId>/base/<PackageName>") == 0, 1);
        ASSERT_EQ(strcmp(pathNode->target, "<deps-path>/base") == 0, 1);
        ret = 0;
    } while (0);
    if (sandbox) {
        DeleteAppSpawnSandbox(sandbox);
    }
    ASSERT_EQ(ret, 0);
}

/**
 * @brief 包含create-on-demand字段的
 * "create-on-demand": {
    "uid": "userId", // 默认使用消息的uid、gid
    "gid":  "groupId",
    "ugo": 750
    }
 *
 */
static const std::string g_createOnDemandConfig = "{ \
    \"required\":{ \
        \"app-variable\":{ \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/appspawn_ut/config\", \
                \"sandbox-path\" : \"/data/appspawn_ut/config\", \
                \"check-action-status\": \"false\", \
                \"create-on-demand\": { \
                    \"uid\": \"system\", \
                    \"gid\": \"system\",\
                    \"ugo\": 750\
                } \
            }, { \
                \"src-path\" : \"/data/appspawn_ut/config2\", \
                \"sandbox-path\" : \"/data/appspawn_ut/config2\", \
                \"check-action-status\": \"false\", \
                \"create-on-demand\": { \
                    \"uid\": 1000, \
                    \"gid\":  1000,\
                    \"ugo\": 750\
                } \
            }, { \
                \"src-path\" : \"/data/appspawn_ut/config3\", \
                \"sandbox-path\" : \"/data/appspawn_ut/config3\", \
                \"check-action-status\": \"false\", \
                \"create-on-demand\": { \
                    \"gid\":  1000,\
                    \"ugo\": 750\
                } \
            }, { \
                \"src-path\" : \"/data/appspawn_ut/config4\", \
                \"sandbox-path\" : \"/data/appspawn_ut/config4\", \
                \"check-action-status\": \"false\", \
                \"create-on-demand\": { \
                    \"uid\": 1000, \
                    \"ugo\": 750\
                } \
            }, { \
                \"src-path\" : \"/data/appspawn_ut/config5\", \
                \"sandbox-path\" : \"/data/appspawn_ut/config5\", \
                \"check-action-status\": \"false\", \
                \"create-on-demand\": { \
                    \"uid\": {}, \
                    \"gid\": {}, \
                    \"ugo\": 750\
                } \
            }], \
            \"symbol-links\" : [] \
        } \
    } \
}";

HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_007, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = nullptr;
    sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, g_createOnDemandConfig.c_str());
    ASSERT_EQ(ret, 0);
    // check private section
    SandboxSection *section = GetSandboxSection(&sandbox->requiredQueue, "app-variable");
    ASSERT_EQ(section != nullptr, 1);
    ASSERT_EQ(strcmp(section->name, "app-variable"), 0);

    // check path node
    PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSandboxMountNode(section));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(pathNode->category, MOUNT_TMP_DEFAULT);
    ASSERT_EQ(strcmp(pathNode->target, "/data/appspawn_ut/config") == 0, 1);
    // 检查demand信息
    ASSERT_EQ(pathNode->createDemand, 1);
    ASSERT_EQ(pathNode->demandInfo->uid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->gid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->mode, 750); // 750 test

    pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(pathNode->category, MOUNT_TMP_DEFAULT);
    ASSERT_EQ(strcmp(pathNode->target, "/data/appspawn_ut/config2") == 0, 1);
    // 检查demand信息
    ASSERT_EQ(pathNode->createDemand, 1);
    ASSERT_EQ(pathNode->demandInfo->uid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->gid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->mode, 750); // 750 test

    pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(pathNode->category, MOUNT_TMP_DEFAULT);
    ASSERT_EQ(strcmp(pathNode->target, "/data/appspawn_ut/config3") == 0, 1);
    // 检查demand信息
    ASSERT_EQ(pathNode->createDemand, 1);
    ASSERT_EQ(pathNode->demandInfo->uid, -1); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->gid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->mode, 750); // 750 test

    pathNode = reinterpret_cast<PathMountNode *>(GetNextSandboxMountPathNode(section, &pathNode->sandboxNode));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(pathNode->category, MOUNT_TMP_DEFAULT);
    ASSERT_EQ(strcmp(pathNode->target, "/data/appspawn_ut/config4") == 0, 1);
    // 检查demand信息
    ASSERT_EQ(pathNode->createDemand, 1);
    ASSERT_EQ(pathNode->demandInfo->uid, 1000); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->gid, -1); // 1000 test
    ASSERT_EQ(pathNode->demandInfo->mode, 750); // 750 test
    DeleteAppSpawnSandbox(sandbox);
}

// START_FLAGS_BACKUP_2 无效的flags
static const std::string g_InvalidSpawnFlagsConfig = "{ \
    \"conditional\":{ \
        \"spawn-flag\": [{ \
            \"name\": \"START_FLAGS_BACKUP_2\", \
            \"mount-paths\": [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"check-action-status\": \"true\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"sandbox-path\": \"/data/storage/el1/backup\", \
                \"src-path\": \"/data/service/el1/<currentUserId>/backup/bundles/<PackageName>\" \
            }], \
            \"mount-groups\": [] \
        }, { \
            \"mount-paths\": [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"check-action-status\": \"true\" \
            }], \
            \"mount-groups\": [] \
        }, { \
            \"name\": \"\", \
            \"mount-paths\": [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"check-action-status\": \"true\" \
            }], \
            \"mount-groups\": [] \
        }] \
    }\
}";
/**
 * @brief 无效的flags，index 为0
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_008, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, g_InvalidSpawnFlagsConfig.c_str());
    ASSERT_NE(ret, 0);
    // check private section
    SandboxFlagsNode *sandboxNode = reinterpret_cast<SandboxFlagsNode *>(
        GetSandboxSection(&sandbox->spawnFlagsQueue, "START_FLAGS_BACKUP_2"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "START_FLAGS_BACKUP_2"), 0);
    ASSERT_EQ(sandboxNode->flagIndex, 0);
    DeleteAppSpawnSandbox(sandbox);
}

/**
 * @brief 无效的sandbox-ns-flags
 *
 */

HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_009, TestSize.Level0)
{
    static const std::string InvalidNsFlagsConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"sandbox-ns-flags\": [ \"pid\", \"net\", \"22222\" ], \
            \"top-sandbox-switch\": \"OFF\" \
        } \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, InvalidNsFlagsConfig.c_str());
    ASSERT_EQ(ret, 0);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_010, TestSize.Level0)
{
    static const std::string InvalidNsFlagsConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"sandbox-ns-flags\": \"\", \
            \"top-sandbox-switch\": \"OFF\" \
        } \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, InvalidNsFlagsConfig.c_str());
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sandbox->sandboxNsFlags == 0, 1);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_011, TestSize.Level0)
{
    static const std::string InvalidNsFlagsConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"top-sandbox-switch\": \"OFF\" \
        } \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, InvalidNsFlagsConfig.c_str());
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sandbox->sandboxNsFlags == 0, 1);
    DeleteAppSpawnSandbox(sandbox);
}

/**
 * @brief 测试无效的dep-mode
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_012, TestSize.Level0)
{
    static const std::string g_depModeConfig = "{ \
        \"name-groups\": [ \
            { \
                \"name\": \"test-001\", \
                \"type\": \"system-const\", \
                \"deps-mode\": \"not-exists\" \
            }, { \
                \"name\": \"test-002\", \
                \"type\": \"app-variable\", \
                \"deps-mode\": \"always\" \
            }, { \
                \"name\": \"test-003\", \
                \"deps-mode\": \"\" \
            } , { \
                \"name\": \"test-004\", \
                \"type\": \"\" \
            } \
        ] \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, g_depModeConfig.c_str());
    ASSERT_EQ(ret, 0);
    SandboxNameGroupNode *sandboxNode = nullptr;
    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-001"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-001"), 0);
    ASSERT_EQ(sandboxNode->depMode, MOUNT_MODE_NOT_EXIST);
    ASSERT_EQ(sandboxNode->destType, SANDBOX_TAG_SYSTEM_CONST);

    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-002"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-002"), 0);
    ASSERT_EQ(sandboxNode->depMode, MOUNT_MODE_ALWAYS);
    ASSERT_EQ(sandboxNode->destType, SANDBOX_TAG_APP_VARIABLE);

    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-003"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-003"), 0);
    ASSERT_EQ(sandboxNode->depMode, MOUNT_MODE_ALWAYS);
    ASSERT_EQ(sandboxNode->destType, SANDBOX_TAG_INVALID);

    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-004"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-004"), 0);
    ASSERT_EQ(sandboxNode->depMode, MOUNT_MODE_ALWAYS);
    ASSERT_EQ(sandboxNode->destType, SANDBOX_TAG_INVALID);

    DeleteAppSpawnSandbox(sandbox);
}

/**
 * @brief 无效的 mount-paths
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_013, TestSize.Level0)
{
    static const std::string InvalidMountPathsConfig = "{ \
        \"name-groups\": [ \
            { \
                \"name\": \"test-013-1\", \
                \"type\": \"system-const\", \
                \"mount-paths\" : [{ \
                    \"sandbox-path\" : \"/data/storage/el2/base\" \
                }, { \
                    \"src-path\" : \"/data/storage/el2/base\" \
                }, { \
                    \"src-path\" : \"/data/storage/el2/base2\", \
                    \"sandbox-path\" : \"/data/storage/el2/base2\", \
                    \"category\": \"shared\" \
                }] \
            } \
        ] \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, InvalidMountPathsConfig.c_str());
    ASSERT_EQ(ret, 0);
    SandboxNameGroupNode *sandboxNode = nullptr;
    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-013-1"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-013-1"), 0);
    // only one
    PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSandboxMountNode(&sandboxNode->section));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(pathNode->category, MOUNT_TMP_SHRED);
    ASSERT_EQ(strcmp(pathNode->target, "/data/storage/el2/base2") == 0, 1);

    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_014, TestSize.Level0)
{
    static const std::string InvalidMountPathsConfig = "{ \
        \"name-groups\": [ \
            { \
                \"name\": \"test-014-1\", \
                \"type\": \"system-const\", \
                \"symbol-links\" : [{ \
                    \"target-name\" : \"/data/storage/el2/base\" \
                }, { \
                    \"link-name\" : \"/data/storage/el2/base\" \
                }, { \
                    \"link-name\" : \"/data/storage/el2/base2\", \
                    \"target-name\" : \"/data/storage/el2/base2\", \
                    \"category\": \"shared\" \
                }] \
            } \
        ] \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, InvalidMountPathsConfig.c_str());
    ASSERT_EQ(ret, 0);
    SandboxNameGroupNode *sandboxNode = nullptr;
    sandboxNode = reinterpret_cast<SandboxNameGroupNode *>(GetSandboxSection(&sandbox->nameGroupsQueue, "test-014-1"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->section.name, "test-014-1"), 0);
    // only one
    SymbolLinkNode *pathNode = reinterpret_cast<SymbolLinkNode *>(GetFirstSandboxMountNode(&sandboxNode->section));
    ASSERT_EQ(pathNode != nullptr, 1);
    ASSERT_EQ(strcmp(pathNode->target, "/data/storage/el2/base2") == 0, 1);

    DeleteAppSpawnSandbox(sandbox);
}

/**
 * @brief 测试mount-groups 的合并
 *
 */
HWTEST(AppSpawnSandboxLoadTest, App_Spawn_Sandbox_cfg_015, TestSize.Level0)
{
    static const std::string nameGroupsConfig1 = "{ \
        \"required\":{ \
            \"system-const\":{ \
                \"mount-groups\": [\"test-001\", \"test-002\"] \
            }, \
            \"app-variable\":{ \
                \"mount-groups\": [\"test-003\", \"test-004\", \"test-003\"] \
            } \
        }, \
        \"name-groups\": [ \
            { \
                \"name\": \"test-001\", \
                \"type\": \"system-const\", \
                \"deps-mode\": \"not-exists\" \
            }, { \
                \"name\": \"test-002\", \
                \"type\": \"app-variable\", \
                \"deps-mode\": \"always\" \
            }, { \
                \"name\": \"test-003\", \
                \"deps-mode\": \"\" \
            } , { \
                \"name\": \"test-004\", \
                \"type\": \"\" \
            } , { \
                \"name\": \"test-005\", \
                \"type\": \"\" \
            }, { \
                \"name\": \"test-006\", \
                \"type\": \"\" \
            }\
        ] \
    }";
    static const std::string nameGroupsConfig2 = "{ \
        \"required\":{ \
            \"system-const\":{ \
                \"mount-groups\": [\"test-001\", \"test-002\"] \
            }, \
            \"app-variable\":{ \
                \"mount-groups\": [\"test-003\", \"test-004\", \"test-005\", \"test-006\", \"test-007\"] \
            } \
        } \
    }";

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    ASSERT_EQ(sandbox != nullptr, 1);
    int ret = TestParseAppSandboxConfig(sandbox, nameGroupsConfig1.c_str());
    ASSERT_EQ(ret, 0);
    SandboxSection *sandboxNode = nullptr;
    sandboxNode = reinterpret_cast<SandboxSection *>(GetSandboxSection(&sandbox->requiredQueue, "app-variable"));
    ASSERT_EQ(sandboxNode != nullptr, 1);
    ASSERT_EQ(strcmp(sandboxNode->name, "app-variable"), 0);
    // name group check
    ASSERT_EQ(sandboxNode->nameGroups != nullptr, 1);
    ASSERT_EQ(sandboxNode->number, 2);

    SandboxSection *nameGroup4 = GetSandboxSection(&sandbox->nameGroupsQueue, "test-004");
    ASSERT_EQ(nameGroup4 != nullptr, 1);
    ASSERT_EQ(sandboxNode->nameGroups[1] == &nameGroup4->sandboxNode, 1);

    // 重复解析，合并
    ret = TestParseAppSandboxConfig(sandbox, nameGroupsConfig2.c_str());
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sandboxNode->nameGroups != nullptr, 1);
    ASSERT_EQ(sandboxNode->number, 4); // 4 total name group
    ASSERT_EQ(sandboxNode->nameGroups[1] == &nameGroup4->sandboxNode, 1);

    DeleteAppSpawnSandbox(sandbox);
}
}  // namespace OHOS
