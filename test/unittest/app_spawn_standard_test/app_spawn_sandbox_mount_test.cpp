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
class AppSpawnSandboxMountTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static inline std::tuple<AppSpawnMgr *, AppSpawnSandboxCfg *, AppSpawningCtx *> TestCreateSandbox(int mode)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(mode);
    AppSpawningCtx *property = TestCreateAppSpawningCtx();
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    if (mgr != nullptr && property != nullptr && sandbox != nullptr) {
        OH_ListAddTail(&mgr->extData, &sandbox->extData.node);
        OH_ListRemove(&property->node);
        OH_ListInit(&property->node);
        OH_ListAddTail(&mgr->appSpawnQueue, &property->node);
        return std::make_tuple<>(mgr, sandbox, property);
    }
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
    return std::make_tuple<>(nullptr, nullptr, nullptr);
}
/**
 * @brief PrepareSandbox
 *
 */
HWTEST(AppSpawnSandboxMountTest, Sandbox_Stage_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);
    stub->flags &= ~STUB_NEED_CHECK;

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret, 0);

    sandbox->appFullMountEnable = 1;
    // spawn prepare process
    ret = AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    // unmount
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 准备阶段，保存permission中的gid到用户
 *
 */
HWTEST(AppSpawnSandboxMountTest, Sandbox_Stage_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxPermissionCfg());
    ASSERT_EQ(ret, 0);

    int index = GetPermissionIndexInQueue(&sandbox->permissionQueue, "ohos.permission.ACTIVATE_THEME_PACKAGE");
    ret = SetAppPermissionFlags(property, index);
    ASSERT_EQ(ret, 0);

    // spawn prepare process
    ret = AppSpawnHookExecute(STAGE_PARENT_PRE_FORK, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ASSERT_EQ(dacInfo->gidCount, APP_MAX_GIDS);

    // unmount
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 设置不执行沙盒
 *
 */
HWTEST(AppSpawnSandboxMountTest, Sandbox_Stage_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret, 0);

    ret = SetAppSpawnMsgFlag(property->message, TLV_MSG_FLAGS, APP_FLAGS_NO_SANDBOX);
    ASSERT_EQ(ret, 0);

    // spawn prepare process
    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 设置忽略沙盒执行结果
 *
 */
HWTEST(AppSpawnSandboxMountTest, Sandbox_Stage_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret, 0);

    ret = SetAppSpawnMsgFlag(property->message, TLV_MSG_FLAGS, APP_FLAGS_IGNORE_SANDBOX);
    ASSERT_EQ(ret, 0);

    // spawn prepare process
    ret = AppSpawnHookExecute(STAGE_CHILD_EXECUTE, 0, &mgr->content, &property->client);
    ASSERT_EQ(ret, 0);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 执行挂载，构造失败场景，测试失败
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el2/appdata";
    args.destinationPath = "/mnt/sandbox/100/app-root//data/app/el2/appdata";
    args.fsType = "sharefs";
    args.options = "support_overwrite=1";
    args.mountFlags = MS_NODEV | MS_RDONLY;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    MountArg mountArg = {};
    mountArg.originPath = "/data/app/el2/appdata";
    mountArg.destinationPath = "/mnt/sandbox/100/app-root//data/app/el2/appdata";
    mountArg.fsType = "sharefs";
    mountArg.options = "support_overwrite=1";
    mountArg.mountFlags = MS_NODEV;
    mountArg.mountSharedFlag = MS_SLAVE;
    int ret = SandboxMountPath(&mountArg);
    ASSERT_NE(stub->result, 0);
    ASSERT_NE(ret, 0);
    stub->flags &= ~STUB_NEED_CHECK;
}

HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_002, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_NE(stub != nullptr, 0);

    // set check point
    MountArg args = {};
    args.originPath = nullptr;
    args.destinationPath = "/mnt/sandbox/100/app-root//data/app/el2/appdata";
    args.fsType = "sharefs";
    args.options = "support_overwrite=1";
    args.mountFlags = MS_NODEV | MS_RDONLY;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    MountArg mountArg = {};
    mountArg.originPath = "/data/app/el2/appdata";
    mountArg.destinationPath = "/mnt/sandbox/100/app-root//data/app/el2/appdata";
    mountArg.fsType = "sharefs";
    mountArg.options = "support_overwrite=1";
    mountArg.mountFlags = MS_NODEV | MS_RDONLY;
    mountArg.mountSharedFlag = MS_SHARED;
    int ret = SandboxMountPath(&mountArg);
    ASSERT_NE(stub->result, 0);
    ASSERT_NE(ret, 0);
    stub->flags &= ~STUB_NEED_CHECK;
}

/**
 * @brief 沙盒执行，能执行到对应的检查项，并且检查通过
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_003, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    EXPECT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/storage/Users/100/appdata/el1";
    args.destinationPath = "/mnt/sandbox/100/app-root/storage/Users/100/appdata/el1";
    args.fsType = "sharefs";
    args.options = "support_overwrite=1";
    args.mountFlags = MS_NODEV | MS_RDONLY;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    ret = StagedMountSystemConst(sandbox, property, 0);
    EXPECT_EQ(ret == 0, 1);
    ASSERT_EQ(stub->result, 0);
    stub->flags &= ~STUB_NEED_CHECK;

    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief app-variable部分执行。让mount执行失败，但是不需要返回错误结果
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_004, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    EXPECT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/config";
    args.destinationPath = "/mnt/sandbox/100/com.example.myapplication/config";
    args.fsType = "sharefs";
    args.mountFlags = MS_NODEV | MS_RDONLY;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    // 执行失败, 但是不返回
    args.mountFlags = MS_NODEV;
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief app-variable部分执行。让mount执行失败，失败返回错误结果
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_005, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    EXPECT_EQ(ret == 0, 1);

    SandboxSection *section = GetSandboxSection(&sandbox->requiredQueue, "app-variable");
    ASSERT_EQ(section != nullptr, 1);
    PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(GetFirstSandboxMountNode(section));
    pathNode->checkErrorFlag = 1;  // 设置错误检查
    APPSPAWN_LOGV("pathNode %s => %s \n", pathNode->source, pathNode->target);

    // set check point
    MountArg args = {};
    args.originPath = "/config";
    args.destinationPath = "/mnt/sandbox/100/com.example.myapplication/config";
    args.fsType = "sharefs";
    args.mountFlags = MS_NODEV | MS_RDONLY;  // 当前条件走customizedFlags，这里设置为customizedFlags
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    // 执行失败, 返回错误
    args.mountFlags = MS_NODEV;
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_NE(ret, 0);
    ASSERT_NE(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief package name 执行
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_006, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxPackageNameCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/dev/fuse";
    args.destinationPath = "/mnt/sandbox/100/app-root/mnt/data/fuse";
    args.fsType = "fuse";
    args.mountFlags = MS_LAZYTIME | MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试package-name执行，执行失败
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_007, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxPackageNameCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/dev/fuse";
    args.destinationPath = "/home/axw/appspawn_ut/mnt/sandbox/100/com.example.myapplication/mnt/data/fuse";
    args.fsType = "fuse";
    args.mountFlags = MS_LAZYTIME | MS_NOATIME | MS_NODEV | MS_NOEXEC;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_NE(ret, 0);
    ASSERT_NE(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试permission 添加下appFullMountEnable 打开
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_008, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxPermissionCfg());
    ASSERT_EQ(ret == 0, 1);

    // set permission flags
    int index = GetPermissionIndexInQueue(&sandbox->permissionQueue, "ohos.permission.FILE_ACCESS_MANAGER");
    SetAppPermissionFlags(property, index);

    // set check point
    MountArg args = {};
    args.originPath = "/config--1";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/app/el1/currentUser/"
        "database/com.example.myapplication_100";
    // permission 下，fstype使用default
    // "sharefs"
    args.mountFlags = MS_BIND | MS_REC;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = 0;
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);  // do not check result
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试permission 添加下appFullMountEnable 打开，执行失败
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_mount_007, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxPermissionCfg());
    ASSERT_EQ(ret == 0, 1);

    // set permission flags
    int index = GetPermissionIndexInQueue(&sandbox->permissionQueue, "ohos.permission.FILE_ACCESS_MANAGER");
    SetAppPermissionFlags(property, index);

    // set check point
    MountArg args = {};
    args.originPath = "/config--1";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/app/el1/currentUser/"
        "database/com.example.myapplication_100";
    args.fsType = "sharefs";
    args.mountFlags = MS_RDONLY;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_NE(ret, 0);
    ASSERT_NE(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-config部分执行，测试每一种模版结果是否正确
 *  测试 shared
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Category_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/lib";
    args.destinationPath = "/mnt/sandbox/100/app-root/lib";
    args.fsType = nullptr;
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SHARED;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    ret = StagedMountSystemConst(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-config部分执行，测试每一种模版结果是否正确
 *  测试 rdonly
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Category_002, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/lib1";
    args.destinationPath = "/mnt/sandbox/100/app-root/lib1";
    args.fsType = nullptr;
    args.mountFlags = MS_NODEV | MS_RDONLY;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    ret = StagedMountSystemConst(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-config部分执行，测试每一种模版结果是否正确
 *  测试 epfs
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Category_003, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "none";
    args.destinationPath = "/mnt/sandbox/100/app-root/storage/cloud/epfs";
    args.fsType = "epfs";
    args.mountFlags = MS_NODEV;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);

    ret = StagedMountSystemConst(sandbox, property, 0);
    ASSERT_EQ(ret == 0, 1);
    ASSERT_EQ(stub->result, 0);
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-config部分执行，测试每一种模版结果是否正确
 *  测试 fuse
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Category_004, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/dev/fuse";
    args.destinationPath = "/mnt/sandbox/100/app-root/mnt/data/fuse";
    args.fsType = "fuse";
    args.mountFlags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_LAZYTIME;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = StagedMountSystemConst(sandbox, property, 0);
    ASSERT_EQ(ret == 0, 1);
    ASSERT_EQ(stub->result, 0);
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试unshare前的执行，not-exist时，节点不存在，执行dep的挂载
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_001, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el5/100";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el5";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SHARED;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试unshare前的执行，not-exist时，节点存在，不执行dep的挂载
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_002, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el6/100";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el6";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SHARED;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试unshare前的执行，always时，执行dep的挂载
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_003, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/e20/100/base";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/e20";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SHARED;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = 0;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 测试unshare后执行，一次挂载时，使用sandbox-path
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_004, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/e15/100/base/com.example.myapplication";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/e15/base";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = 0;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-const，一次挂载时，使用sandbox-path
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_005, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/e20/100/base/com.example.myapplication";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/e20/base";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = StagedMountSystemConst(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);
    AppSpawnMsgDacInfo *dacInfo = reinterpret_cast<AppSpawnMsgDacInfo *>(GetAppProperty(property, TLV_DAC_INFO));
    ASSERT_EQ(dacInfo != nullptr, 1);
    ret = UnmountSandboxConfigs(sandbox, "system-const", dacInfo->uid, GetProcessName(property));
    ASSERT_EQ(ret == 0, 1);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief system-const，二次挂载时，使用src-path
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Sandbox_Deps_006, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxCommonCfg());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/e20/100/base/com.example.myapplication";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/app/e20/100/base";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    SandboxContext *context = TestGetSandboxContext(property, 0);
    ASSERT_EQ(context != nullptr, 1);
    uint32_t operation = (1 << MOUNT_PATH_OP_REPLACE_BY_SRC); // 二挂载时，使用src-path
    SandboxSection *section = GetSandboxSection(&sandbox->requiredQueue, "system-const");
    if (section != NULL) {
        ret = MountSandboxConfig(context, sandbox, section, operation);
    }
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    DeleteSandboxContext(context);
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

static const std::string g_createOnDemandConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"ON\" \
    }, \
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
            }], \
            \"symbol-links\" : [] \
        } \
    } \
}";
/**
 * @brief create create-on-demand
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_020, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, g_createOnDemandConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/appspawn_ut/config";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/appspawn_ut/config";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

static const std::string g_mountFileConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"ON\" \
    }, \
    \"required\":{ \
        \"app-variable\":{ \
            \"mount-files\" : [{ \
                \"src-path\" : \"/system/lib/ld-musl-arm.so.1\", \
                \"sandbox-path\" : \"/data/appspawn_ut/lib/ld-musl-arm.so.1\" \
            }], \
            \"symbol-links\" : [] \
        } \
    } \
}";

/**
 * @brief mount file
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_021, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, g_mountFileConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/system/lib/ld-musl-arm.so.1";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/appspawn_ut/lib/ld-musl-arm.so.1";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief mount spawn flags APP_FLAGS_BACKUP_EXTENSION
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_022, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxspawnFlagsCfg());
    ASSERT_EQ(ret == 0, 1);
    ret = SetAppSpawnMsgFlag(property->message, TLV_MSG_FLAGS, APP_FLAGS_BACKUP_EXTENSION);
    ASSERT_EQ(ret, 0);

    // set check point
    MountArg args = {};
    std::string originPath = "/data/service/el1/100/backup/bundles/";
    originPath += GetBundleName(property);
    args.originPath = originPath.c_str();
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el1/backup";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief mount spawn flags APP_FLAGS_DLP_MANAGER
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_023, TestSize.Level0)
{
    AppSpawnTestHelper *helper = GetAppSpawnTestHelper();
    ASSERT_EQ(helper != nullptr, 1);
    helper->SetProcessName("com.ohos.dlpmanager");
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxspawnFlagsCfg());
    ASSERT_EQ(ret == 0, 1);
    ret = SetAppSpawnMsgFlag(property->message, TLV_MSG_FLAGS, APP_FLAGS_DLP_MANAGER);
    ASSERT_EQ(ret, 0);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el1/bundle/public/";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/bundles/";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief mount spawn flags APP_FLAGS_DLP_MANAGER for wps
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_024, TestSize.Level0)
{
    AppSpawnTestHelper *helper = GetAppSpawnTestHelper();
    ASSERT_EQ(helper != nullptr, 1);
    helper->SetProcessName("com.ohos.dlpmanager.wps");
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, GetSandboxspawnFlagsCfg());
    ASSERT_EQ(ret == 0, 1);
    ret = SetAppSpawnMsgFlag(property->message, TLV_MSG_FLAGS, APP_FLAGS_DLP_MANAGER);
    ASSERT_EQ(ret, 0);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el1/100/database/com.ohos.dlpmanager.wps";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/storage/el1/database";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = 0; // wps 下，这种配置无效，不执行，不检查

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

static const std::string g_aplCheckConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"ON\" \
    }, \
    \"required\":{ \
        \"app-variable\":{ \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"app-apl-name\" : \"system_core\", \
                \"check-action-status\": \"true\" \
            }], \
            \"symbol-links\" : [] \
        } \
    } \
}";

/**
 * @brief mount file, apl check
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_025, TestSize.Level0)
{
    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, g_aplCheckConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el1/bundle/public/";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/bundles/";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0); // 不检查执行结果

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief apl 不一样，执行
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_026, TestSize.Level0)
{
    AppSpawnTestHelper *helper = GetAppSpawnTestHelper();
    ASSERT_EQ(helper != nullptr, 1);
    helper->SetTestApl("normal");

    StubNode *stub = GetStubNode(STUB_MOUNT);
    ASSERT_EQ(stub != nullptr, 1);

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, g_aplCheckConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    MountArg args = {};
    args.originPath = "/data/app/el1/bundle/public/";
    args.destinationPath = "/mnt/sandbox/100/app-root/data/bundles/";
    args.mountFlags = MS_BIND | MS_REC;
    args.mountSharedFlag = MS_SLAVE;
    stub->flags = STUB_NEED_CHECK;
    stub->arg = reinterpret_cast<void *>(&args);
    stub->result = -1;

    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(stub->result, 0);

    // clear env
    stub->flags &= ~STUB_NEED_CHECK;
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief symlink fail
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_027, TestSize.Level0)
{
    static const std::string symlinkFailConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
            \"top-sandbox-switch\": \"ON\" \
        }, \
        \"required\":{ \
            \"app-variable\":{ \
                \"symbol-links\" : [{ \
                    \"target-name\" : \"/system/etc2222\", \
                    \"link-name\" : \"/appspawn_ut/etc\", \
                    \"check-action-status\": \"true\" \
                }], \
                \"symbol-links\" : [] \
            } \
        } \
    }";
    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, symlinkFailConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_NE(ret, 0);

    // clear env
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief symlink fail
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_028, TestSize.Level0)
{
    static const std::string symlinkFailConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
            \"top-sandbox-switch\": \"ON\" \
        }, \
        \"required\":{ \
            \"app-variable\":{ \
                \"symbol-links\" : [{ \
                    \"target-name\" : \"/system/etc\", \
                    \"link-name\" : \"/appspawn_ut/etc\" \
                }], \
                \"symbol-links\" : [] \
            } \
        } \
    }";

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, symlinkFailConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    // set check point
    ret = MountSandboxConfigs(sandbox, property, 0);
    ASSERT_EQ(ret, 0);

    // clear env
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief 设置symlink不执行
 *
 */
HWTEST(AppSpawnSandboxMountTest, App_Spawn_Mount_029, TestSize.Level0)
{
    static const std::string symlinkConfig = "{ \
        \"global\": { \
            \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
            \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
            \"top-sandbox-switch\": \"OFF\" \
        }, \
        \"required\":{ \
            \"app-variable\":{ \
                \"symbol-links\" : [{ \
                    \"target-name\" : \"/system/etc\", \
                    \"link-name\" : \"/appspawn_ut/etc\" \
                }], \
                \"symbol-links\" : [] \
            } \
        } \
    }";

    AppSpawnMgr *mgr = nullptr;
    AppSpawnSandboxCfg *sandbox = nullptr;
    AppSpawningCtx *property = nullptr;
    std::tie(mgr, sandbox, property) = TestCreateSandbox(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);
    ASSERT_EQ(property != nullptr, 1);
    ASSERT_EQ(sandbox != nullptr, 1);

    sandbox->appFullMountEnable = 1;
    int ret = TestParseAppSandboxConfig(sandbox, symlinkConfig.c_str());
    ASSERT_EQ(ret == 0, 1);

    SandboxContext *context = TestGetSandboxContext(property, 0);
    ASSERT_EQ(context != nullptr, 1);
    context->sandboxSwitch = 0;
    uint32_t operation = (1 << MOUNT_PATH_OP_REPLACE_BY_SRC);
    SandboxSection *section = GetSandboxSection(&sandbox->requiredQueue, "app-variable");
    if (section != NULL) {
        ret = MountSandboxConfig(context, sandbox, section, operation);
    }
    ASSERT_EQ(ret, 0);

    // clear env
    DeleteSandboxContext(context);
    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}
}  // namespace OHOS
