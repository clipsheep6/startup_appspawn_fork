/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_hook.h"
#include "appspawn_manager.h"
#include "appspawn_modulemgr.h"
#include "appspawn_permission.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "init_param.h"
#include "parameter.h"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static AppSpawnTestHelper g_testHelper;
class AppSpawnSandboxMgrTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static int HandleSplitString(const char *str, void *context)
{
    std::vector<std::string> *results = reinterpret_cast<std::vector<std::string> *>(context);
    results->push_back(std::string(str));
    return 0;
}

static int TestJsonUtilSplit(const char *args[], uint32_t argc, const std::string &input, const std::string &pattern)
{
    std::vector<std::string> results;
    StringSplit(input.c_str(), pattern.c_str(), reinterpret_cast<void *>(&results), HandleSplitString);
    if (argc != results.size()) {
        return -1;
    }
    for (size_t i = 0; i < argc; i++) {
        if (strcmp(args[i], results[i].c_str()) != 0) {
            return -1;
        }
    }
    return 0;
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_001, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR", "S_IWOTH", "S_IRWXU"};
    std::string cmd = "   S_IRUSR   S_IWOTH      S_IRWXU   ";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_002, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR", "S_IWOTH", "S_IRWXU"};
    std::string cmd = "S_IRUSR   S_IWOTH      S_IRWXU";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_003, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR", "S_IWOTH", "S_IRWXU"};
    std::string cmd = "  S_IRUSR   S_IWOTH      S_IRWXU";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_004, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR", "S_IWOTH", "S_IRWXU"};
    std::string cmd = "S_IRUSR   S_IWOTH      S_IRWXU  ";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_005, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR"};
    std::string cmd = "  S_IRUSR    ";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_006, TestSize.Level0)
{
    const char *args[] = {"S_IRUSR", "S_IWOTH", "S_IRWXU"};
    std::string cmd = "  S_IRUSR |  S_IWOTH    |  S_IRWXU  ";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, "|"), 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_JsonUtil_007, TestSize.Level0)
{
    const char *args[] = {"send", "--type", "2"};
    std::string cmd = "send --type 2 ";
    size_t size = sizeof(args) / sizeof(args[0]);
    ASSERT_EQ(TestJsonUtilSplit(args, size, cmd, " "), 0);
}

/**
 * @brief AppSpawnSandboxCfg
 *
 */
HWTEST(AppSpawnSandboxMgrTest, App_Spawn_AppSpawnSandboxCfg_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = GetAppSpawnSandbox(mgr);
    EXPECT_EQ(sandbox == nullptr, 1);

    sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    sandbox = GetAppSpawnSandbox(mgr);
    EXPECT_EQ(sandbox != nullptr, 1);

    // dump
    DumpAppSpawnSandboxCfg(sandbox);

    // delete
    DeleteAppSpawnSandbox(sandbox);
    // get none
    sandbox = GetAppSpawnSandbox(mgr);
    EXPECT_EQ(sandbox == nullptr, 1);
    DumpAppSpawnSandboxCfg(sandbox);

    DeleteAppSpawnMgr(mgr);
    sandbox = GetAppSpawnSandbox(nullptr);
    EXPECT_EQ(sandbox == nullptr, 1);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_AppSpawnSandboxCfg_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    // for appspawn
    int ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);
    ret = LoadAppSandboxConfig(sandbox, 0);  // 重复load
    EXPECT_EQ(ret, 0);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);

    ret = LoadAppSandboxConfig(nullptr, 0);
    EXPECT_NE(ret, 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_AppSpawnSandboxCfg_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);
    int ret = 0;
#ifdef APPSPAWN_SANDBOX_NEW
    // for nwebspawn
    ret = LoadAppSandboxConfig(sandbox, 1);
    EXPECT_EQ(ret, 0);
    ret = LoadAppSandboxConfig(sandbox, 1);  // 重复load
    EXPECT_EQ(ret, 0);
    ret = LoadAppSandboxConfig(sandbox, 2);  // 重复load
    EXPECT_EQ(ret, 0);
#else
    // for nwebspawn
    ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);
    ret = LoadAppSandboxConfig(sandbox, 0);  // 重复load
    EXPECT_EQ(ret, 0);
#endif
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);

    ret = LoadAppSandboxConfig(nullptr, 1);
    EXPECT_NE(ret, 0);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxSection_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    const uint32_t nameCount = 3;
    const uint32_t lenCount = 7;
    const char *inputName[nameCount] = {"test-001", nullptr, ""};
    const uint32_t inputDataLen[lenCount] = {
        0,
        sizeof(SandboxSection),
        sizeof(SandboxPackageNameNode),
        sizeof(SandboxFlagsNode),
        sizeof(SandboxNameGroupNode),
        sizeof(SandboxPermissionNode),
        sizeof(SandboxNameGroupNode) + 100
    };
    int result[lenCount] = {0};
    result[1] = 1;
    result[2] = 1;
    result[3] = 1;
    result[4] = 1;
    result[5] = 1;
    auto testFunc = [result](const char *name, uint32_t len, size_t nameIndex, size_t lenIndex) {
        for (size_t type = SANDBOX_TAG_PERMISSION; type <= SANDBOX_TAG_REQUIRED; type++) {
            SandboxSection *section = CreateSandboxSection(name, len, type);
            EXPECT_EQ(section != nullptr, nameIndex == 0 && result[lenIndex]);
            if (section) {
                EXPECT_EQ(GetSectionType(section), type);
                free(section->name);
                free(section);
            }
        }
    };
    for (size_t i = 0; i < nameCount; i++) {
        for (size_t j = 0; j < lenCount; j++) {
            testFunc(inputName[i], inputDataLen[j], i, j);
        }
    }
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxSection_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    const uint32_t nameCount = 3;
    const uint32_t lenCount = 7;
    const char *inputName[nameCount] = {"test-001", nullptr, ""};
    const uint32_t inputDataLen[lenCount] = {
        0,
        sizeof(SandboxSection),
        sizeof(SandboxPackageNameNode),
        sizeof(SandboxFlagsNode),
        sizeof(SandboxNameGroupNode),
        sizeof(SandboxPermissionNode),
        sizeof(SandboxNameGroupNode) + 100
    };
    for (size_t i = 0; i < nameCount; i++) {
        for (size_t j = 0; j < lenCount; j++) {
            SandboxSection *section = CreateSandboxSection(inputName[i], inputDataLen[j], 0);
            EXPECT_EQ(section == nullptr, 1);
            section = CreateSandboxSection(inputName[i], inputDataLen[j], 1);
            EXPECT_EQ(section == nullptr, 1);
            section = CreateSandboxSection(inputName[i], inputDataLen[j], SANDBOX_TAG_INVALID);
            EXPECT_EQ(section == nullptr, 1);
            section = CreateSandboxSection(inputName[i], inputDataLen[j], SANDBOX_TAG_INVALID + 1);
            EXPECT_EQ(section == nullptr, 1);
        }
    }
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxSection_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);
    // GetSandboxSection
    section = GetSandboxSection(&sandbox->requiredQueue, "system-const");
    EXPECT_EQ(section != nullptr, 1);
    // DeleteSandboxSection
    DeleteSandboxSection(section);

    // GetSandboxSection has deleted
    section = GetSandboxSection(&sandbox->requiredQueue, "system-const");
    EXPECT_EQ(section != nullptr, 0);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxSection_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    AddSandboxSection(nullptr, &sandbox->requiredQueue);
    AddSandboxSection(nullptr, nullptr);

    // GetSandboxSection
    SandboxSection *section = GetSandboxSection(nullptr, "system-const");
    EXPECT_EQ(section == nullptr, 1);
    section = GetSandboxSection(nullptr, "");
    EXPECT_EQ(section == nullptr, 1);
    section = GetSandboxSection(nullptr, nullptr);
    EXPECT_EQ(section == nullptr, 1);
    section = GetSandboxSection(&sandbox->requiredQueue, "");
    EXPECT_EQ(section == nullptr, 1);
    section = GetSandboxSection(&sandbox->requiredQueue, nullptr);
    EXPECT_EQ(section == nullptr, 1);

    // DeleteSandboxSection
    DeleteSandboxSection(section);
    DeleteSandboxSection(nullptr);

    // GetSandboxSection has deleted
    section = GetSandboxSection(&sandbox->requiredQueue, "system-const");
    EXPECT_EQ(section == nullptr, 1);

    EXPECT_EQ(GetSectionType(nullptr), SANDBOX_TAG_INVALID);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief SandboxMountNode
 *
 */
HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    const uint32_t lenCount = 4;
    const uint32_t inputDataLen[lenCount] = {
        0,
        sizeof(PathMountNode),
        sizeof(SymbolLinkNode),
        sizeof(SymbolLinkNode) + 100
    };
    int result[lenCount] = {0, 1, 1, 0};
    for (size_t i = 0; i < lenCount; i++) {
        for (size_t j = 0; j < SANDBOX_TAG_INVALID; j++) {
            SandboxMountNode *path = CreateSandboxMountNode(inputDataLen[i], j);
            EXPECT_EQ(path != nullptr, result[i]);
            if (path) {
                free(path);
            }
        }
    }

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    SandboxMountNode *path = CreateSandboxMountNode(sizeof(PathMountNode), SANDBOX_TAG_MOUNT_PATH);
    EXPECT_EQ(path != nullptr, 1);
    AddSandboxMountNode(path, section);

    path = GetFirstSandboxMountNode(section);
    EXPECT_EQ(path != nullptr, 1);
    DeleteSandboxMountNode(path);
    path = GetFirstSandboxMountNode(section);
    EXPECT_EQ(path == nullptr, 1);

    path = GetFirstSandboxMountNode(nullptr);
    EXPECT_EQ(path == nullptr, 1);
    DeleteSandboxMountNode(nullptr);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    SandboxMountNode *path = CreateSandboxMountNode(sizeof(PathMountNode), SANDBOX_TAG_MOUNT_PATH);
    EXPECT_EQ(path != nullptr, 1);
    PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(path);
    const char *testPath = "xxx/xxx/xxx";
    pathNode->source = strdup(testPath);
    pathNode->target = strdup(testPath);
    AddSandboxMountNode(path, section);

    pathNode = GetPathMountNode(section, SANDBOX_TAG_MOUNT_PATH, testPath, testPath);
    EXPECT_EQ(pathNode != nullptr, 1);

    // 异常
    for (size_t j = 0; j < SANDBOX_TAG_INVALID; j++) {
        pathNode = GetPathMountNode(section, j, testPath, testPath);
        EXPECT_EQ(pathNode != nullptr, j == SANDBOX_TAG_MOUNT_PATH);
        pathNode = GetPathMountNode(section, j, nullptr, testPath);
        EXPECT_EQ(pathNode != nullptr, 0);
        pathNode = GetPathMountNode(section, j, nullptr, nullptr);
        EXPECT_EQ(pathNode != nullptr, 0);
        pathNode = GetPathMountNode(section, j, testPath, nullptr);
        EXPECT_EQ(pathNode != nullptr, 0);

        EXPECT_EQ(pathNode != nullptr, 0);
        pathNode = GetPathMountNode(nullptr, j, nullptr, testPath);
        EXPECT_EQ(pathNode != nullptr, 0);
        pathNode = GetPathMountNode(nullptr, j, nullptr, nullptr);
        EXPECT_EQ(pathNode != nullptr, 0);
        pathNode = GetPathMountNode(nullptr, j, testPath, nullptr);
        EXPECT_EQ(pathNode != nullptr, 0);
    }

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_004, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    SandboxMountNode *path = CreateSandboxMountNode(sizeof(SymbolLinkNode), SANDBOX_TAG_SYMLINK);
    EXPECT_EQ(path != nullptr, 1);
    SymbolLinkNode *pathNode = reinterpret_cast<SymbolLinkNode *>(path);
    const char *testPath = "xxx/xxx/xxx";
    pathNode->linkName = strdup(testPath);
    pathNode->target = strdup(testPath);
    AddSandboxMountNode(path, section);

    pathNode = GetSymbolLinkNode(section, testPath, testPath);
    EXPECT_EQ(pathNode != nullptr, 1);

    // 异常
    pathNode = GetSymbolLinkNode(section, testPath, testPath);
    EXPECT_EQ(pathNode != nullptr, 1);
    pathNode = GetSymbolLinkNode(section, nullptr, testPath);
    EXPECT_EQ(pathNode != nullptr, 0);
    pathNode = GetSymbolLinkNode(section, nullptr, nullptr);
    EXPECT_EQ(pathNode != nullptr, 0);
    pathNode = GetSymbolLinkNode(section, testPath, nullptr);
    EXPECT_EQ(pathNode != nullptr, 0);

    EXPECT_EQ(pathNode != nullptr, 0);
    pathNode = GetSymbolLinkNode(nullptr, nullptr, testPath);
    EXPECT_EQ(pathNode != nullptr, 0);
    pathNode = GetSymbolLinkNode(nullptr, nullptr, nullptr);
    EXPECT_EQ(pathNode != nullptr, 0);
    pathNode = GetSymbolLinkNode(nullptr, testPath, nullptr);
    EXPECT_EQ(pathNode != nullptr, 0);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_005, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_APP_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    SandboxMountNode *path = CreateSandboxMountNode(sizeof(SymbolLinkNode), SANDBOX_TAG_SYMLINK);
    EXPECT_EQ(path != nullptr, 1);
    path->type = SANDBOX_TAG_INVALID;
    AddSandboxMountNode(path, section);
    DumpAppSpawnSandboxCfg(sandbox);
    DeleteSandboxMountNode(path);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountNode_006, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxSection *section = CreateSandboxSection("system-const", sizeof(SandboxSection), SANDBOX_TAG_SYSTEM_CONST);
    EXPECT_EQ(section != nullptr, 1);
    AddSandboxSection(section, &sandbox->requiredQueue);

    SandboxMountNode *path = CreateSandboxMountNode(sizeof(PathMountNode), SANDBOX_TAG_MOUNT_PATH);
    EXPECT_EQ(path != nullptr, 1);
    PathMountNode *pathNode = reinterpret_cast<PathMountNode *>(path);
    const char *testPath = "xxx/xxx/xxx";
    pathNode->source = strdup(testPath);
    pathNode->target = strdup(testPath);
    AddSandboxMountNode(path, section);

    pathNode = GetPathMountNode(section, SANDBOX_TAG_MOUNT_PATH, testPath, testPath);
    EXPECT_EQ(pathNode != nullptr, 1);
    DumpMountPathMountNode(pathNode);
    pathNode->category = 100; // 100 test
    DumpMountPathMountNode(pathNode);

    pathNode->category = 1;
    pathNode->mountSharedFlag = 1;
    DumpMountPathMountNode(pathNode);
    pathNode->mountSharedFlag = 0;
    DumpMountPathMountNode(pathNode);

    DumpMountPathMountNode(nullptr);

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief mount
 *
 */
static AppSpawningCtx *TestCreateAppSpawningCtx()
{
    // get from buffer
    AppSpawnTestHelper testHelper;
    std::vector<uint8_t> buffer(1024 * 2);  // 1024 * 2  max buffer
    uint32_t msgLen = 0;
    int ret = testHelper.CreateSendMsg(buffer, MSG_APP_SPAWN, msgLen, {AppSpawnTestHelper::AddBaseTlv});
    EXPECT_EQ(0, ret);

    AppSpawnMsgNode *outMsg = nullptr;
    uint32_t msgRecvLen = 0;
    uint32_t reminder = 0;
    ret = GetAppSpawnMsgFromBuffer(buffer.data(), msgLen, &outMsg, &msgRecvLen, &reminder);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(msgLen, msgRecvLen);
    EXPECT_EQ(memcmp(buffer.data() + sizeof(AppSpawnMsg), outMsg->buffer, msgLen - sizeof(AppSpawnMsg)), 0);
    EXPECT_EQ(0, reminder);
    ret = DecodeAppSpawnMsg(outMsg);
    EXPECT_EQ(0, ret);
    AppSpawningCtx *appCtx = CreateAppSpawningCtx();
    EXPECT_EQ(appCtx != nullptr, 1);
    appCtx->message = outMsg;
    return appCtx;
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Mount_001, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);
    sandbox->rootPath = strdup("/mnt/sandbox/<currentUserId>/app-root");
    EXPECT_EQ(sandbox->rootPath != nullptr, 1);
    AppSpawningCtx *property = TestCreateAppSpawningCtx();
    EXPECT_EQ(property != nullptr, 1);

    // 只做异常测试，正常流程需要基于业务流进行测试
    const AppSpawningCtx *inputAppSpawningCtx[2] = {property, nullptr};
    const AppSpawnSandboxCfg *inputAppSpawnSandboxCfg[2] = {sandbox, nullptr};
    uint32_t inputSpawn[3] = {0, 1, 2};
    int ret = 0;
    for (uint32_t i = 0; i < 2; i++) {          // 2
        for (uint32_t j = 0; j < 2; j++) {      // 2
            for (uint32_t k = 0; k < 2; k++) {  // 2
                ret = MountSandboxConfigs(inputAppSpawnSandboxCfg[i], inputAppSpawningCtx[j], inputSpawn[k]);
                EXPECT_EQ(ret == 0, i == 0 && j == 0);
            }
        }
    }

    for (uint32_t i = 0; i < 2; i++) {          // 2
        for (uint32_t j = 0; j < 2; j++) {      // 2
            for (uint32_t k = 0; k < 2; k++) {  // 2
                ret = StagedMountSystemConst(inputAppSpawnSandboxCfg[i], inputAppSpawningCtx[j], inputSpawn[k]);
                EXPECT_EQ(ret == 0, i == 0 && j == 0);
            }
        }
    }

    DeleteAppSpawningCtx(property);
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Mount_002, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    SandboxContext context = {};
    // 只做异常测试，正常流程需要基于业务流进行测试
    const SandboxContext *inputContext[2] = {&context, nullptr};
    const AppSpawnSandboxCfg *inputAppSpawnSandboxCfg[2] = {sandbox, nullptr};

    int ret = 0;
    for (uint32_t i = 0; i < 2; i++) {      // 2
        for (uint32_t j = 0; j < 2; j++) {  // 2
            ret = StagedMountPreUnShare(inputContext[i], inputAppSpawnSandboxCfg[j]);
            EXPECT_EQ(ret == 0, i == 0 && j == 0);
        }
    }

    for (uint32_t i = 0; i < 2; i++) {      // 2
        for (uint32_t j = 0; j < 2; j++) {  // 2
            ret = StagedMountPostUnshare(inputContext[i], inputAppSpawnSandboxCfg[j]);
            EXPECT_EQ(ret == 0, i == 0 && j == 0);
        }
    }

    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Mount_003, TestSize.Level0)
{
    AppSpawnMgr *mgr = CreateAppSpawnMgr(MODE_FOR_NWEB_SPAWN);
    EXPECT_EQ(mgr != nullptr, 1);

    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    sandbox->rootPath = strdup("/data/appspawn_ut/sandbox/");
    OH_ListAddTail(&mgr->extData, &sandbox->extData.node);

    // 只做异常测试，正常流程需要基于业务流进行测试
    const AppSpawnSandboxCfg *inputAppSpawnSandboxCfg[2] = {sandbox, nullptr};
    const char *inputName[2] = {"test", nullptr};

    for (uint32_t k = 0; k < 2; k++) {  // 2
        int ret = UnmountDepPaths(inputAppSpawnSandboxCfg[k], 0, nullptr);
        EXPECT_EQ(ret == 0, k == 0);
    }
    for (uint32_t i = 0; i < 2; i++) {      // 2
        for (uint32_t k = 0; k < 2; k++) {  // 2
            int ret = UnmountSandboxConfigs(inputAppSpawnSandboxCfg[k], inputName[i], 0, nullptr);
            EXPECT_EQ(ret == 0, k == 0 && i == 0);
        }
    }
    for (uint32_t i = 0; i < 2; i++) {      // 2
        for (uint32_t k = 0; k < 2; k++) {  // 2
            int ret = UnmountSandboxConfigs(inputAppSpawnSandboxCfg[k], inputName[i], 0, "test");
            EXPECT_EQ(ret == 0, k == 0 && i == 0);
        }
    }
    DeleteAppSpawnSandbox(sandbox);
    DeleteAppSpawnMgr(mgr);
}

/**
 * @brief SandboxMountPath
 *
 */
HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxMountPath_001, TestSize.Level0)
{
    MountArg arg = {};
    arg.originPath = "/data/";
    arg.destinationPath = "/data/appspawn/test";
    arg.mountSharedFlag = 1;

    int ret = SandboxMountPath(&arg);
    EXPECT_EQ(ret, 0);
    ret = SandboxMountPath(&arg);
    EXPECT_EQ(ret, 0);
    arg.destinationPath = nullptr;
    ret = SandboxMountPath(&arg);
    EXPECT_NE(ret, 0);
    arg.originPath = nullptr;
    ret = SandboxMountPath(&arg);
    EXPECT_NE(ret, 0);
    ret = SandboxMountPath(nullptr);
    EXPECT_NE(ret, 0);
    arg.mountSharedFlag = -1;
    arg.originPath = "/data/";
    arg.destinationPath = "/data/appspawn/test";
    ret = SandboxMountPath(&arg);
    EXPECT_EQ(ret, 0);
}

/**
 * @brief AddVariableReplaceHandler
 *
 */
static int TestReplaceVarHandler(const SandboxContext *context,
    const char *buffer, uint32_t bufferLen, uint32_t *realLen, const VarExtraData *extraData)
{
    return 0;
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_AddVariableReplaceHandler_001, TestSize.Level0)
{
    int ret = AddVariableReplaceHandler(nullptr, nullptr);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);
    ret = AddVariableReplaceHandler("xxx", nullptr);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);
    ret = AddVariableReplaceHandler(nullptr, TestReplaceVarHandler);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);

    ret = AddVariableReplaceHandler("global", TestReplaceVarHandler);
    EXPECT_EQ(ret, 0);
    ret = AddVariableReplaceHandler("global", TestReplaceVarHandler);
    EXPECT_EQ(ret, APPSPAWN_NODE_EXIST);

    ret = AddVariableReplaceHandler("<Test-Var-005>", TestReplaceVarHandler);
    EXPECT_EQ(ret, 0);
}

/**
 * @brief RegisterExpandSandboxCfgHandler
 *
 */
static int TestProcessExpandSandboxCfg(const SandboxContext *context,
    const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    return 0;
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_RegisterExpandSandboxCfgHandler_001, TestSize.Level0)
{
    int ret = RegisterExpandSandboxCfgHandler(nullptr, 0, nullptr);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);
    ret = RegisterExpandSandboxCfgHandler("test", 0, nullptr);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);
    ret = RegisterExpandSandboxCfgHandler(nullptr, 0, TestProcessExpandSandboxCfg);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);

    ret = RegisterExpandSandboxCfgHandler("test-001", 0, TestProcessExpandSandboxCfg);
    EXPECT_EQ(ret, 0);
    ret = RegisterExpandSandboxCfgHandler("test-001", 0, TestProcessExpandSandboxCfg);
    EXPECT_EQ(ret, APPSPAWN_NODE_EXIST);
    ret = RegisterExpandSandboxCfgHandler("test-001", -1, TestProcessExpandSandboxCfg);
    EXPECT_EQ(ret, APPSPAWN_NODE_EXIST);
}

/**
 * @brief permission test
 *
 */
HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_001, TestSize.Level0)
{
    int ret = LoadPermission(CLIENT_FOR_APPSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_FOR_NWEBSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_MAX);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);

    int32_t max = GetPermissionMaxCount();
    EXPECT_EQ(max >= 0, 1);

    DeletePermission(CLIENT_FOR_APPSPAWN);
    DeletePermission(CLIENT_FOR_NWEBSPAWN);
    DeletePermission(CLIENT_MAX);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_002, TestSize.Level0)
{
    int ret = LoadPermission(CLIENT_FOR_APPSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_FOR_NWEBSPAWN);
    EXPECT_EQ(ret, 0);

    int32_t max = GetPermissionMaxCount();
    EXPECT_EQ(max >= 0, 1);

    AppSpawnClientHandle clientHandle;
    ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);

    max = GetMaxPermissionIndex(clientHandle);
    int32_t index = GetPermissionIndex(clientHandle, "ohos.permission.ACCESS_BUNDLE_DIR");
    EXPECT_EQ(index >= 0, 1);
    EXPECT_EQ(index < max, 1);

    const char *permission = GetPermissionByIndex(clientHandle, index);
    EXPECT_EQ(permission != nullptr, 1);
    EXPECT_EQ(strcmp(permission, "ohos.permission.ACCESS_BUNDLE_DIR") == 0, 1);
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_003, TestSize.Level0)
{
    int ret = LoadPermission(CLIENT_FOR_APPSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_FOR_NWEBSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_MAX);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);

    int32_t max = GetPermissionMaxCount();
    EXPECT_EQ(max >= 0, 1);

    AppSpawnClientHandle clientHandle;
    ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);

#ifndef APPSPAWN_SANDBOX_NEW
    max = GetMaxPermissionIndex(clientHandle);
    int32_t index = GetPermissionIndex(clientHandle, "ohos.permission.ACCESS_BUNDLE_DIR");
    EXPECT_EQ(index >= 0, 1);
    EXPECT_EQ(max >= index, 1);

    const char *permission = GetPermissionByIndex(clientHandle, index);
    EXPECT_EQ(permission != nullptr, 1);
    EXPECT_EQ(strcmp(permission, "ohos.permission.ACCESS_BUNDLE_DIR") == 0, 1);
#else
    // nweb no permission, so max = 0
    max = GetMaxPermissionIndex(clientHandle);
    EXPECT_EQ(max, 0);
#endif
    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_004, TestSize.Level0)
{
    int ret = LoadPermission(CLIENT_FOR_APPSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_FOR_NWEBSPAWN);
    EXPECT_EQ(ret, 0);
    ret = LoadPermission(CLIENT_MAX);
    EXPECT_EQ(ret, APPSPAWN_ARG_INVALID);

    int32_t max = GetPermissionMaxCount();
    EXPECT_EQ(max >= 0, 1);

    AppSpawnClientHandle clientHandle;
    ret = AppSpawnClientInit(NWEBSPAWN_SERVER_NAME, &clientHandle);
    EXPECT_EQ(ret, 0);

    max = GetMaxPermissionIndex(nullptr);
    EXPECT_EQ(max >= 0, 1);

    int32_t index = GetPermissionIndex(clientHandle, nullptr);
    EXPECT_EQ(index, INVALID_PERMISSION_INDEX);
    index = GetPermissionIndex(nullptr, "ohos.permission.ACCESS_BUNDLE_DIR");
    EXPECT_EQ(max >= index, 1);
    const char *permission = GetPermissionByIndex(clientHandle, INVALID_PERMISSION_INDEX);
    EXPECT_EQ(permission == nullptr, 1);

    AppSpawnClientDestroy(clientHandle);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_005, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);

    ret = AddSandboxPermissionNode("com.permission.test001", &sandbox->permissionQueue);
    EXPECT_EQ(ret, 0);
    ret = PermissionRenumber(&sandbox->permissionQueue);
    EXPECT_EQ(ret > 0, 1);

    ret = GetPermissionIndexInQueue(&sandbox->permissionQueue, "com.permission.test001");
    EXPECT_EQ(ret >= 0, 1);

    const SandboxPermissionNode *node = GetPermissionNodeInQueue(&sandbox->permissionQueue, "com.permission.test001");
    EXPECT_EQ(node != nullptr, 1);
    node = GetPermissionNodeInQueueByIndex(&sandbox->permissionQueue, 0);
    EXPECT_EQ(node != nullptr, 1);

    ret = DeleteSandboxPermissions(&sandbox->permissionQueue);
    EXPECT_EQ(ret, 0);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_006, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);

    ret = AddSandboxPermissionNode(nullptr, &sandbox->permissionQueue);
    EXPECT_NE(ret, 0);
    ret = PermissionRenumber(&sandbox->permissionQueue);
    EXPECT_EQ(ret > 0, 1);

    ret = GetPermissionIndexInQueue(&sandbox->permissionQueue, nullptr);
    EXPECT_EQ(ret, INVALID_PERMISSION_INDEX);

    const SandboxPermissionNode *node = GetPermissionNodeInQueue(&sandbox->permissionQueue, nullptr);
    EXPECT_EQ(node == nullptr, 1);
    node = GetPermissionNodeInQueueByIndex(&sandbox->permissionQueue, 0);
    EXPECT_EQ(node != nullptr, 1);

    ret = DeleteSandboxPermissions(&sandbox->permissionQueue);
    EXPECT_EQ(ret, 0);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Permission_007, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    int ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);

    ret = AddSandboxPermissionNode("com.permission.test001", nullptr);
    EXPECT_NE(ret, 0);
    ret = PermissionRenumber(nullptr);
    EXPECT_NE(ret, 0);

    ret = GetPermissionIndexInQueue(nullptr, "com.permission.test001");
    EXPECT_NE(ret, 0);

    const SandboxPermissionNode *node = GetPermissionNodeInQueue(nullptr, "com.permission.test001");
    EXPECT_EQ(node == nullptr, 1);
    node = GetPermissionNodeInQueueByIndex(nullptr, 0);
    EXPECT_EQ(node == nullptr, 1);

    ret = DeleteSandboxPermissions(nullptr);
    EXPECT_NE(ret, 0);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Parameter_001, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    sandbox->rootPath = strdup("/data/appspawn_ut/sandbox/");

    bool appFullMountEnable = false;
    char value[] = "false";
    int32_t ret = GetParameter("const.filemanager.full_mount.enable", "false", value, sizeof(value));
    if (ret > 0 && (strcmp(value, "true") == 0)) {
        appFullMountEnable = true;
    }
    ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(appFullMountEnable, sandbox->appFullMountEnable);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Parameter_002, TestSize.Level0)
{
    AppSpawnSandboxCfg *sandbox = CreateAppSpawnSandbox();
    EXPECT_EQ(sandbox != nullptr, 1);
    sandbox->rootPath = strdup("/data/appspawn_ut/sandbox/");

    bool pidNamespaceSupport = true;
    char buffer[10] = {0};
    uint32_t buffSize = sizeof(buffer);
    if (SystemGetParameter("const.sandbox.pidns.support", buffer, &buffSize) != 0) {
        pidNamespaceSupport = true;
    }
    if (!strcmp(buffer, "false")) {
        pidNamespaceSupport = false;
    }
    int ret = LoadAppSandboxConfig(sandbox, 0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pidNamespaceSupport, sandbox->pidNamespaceSupport);
    DeleteAppSpawnSandbox(sandbox);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_Category_001, TestSize.Level0)
{
    uint32_t category = GetMountCategory(nullptr);
    EXPECT_EQ(category, MOUNT_TMP_DEFAULT);
    category = GetMountCategory("");
    EXPECT_EQ(category, MOUNT_TMP_DEFAULT);

    category = GetMountCategory("default");
    EXPECT_EQ(category, MOUNT_TMP_DEFAULT);

    category = GetMountCategory("rdonly");
    EXPECT_EQ(category, MOUNT_TMP_RDONLY);
    category = GetMountCategory("epfs");
    EXPECT_EQ(category, MOUNT_TMP_EPFS);

    category = GetMountCategory("dac_override");
    EXPECT_EQ(category, MOUNT_TMP_DAC_OVERRIDE);
    category = GetMountCategory("fuse");
    EXPECT_EQ(category, MOUNT_TMP_FUSE);
    category = GetMountCategory("dlp_fuse");
    EXPECT_EQ(category, MOUNT_TMP_DLP_FUSE);
    category = GetMountCategory("shared");
    EXPECT_EQ(category, MOUNT_TMP_SHRED);

    const MountArgTemplate *temp = GetMountArgTemplate(MOUNT_TMP_SHRED);
    EXPECT_EQ(temp != nullptr, 1);
    EXPECT_EQ(strcmp(temp->name, "shared") == 0, 1);
    temp = GetMountArgTemplate(MOUNT_TMP_EPFS);
    EXPECT_EQ(temp != nullptr, 1);
    EXPECT_EQ(strcmp(temp->name, "epfs") == 0, 1);
    temp = GetMountArgTemplate(100); // 100 test
    EXPECT_EQ(temp == nullptr, 1);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_SandboxFlagInfo_001, TestSize.Level0)
{
    static const SandboxFlagInfo infos[] = {
        {"not-exists", (unsigned long)MOUNT_MODE_NOT_EXIST},
        {"always", (unsigned long)MOUNT_MODE_ALWAYS}
    };

    const SandboxFlagInfo *info = GetSandboxFlagInfo("no-exist", nullptr, 0);
    EXPECT_EQ(info == nullptr, 1);
    info = GetSandboxFlagInfo("not-exists", infos, 0);
    EXPECT_EQ(info == nullptr, 1);
    info = GetSandboxFlagInfo("not-exists", infos, 2);// 2 test
    EXPECT_EQ(info != nullptr, 1);
    EXPECT_EQ(strcmp(info->name, "not-exists") == 0, 1);
    info = GetSandboxFlagInfo("always", infos, 2); // 2 test
    EXPECT_EQ(info != nullptr, 1);
    EXPECT_EQ(strcmp(info->name, "always") == 0, 1);
    info = GetSandboxFlagInfo("ttestt", infos, 2); // 2 test
    EXPECT_EQ(info == nullptr, 1);
    info = GetSandboxFlagInfo(nullptr, infos, 2); // 2 test
    EXPECT_EQ(info == nullptr, 1);
}

HWTEST(AppSpawnSandboxMgrTest, App_Spawn_PathMode_001, TestSize.Level0)
{
    // S_IRUSR | S_IWOTH | S_IRWXU
    int mode = GetPathMode("S_IRUSR");
    EXPECT_EQ(mode, S_IRUSR);
    mode = GetPathMode("S_IRGRP");
    EXPECT_EQ(mode, S_IRGRP);
    mode = GetPathMode("S_IROTH");
    EXPECT_EQ(mode, S_IROTH);
    mode = GetPathMode("S_IRWXU");
    EXPECT_EQ(mode, S_IRWXU);

    mode = GetPathMode("S_IWUSR");
    EXPECT_EQ(mode, S_IWUSR);
    mode = GetPathMode("S_IWGRP");
    EXPECT_EQ(mode, S_IWGRP);
    mode = GetPathMode("S_IWOTH");
    EXPECT_EQ(mode, S_IWOTH);
    mode = GetPathMode("S_IRWXG");
    EXPECT_EQ(mode, S_IRWXG);

    mode = GetPathMode("S_IXUSR");
    EXPECT_EQ(mode, S_IXUSR);
    mode = GetPathMode("S_IXGRP");
    EXPECT_EQ(mode, S_IXGRP);
    mode = GetPathMode("S_IXOTH");
    EXPECT_EQ(mode, S_IXOTH);
    mode = GetPathMode("S_IRWXO");
    EXPECT_EQ(mode, S_IRWXO);
    mode = GetPathMode("");
    EXPECT_EQ(mode, 0);
    mode = GetPathMode(nullptr);
    EXPECT_EQ(mode, 0);
}
}  // namespace OHOS
