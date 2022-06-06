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
#include <memory>
#include <gtest/gtest.h>
#include <cstring>
#include <cerrno>

// redefine private and protected since testcase need to invoke and test private function
#define private public
#define protected public
#include "appspawn_service.h"
#undef private
#undef protected

#include "securec.h"
#include "appspawn_adapter.h"
#include "appspawn_server.h"

using namespace testing;
using namespace testing::ext;

#ifdef __cplusplus
    extern "C" {
#endif
    int OnConnection(const LoopHandle loopHandle, const TaskHandle server);
    void AppSpawnRun(AppSpawnContent *content, int argc, char *const argv[]);
#ifdef __cplusplus
    }
#endif

namespace OHOS {
static void RunChildProcessor(struct AppSpawnContent_ *content, AppSpawnClient *client)
{}

static void initAppSpawn(struct AppSpawnContent_ *content)
{}

static void runAppSpawn(struct AppSpawnContent_ *content, int argc, char *const argv[])
{}

static int setAppSandbox(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    return 0;
}

static int setKeepCapabilities(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    return 0;
}

static int setFileDescriptors(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    return 0;
}

static int setProcessName(struct AppSpawnContent_ *content, AppSpawnClient *client,
    char *longProcName, uint32_t longProcNameLen)
{
    return 0;
}

static int setUidGid(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    return 0;
}

static int setCapabilities(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    return 0;
}

class AppSpawnStandardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
}

void AppSpawnStandardTest::SetUpTestCase()
{}

void AppSpawnStandardTest::TearDownTestCase()
{}

void AppSpawnStandardTest::SetUp()
{}

void AppSpawnStandardTest::TearDown()
{}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_001 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();
    int cold = 0;
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, cold);
    EXPECT_TRUE(content);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;
    AppSpawnRun(content, 0, nullptr);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_001 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_002 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();

    AppSpawnClientExt* client = (AppSpawnClientExt*)malloc(sizeof(AppSpawnClientExt));
    client->client.id = 1;
    client->client.flags = 1;
    if (strcpy_s(client->property.apl, APP_APL_MAX_LEN, "system_basic") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }

    pid_t pid = 0;
    AppSpawnContentExt* appSpawnContent = (AppSpawnContentExt*)malloc(sizeof(AppSpawnContentExt));
    EXPECT_TRUE(appSpawnContent);
    if (strcpy_s(appSpawnContent->content.longProcName, longProcNameLen, longProcName.c_str()) != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    appSpawnContent->timer = NULL;
    appSpawnContent->content.runAppSpawn = NULL;
    appSpawnContent->content.initAppSpawn = NULL;
    AppSpawnProcessMsg(&appSpawnContent->content, &client->client, &pid);
    free(appSpawnContent);
    free(client);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_002 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_003 start";
    char longProcName[124] = "ohos.samples.ecg.default";
    int64_t longProcNameLen = 124; // 124 is str length
    std::unique_ptr<AppSpawnClientExt> clientExt = std::make_unique<AppSpawnClientExt>();

    clientExt->client.id = 1;
    clientExt->client.flags = 0;
    clientExt->fd[0] = 123;
    clientExt->fd[1] = 456;
    clientExt->property.uid = 10002;
    clientExt->property.gid = 1000;
    clientExt->property.gidCount = 1;
    if (strcpy_s(clientExt->property.processName, APP_LEN_PROC_NAME, "com.ohos.settingsdata") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(clientExt->property.bundleName, APP_LEN_BUNDLE_NAME, "com.ohos.settingsdata") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(clientExt->property.soPath, APP_LEN_SO_PATH, "/test") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    clientExt->property.accessTokenId = 671201800;
    if (strcpy_s(clientExt->property.apl, APP_APL_MAX_LEN, "system_core") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(clientExt->property.renderCmd, APP_RENDER_CMD_MAX_LEN, "cmd_test") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    clientExt->property.flags = 0;
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", longProcName, longProcNameLen, 1);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;

    SetContentFunction(content);
    content->clearEnvironment(content, &clientExt->client);
    EXPECT_EQ(content->setProcessName(content, &clientExt->client, longProcName, longProcNameLen), 0);
    EXPECT_EQ(content->setKeepCapabilities(content, &clientExt->client), 0);
    EXPECT_EQ(content->setUidGid(content, &clientExt->client), 0);
    EXPECT_EQ(content->setCapabilities(content, &clientExt->client), 0);
    content->setAppSandbox(content, &clientExt->client);
    content->setAppAccessToken(content, &clientExt->client);
    EXPECT_EQ(content->coldStartApp(content, &clientExt->client), 0);

    int ret = ForkChildProc((AppSpawnContent_*)content, &clientExt->client, 0);
    EXPECT_EQ(ret, 0);
    ForkChildProc((AppSpawnContent_ *)content, &clientExt->client, -1);
    DoStartApp(content, &clientExt->client, longProcName, longProcNameLen);
    free(content);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_003 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_004 start";
    AppSpawnClientExt* client = (AppSpawnClientExt*)malloc(sizeof(AppSpawnClientExt));
    client->client.id = 8;
    client->client.flags = 1;
    client->fd[0] = 1;
    client->fd[1] = 2;
    client->property.uid = 10000;
    client->property.gid = 1000;
    client->property.gidCount = 1;
    if (strcpy_s(client->property.processName, APP_LEN_PROC_NAME, "ohos.samples.ecg") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.bundleName, APP_LEN_BUNDLE_NAME, "ohos.samples.ecg") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.soPath, APP_LEN_SO_PATH, "default") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    client->property.accessTokenId = 671201800;
    if (strcpy_s(client->property.apl, APP_APL_MAX_LEN, "system_core") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.renderCmd, APP_RENDER_CMD_MAX_LEN, "test4") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    client->property.flags = 0;

    char* argv[] = {const_cast<char*>("default"), const_cast<char*>("ohos.samples.ecg")};
    int argc = sizeof(argv)/sizeof(argv[0]);

    EXPECT_EQ(GetAppSpawnClientFromArg(argc, argv, client), -1);
    free(client);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_004 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_005 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();

    AppSpawnClientExt* client = (AppSpawnClientExt*)malloc(sizeof(AppSpawnClientExt));
    client->client.id = 20010013;
    client->client.flags = 0;
    if (strcpy_s(client->property.apl, APP_APL_MAX_LEN, "system_basic") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    pid_t pid = 100;
    AppSpawnContentExt* appSpawnContent = (AppSpawnContentExt*)malloc(sizeof(AppSpawnContentExt));
    EXPECT_TRUE(appSpawnContent);
    if (strcpy_s(appSpawnContent->content.longProcName, longProcNameLen, longProcName.c_str()) != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    appSpawnContent->timer = NULL;
    appSpawnContent->content.runAppSpawn = runAppSpawn;
    appSpawnContent->content.initAppSpawn = initAppSpawn;
    AppSpawnProcessMsg(&appSpawnContent->content, &client->client, &pid);
    free(appSpawnContent);
    free(client);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_005 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_006 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();
    int cold = 1;
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, cold);
    EXPECT_TRUE(content);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;

    char tmp0[] = "/system/bin/appspawn";
    char tmp1[] = "cold-start";
    char tmp2[] = "1";
    char tmp3[] = "1:1:1:1:0:ohos.samples.ecg.default:ohos.samples.ecg:default:671201800:system_core:default";
    char * const argv[] = {tmp0, tmp1, tmp2, tmp3};
    content->initAppSpawn(content);
    AppSpawnColdRun(content, 4, argv);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_006 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_007 start";
    RunChildProcessor(nullptr, nullptr);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_007 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_008 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();
    std::unique_ptr<AppSpawnClientExt> clientExt = std::make_unique<AppSpawnClientExt>();
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, 1);
    content->setAppSandbox = setAppSandbox;
    content->setKeepCapabilities = setKeepCapabilities;
    content->setProcessName = setProcessName;
    content->setUidGid = setUidGid;
    content->setFileDescriptors = setFileDescriptors;
    content->setCapabilities = setCapabilities;
    int ret = DoStartApp((AppSpawnContent_*)content, &clientExt->client, (char*)"", 0);
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_008 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_009 start";
    TaskHandle server = (TaskHandle)malloc(sizeof(TaskHandle));
    EXPECT_TRUE(server);
    int ret = OnConnection(nullptr, server);
    EXPECT_EQ(ret, -1);
    server->flags = 0;
    OnConnection(nullptr, server);
    server->flags = 1;
    OnConnection(nullptr, server);
    free(server);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_009 end";
}
} // namespace OHOS
