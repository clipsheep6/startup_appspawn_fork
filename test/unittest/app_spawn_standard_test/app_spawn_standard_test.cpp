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
#include <string>
#include <cerrno>

#include "securec.h"
#include "appspawn_adapter.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "json_utils.h"
#include "init_hashmap.h"
#include "loop_event.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppSpawn;
using nlohmann::json;

#ifdef __cplusplus
    extern "C" {
#endif
int OnConnection(const LoopHandle loopHandle, const TaskHandle server);
int AppInfoHashNodeCompare(const HashNode *node1, const HashNode *node2);
int AppInfoHashNodeFunction(const HashNode *node);
int AppInfoHashKeyFunction(const void *key);
void AppInfoHashNodeFree(const HashNode *node);
int TestHashKeyCompare(const HashNode *node1, const void *key);
void AddAppInfo(pid_t pid, const char *processName);
void RemoveAppInfo(pid_t pid);
void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen);
extern TaskHandle g_testClientHandle;
#ifdef __cplusplus
    }
#endif

namespace OHOS {
/*
static void RunChildProcessor(struct AppSpawnContent_ *content, AppSpawnClient *client)
{}
*/
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

static AppInfo *TestCreateHashNode(const char *value, int pid)
{
    AppInfo *node = (AppInfo *)malloc(sizeof(AppInfo) + strlen(value) + 1);
    if (node == nullptr) {
        return nullptr;
    }
    node->pid = pid;
    int ret = strcpy_s(node->name, strlen(value) + 1, value);
    if (ret != 0) {
        free(node);
        return nullptr;
    }
    return node;
}

class AppSpawnStandardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

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
    string longProcName = "App_Spawn_Standard_001";
    int64_t longProcNameLen = longProcName.length();
    int cold = 0;
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, cold);
    EXPECT_TRUE(content);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;
    content->initAppSpawn(content);
    content->runAppSpawn(content, 0, nullptr);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_001 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_002 start";
    string longProcName = "App_Spawn_Standard_002";
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
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    appSpawnContent->timer = NULL;
    appSpawnContent->content.runAppSpawn = NULL;

    AppSpawnProcessMsg(&appSpawnContent->content, &client->client, &pid);

    free(appSpawnContent);
    free(client);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_002 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_003 start";
    char longProcName[124] = "App_Spawn_Standard_003";
    int64_t longProcNameLen = 124; // 124 is str length
    AppSpawnClientExt* client = (AppSpawnClientExt*)malloc(sizeof(AppSpawnClientExt));
    client->client.id = 8;
    client->client.flags = 0;
    client->fd[0] = 100;
    client->fd[1] = 200;
    client->property.uid = 10000;
    client->property.gid = 1000;
    client->property.gidCount = 1;
    if (strcpy_s(client->property.processName, APP_LEN_PROC_NAME, "xxx.xxx.xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.bundleName, APP_LEN_BUNDLE_NAME, "xxx.xxx.xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.soPath, APP_LEN_SO_PATH, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    client->property.accessTokenId = 671201800;
    if (strcpy_s(client->property.apl, APP_APL_MAX_LEN, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.renderCmd, APP_RENDER_CMD_MAX_LEN, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }

    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", longProcName, longProcNameLen, 1);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;
    SetContentFunction(content);
    EXPECT_EQ(ForkChildProc(content, &client->client, 0), 0);
    EXPECT_NE(ForkChildProc(content, &client->client, -1), 0);

    content->clearEnvironment(content, &client->client);
    EXPECT_EQ(content->setProcessName(content, &client->client, (char *)longProcName, longProcNameLen), 0);

    EXPECT_EQ(content->setKeepCapabilities(content, &client->client), 0);

    EXPECT_EQ(content->setUidGid(content, &client->client), 0);

    EXPECT_EQ(content->setCapabilities(content, &client->client), 0);

    content->setAppSandbox(content, &client->client);

    content->setAppAccessToken(content, &client->client);

    EXPECT_EQ(content->coldStartApp(content, &client->client), 0);

    GTEST_LOG_(INFO) << "App_Spawn_Standard_003 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_004 start";
    AppSpawnClientExt* client = (AppSpawnClientExt*)malloc(sizeof(AppSpawnClientExt));
    client->client.id = 8;
    client->client.flags = 1;
    client->fd[0] = 100;
    client->fd[1] = 200;
    client->property.uid = 10000;
    client->property.gid = 1000;
    client->property.gidCount = 1;
    if (strcpy_s(client->property.processName, APP_LEN_PROC_NAME, "xxx.xxx.xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.bundleName, APP_LEN_BUNDLE_NAME, "xxx.xxx.xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.soPath, APP_LEN_SO_PATH, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    client->property.accessTokenId = 671201800;
    if (strcpy_s(client->property.apl, APP_APL_MAX_LEN, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    if (strcpy_s(client->property.renderCmd, APP_RENDER_CMD_MAX_LEN, "xxx") != 0) {
        GTEST_LOG_(INFO) << "strcpy_s failed";
    }
    client->property.flags = 0;

    char* argv[] = {const_cast<char*>("xxx"), const_cast<char*>("xxx")};
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
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    appSpawnContent->timer = NULL;
    appSpawnContent->content.runAppSpawn = runAppSpawn;
    AppSpawnProcessMsg(&appSpawnContent->content, &client->client, &pid);
    free(appSpawnContent);
    free(client);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_005 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_006 start";
    string longProcName = "App_Spawn_Standard_006";
    int64_t longProcNameLen = longProcName.length();
    int cold = 1;
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, cold);
    EXPECT_TRUE(content);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;

    content->runChildProcessor(content, nullptr);
    char tmp0[] = "/system/bin/appspawn";
    char tmp1[] = "cold-start";
    char tmp2[] = "1";
    char tmp3[] = "1:1:1:1:0:ohos.samples.ecg.default:ohos.samples.ecg:default:671201800:system_core:default";
    char * const argv[] = {tmp0, tmp1, tmp2, tmp3};

    AppSpawnColdRun(content, 4, argv);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_006 end";
}

/*
HWTEST(AppSpawnStandardTest, App_Spawn_Standard_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_007 start";
    RunChildProcessor(nullptr, nullptr);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_007 end";
}
*/
HWTEST(AppSpawnStandardTest, App_Spawn_Standard_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_008 start";
    string longProcName = "ohos.samples.ecg.default";
    int64_t longProcNameLen = longProcName.length();
    std::unique_ptr<AppSpawnClientExt> clientExt = std::make_unique<AppSpawnClientExt>();
    AppSpawnContent *content = AppSpawnCreateContent("AppSpawn", (char*)longProcName.c_str(), longProcNameLen, 1);
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;
    content->setAppSandbox = setAppSandbox;
    content->setKeepCapabilities = setKeepCapabilities;
    content->setProcessName = setProcessName;
    content->setUidGid = setUidGid;
    content->setFileDescriptors = setFileDescriptors;
    content->setCapabilities = setCapabilities;

    int ret = DoStartApp((AppSpawnContent_*)content, &clientExt->client, (char*)"", 0);
    EXPECT_EQ(ret, 0);

    free(content);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_008 end";
}

static int TestClient(int cold, AppOperateType code, const std::string &processName)
{
    char buffer[64] = {0}; // 64 buffer size
    AppSpawnContentExt *content = (AppSpawnContentExt *)AppSpawnCreateContent("AppSpawn", buffer, sizeof(buffer), cold);
    if (content == NULL) {
        return -1;
    }
    // create connection
    OnConnection(LE_GetDefaultLoop(), content->server);

    // process recv message
    if (g_testClientHandle == nullptr) {
        free(content);
        return -1;
    }

    AppParameter property = {};
    property.uid = 100;
    property.gid = 100;
    property.gidCount = 1;
    property.gidTable[0] = 101;
    (void)strcpy_s(property.processName, sizeof(property.processName), processName.c_str());
    (void)strcpy_s(property.bundleName, sizeof(property.bundleName), processName.c_str());
    (void)strcpy_s(property.renderCmd, sizeof(property.renderCmd), processName.c_str());
    (void)strcpy_s(property.soPath, sizeof(property.soPath), processName.c_str());
    (void)strcpy_s(property.apl, sizeof(property.apl), "system_core");
    property.flags = 0;
    property.code = code;
    property.accessTokenId = 0;
    OnReceiveRequest(g_testClientHandle, (const uint8_t *)&property, sizeof(property));
    LE_CloseTask(LE_GetDefaultLoop(), g_testClientHandle);
    free(content);
    return 0;
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_009 start";
    int ret = TestClient(0, DEFAULT, "ohos.test.testapp");
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_009 end";
}

HWTEST(AppSpawnStandardTest, App_Spawn_Standard_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "App_Spawn_Standard_010 start";
    const char *str1 = "Test hash map node 1";
    const char *str2 = "Test hash map node 2";
    AppInfo *node1 = TestCreateHashNode(str1, 11);
    AppInfo *node2 = TestCreateHashNode(str2, 12);

    AppInfoHashNodeCompare((const HashNode *)node1, (const HashNode *)node2);
    int value = 13;
    TestHashKeyCompare((const HashNode *)node1, &value);
    AppInfoHashNodeFunction((const HashNode *)node1);
    AppInfoHashKeyFunction(&value);
    AppInfoHashNodeFree((const HashNode *)node1);
    AppInfoHashNodeFree((const HashNode *)node2);
    GTEST_LOG_(INFO) << "App_Spawn_Standard_010 end";
}
} // namespace OHOS
