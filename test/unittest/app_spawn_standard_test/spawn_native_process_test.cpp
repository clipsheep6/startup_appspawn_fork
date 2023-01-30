/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <memory>

#include "client_socket.h"
#include "parameter.h"
#include "securec.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppSpawn;

class SpawnNativeProcessTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SpawnNativeProcessTest::SetUpTestCase()
{}

void SpawnNativeProcessTest::TearDownTestCase()
{}

void SpawnNativeProcessTest::SetUp()
{}

void SpawnNativeProcessTest::TearDown()
{}

/*
 * Feature: AppSpawn
 * Function: SpawnNativeProcessTest
 * SubFunction: SpawnSleep & ConnectSocket
 * FunctionPoints: create client socket
 * EnvConditions: mobile that can run ohos test framework
 * CaseDescription: Verify although the client socket created success but don't create the server socket, the connect
 * socket still fail.
 */
HWTEST(SpawnNativeProcessTest, SpawnNativeProcess_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SpawnNativeProcess_001 start now ...";

    std::unique_ptr<ClientSocket> appSpawnSocket = std::make_unique<ClientSocket>("AppSpawn");
    EXPECT_TRUE(appSpawnSocket);

    EXPECT_EQ(0, appSpawnSocket->CreateClient());
    EXPECT_EQ(0, appSpawnSocket->ConnectSocket());

    AppParameter request;
    memset_s((void *)(&request), sizeof(request), 0, sizeof(request));
    request.code = SPAWN_NATIVE_PROCESS;
    request.uid = 20010033;
    request.gid = 20010033;
    request.accessTokenId = 0x200a509d;
    request.accessTokenIdEx = 0x4832514205;
    request.allowInternet = 1;
    snprintf_s(request.apl, sizeof(request.apl), sizeof(request.apl) - 1, "normal");
    snprintf_s(request.processName, sizeof(request.processName), sizeof(request.processName) - 1, "ohos.samples.clock");
    snprintf_s(request.bundleName, sizeof(request.bundleName), sizeof(request.bundleName) - 1, "ohos.samples.clock");
    snprintf_s(request.soPath, sizeof(request.soPath), sizeof(request.soPath) - 1, "system/lib64/libmapleappkit.z.so");
    snprintf_s(request.renderCmd, sizeof(request.renderCmd), sizeof(request.renderCmd) - 1, "sleep 100");

    EXPECT_EQ(sizeof(request), appSpawnSocket->WriteSocketMessage((void *)(&request), sizeof(request)));

    int32_t len = 128;
    std::unique_ptr<uint8_t[]> buff = std::make_unique<uint8_t[]>(len);
    EXPECT_TRUE(appSpawnSocket->ReadSocketMessage(buff.get(), len));

    appSpawnSocket->CloseClient();

    GTEST_LOG_(INFO) << "SpawnNativeProcess_001 end";
}

HWTEST(SpawnNativeProcessTest, SpawnNativeProcess_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SpawnNativeProcess_002 start now ...";

    std::unique_ptr<ClientSocket> appSpawnSocket = std::make_unique<ClientSocket>("AppSpawn");
    EXPECT_TRUE(appSpawnSocket);

    EXPECT_EQ(0, appSpawnSocket->CreateClient());
    EXPECT_EQ(0, appSpawnSocket->ConnectSocket());

    AppParameter request;
    memset_s((void *)(&request), sizeof(request), 0, sizeof(request));
    request.code = SPAWN_NATIVE_PROCESS;
    request.uid = 20010033;
    request.gid = 20010033;
    request.accessTokenId = 0x200a509d;
    request.accessTokenIdEx = 0x4832514205;
    request.allowInternet = 1;
    snprintf_s(request.apl, sizeof(request.apl), sizeof(request.apl) - 1, "normal");
    snprintf_s(request.processName, sizeof(request.processName), sizeof(request.processName) - 1, "ohos.samples.clock");
    snprintf_s(request.bundleName, sizeof(request.bundleName), sizeof(request.bundleName) - 1, "ohos.samples.clock");
    snprintf_s(request.soPath, sizeof(request.soPath), sizeof(request.soPath) - 1, "system/lib64/libmapleappkit.z.so");
    snprintf_s(request.renderCmd, sizeof(request.renderCmd), sizeof(request.renderCmd) - 1, "ls -l /proc/ > /data/storage/el1/base/info.txt");

    EXPECT_EQ(sizeof(request), appSpawnSocket->WriteSocketMessage((void *)(&request), sizeof(request)));

    int32_t len = 128;
    std::unique_ptr<uint8_t[]> buff = std::make_unique<uint8_t[]>(len);
    EXPECT_TRUE(appSpawnSocket->ReadSocketMessage(buff.get(), len));

    appSpawnSocket->CloseClient();

    GTEST_LOG_(INFO) << "SpawnNativeProcess_002 end";
}

HWTEST(SpawnNativeProcessTest, SpawnNativeProcess_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SpawnNativeProcess_003 start now ...";

    std::unique_ptr<ClientSocket> appSpawnSocket = std::make_unique<ClientSocket>("AppSpawn");
    EXPECT_TRUE(appSpawnSocket);

    EXPECT_EQ(0, appSpawnSocket->CreateClient());
    EXPECT_EQ(0, appSpawnSocket->ConnectSocket());

    AppParameter request;
    memset_s((void *)(&request), sizeof(request), 0, sizeof(request));
    request.code = SPAWN_NATIVE_PROCESS;
    request.uid = 20010033;
    request.gid = 20010033;
    request.accessTokenId = 0x200a509d;
    request.accessTokenIdEx = 0x4832514205;
    request.allowInternet = 1;
    request.flags |= APP_NO_SANDBOX;
    snprintf_s(request.apl, sizeof(request.apl), sizeof(request.apl) - 1, "normal");
    snprintf_s(request.processName, sizeof(request.processName), sizeof(request.processName) - 1, "ohos.samples.clock");
    snprintf_s(request.bundleName, sizeof(request.bundleName), sizeof(request.bundleName) - 1, "ohos.samples.clock");
    snprintf_s(request.soPath, sizeof(request.soPath), sizeof(request.soPath) - 1, "system/lib64/libmapleappkit.z.so");
    snprintf_s(request.renderCmd, sizeof(request.renderCmd), sizeof(request.renderCmd) - 1, "ls -l /data/ > /data/app/el1/100/base/ohos.samples.clock/info-nosandbox.txt");

    EXPECT_EQ(sizeof(request), appSpawnSocket->WriteSocketMessage((void *)(&request), sizeof(request)));

    int32_t len = 128;
    std::unique_ptr<uint8_t[]> buff = std::make_unique<uint8_t[]>(len);
    EXPECT_TRUE(appSpawnSocket->ReadSocketMessage(buff.get(), len));

    appSpawnSocket->CloseClient();

    GTEST_LOG_(INFO) << "SpawnNativeProcess_002 end";
}
