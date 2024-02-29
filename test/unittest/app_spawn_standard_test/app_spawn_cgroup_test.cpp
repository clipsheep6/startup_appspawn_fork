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

#include <sys/stat.h>
#include <sys/types.h>
#include <gtest/gtest.h>

#include "appspawn_modulemgr.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "parameter.h"
#include "le_timer.h"
#include "sandbox_utils.h"
#include "securec.h"

#include "app_spawn_test_helper.h"
#include "app_spawn_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using nlohmann::json;

namespace OHOS {
class AppSpawnCGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    AppSpawnTestHelper testHelper_;
};

void AppSpawnCGroupTest::SetUpTestCase()
{}

void AppSpawnCGroupTest::TearDownTestCase()
{}

void AppSpawnCGroupTest::SetUp()
{}

void AppSpawnCGroupTest::TearDown()
{}

static AppSpawnAppInfo *CreateTestAppInfo(const char *name)
{
    AppSpawnAppInfo *appInfo = reinterpret_cast<AppSpawnAppInfo *>(malloc(sizeof(AppSpawnAppInfo) + strlen(name) + 1));
    APPSPAWN_CHECK(appInfo != nullptr, return nullptr, "Failed to create appInfo");
    appInfo->pid = 33; // 33
    appInfo->uid = 200000 * 200 + 21; // 200000 200 21
    appInfo->max = 0;
    appInfo->exitStatus = 0;
    int ret = strcpy_s(appInfo->name, strlen(name) + 1, name);
    APPSPAWN_CHECK(ret == 0,
        free(appInfo); return nullptr, "Failed to strcpy process name");
    OH_ListInit(&appInfo->node);
    return appInfo;
}

static int GetTestCGroupFilePath(const AppSpawnAppInfo *appInfo, const char *fileName, char *path, bool create)
{
    int ret = GetCgroupPath(appInfo, path, PATH_MAX);
    APPSPAWN_CHECK(ret == 0, return errno, "Failed to get real path errno: %{public}d", errno);
    ret = strcat_s(path, PATH_MAX, fileName);
    APPSPAWN_CHECK(ret == 0, return errno, "Failed to strcat_s errno: %{public}d", errno);
    if (create) {
        FILE *file = fopen(path, "w");
        APPSPAWN_CHECK(file != NULL, return errno, "Create file fail %{public}s errno: %{public}d", path, errno);
        fclose(file);
    }
    return 0;
}

HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_001, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    const char name[] = "app-test-001";
    do {
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");
        char path[PATH_MAX] = {};
        ret = GetCgroupPath(appInfo, path, sizeof(path));
        APPSPAWN_CHECK(ret == 0, break, "Failed to get real path errno: %d", errno);
        APPSPAWN_CHECK(strstr(path, "200") != nullptr && strstr(path, "33") != nullptr && strstr(path, name) != nullptr,
            break, "Invalid path: %s", path);
        ret = 0;
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_002, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    FILE *file = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");

        ret = GetTestCGroupFilePath(appInfo, "cgroup.procs", path, true);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        // spawn prepare process
        AppChangeHookExecute(HOOK_APP_ADD, content, appInfo);

        // add success
        ret = GetTestCGroupFilePath(appInfo, "cgroup.procs", path, false);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        // write pid
        pid_t pids[] = { 100, 101, 102 };
        ret = WriteToFile(path, 0, pids, 3);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        file = fopen(path, "r");
        APPSPAWN_CHECK(file != NULL, ret = -1; break, "Open file fail %{public}s errno: %{public}d", path, errno);
        pid_t pid = 0;
        ret = -1;
        while (fscanf_s(file, "%d\n", &pid) == 1 && pid > 0) {
            APPSPAWN_LOGV("pid %d %d", pid, appInfo->pid);
            if (pid == appInfo->pid) {
                ret = 0;
                break;
            }
        }
        APPSPAWN_CHECK(ret == 0, break, "Error no pid write to path errno: %{public}d", errno);

    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    if (file) {
        fclose(file);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_003, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");

        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        AppChangeHookExecute(HOOK_APP_DIED, content, appInfo);
        ret = 0;
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_004, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    FILE *file = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");
        appInfo->pid = 44; // 44 test pid

        content = AppSpawnCreateContent(NWEBSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        AppChangeHookExecute(HOOK_APP_ADD, content, appInfo);
        // add success
        ret = GetCgroupPath(appInfo, path, sizeof(path));
        APPSPAWN_CHECK(ret == 0, break, "Failed to get real path errno: %{public}d", errno);
        ret = strcat_s(path, sizeof(path), "cgroup.procs");
        APPSPAWN_CHECK(ret == 0, break, "Failed to strcat_s errno: %{public}d", errno);
        //do not write for nwebspawn, so no file
        file = fopen(path, "r");
        APPSPAWN_CHECK(file == NULL, break, "Find file %{public}s ", path);
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    if (file) {
        fclose(file);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_005, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");

        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_NWEBSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        AppChangeHookExecute(HOOK_APP_DIED, content, appInfo);
        ret = 0;
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

/**
 * @brief in appspawn service, add and delete app
 *
 */
HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_006, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");

        ret = GetTestCGroupFilePath(appInfo, "cgroup.procs", path, true);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        AppChangeHookExecute(HOOK_APP_ADD, content, appInfo);

        // add success
        ret = GetTestCGroupFilePath(appInfo, "cgroup.procs", path, false);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        // write pid
        pid_t pids[] = { 100, 101, 102 };
        ret = WriteToFile(path, 0, pids, 3);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        AppSpawnAppInfo *appInfo2 = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo2 != nullptr, break, "Failed to create appInfo");
        OH_ListAddTail(&((AppSpawnContentExt *)content)->appMgr.appQueue, &appInfo2->node);
        appInfo2->pid = 102;
        AppChangeHookExecute(HOOK_APP_ADD, content, appInfo2);
        // died
        AppChangeHookExecute(HOOK_APP_DIED, content, appInfo);
        OH_ListRemove(&appInfo2->node);
        free(appInfo2);
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

/**
 * @brief in appspawn service, max write
 *
 */
HWTEST(AppSpawnCGroupTest, App_Spawn_CGroup_007, TestSize.Level0)
{
    int ret = -1;
    AppSpawnAppInfo *appInfo = nullptr;
    AppSpawnContent *content = nullptr;
    const char name[] = "app-test-001";
    do {
        char path[PATH_MAX] = {};
        appInfo = CreateTestAppInfo(name);
        APPSPAWN_CHECK(appInfo != nullptr, break, "Failed to create appInfo");
        appInfo->max = 10; // 10 test max
        ret = GetTestCGroupFilePath(appInfo, "pids.max", path, true);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, path, sizeof(path), MODE_FOR_APPSPAWN);
        APPSPAWN_CHECK_ONLY_EXPER(content != nullptr, break);
        AppChangeHookExecute(HOOK_APP_ADD, content, appInfo);

        // add success
        ret = GetTestCGroupFilePath(appInfo, "pids.max", path, false);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        FILE *file = fopen(path, "r");
        APPSPAWN_CHECK(file != NULL, ret = -1; break, "Open file fail %{public}s errno: %{public}d", path, errno);
        uint32_t max = 0;
        ret = -1;
        while (fscanf_s(file, "%d\n", &max) == 1 && max > 0) {
            APPSPAWN_LOGV("max %d %d", max, appInfo->max);
            if (max == appInfo->max) {
                ret = 0;
                break;
            }
        }
        fclose(file);
    } while (0);
    if (appInfo) {
        free(appInfo);
    }
    AppSpawnDestroyContent(content);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(ret, 0);
}

int32_t g_maxCount = 0;
static void WaitTimeout(const TimerHandle taskHandle, void *context)
{
    g_maxCount--;
    APPSPAWN_LOGV("WaitTimeout count %{public}d", g_maxCount);
    if (g_maxCount <= 0) {
        LE_StopLoop(LE_GetDefaultLoop());
    }
}

static void TimeoutCancel(const TimerHandle taskHandle, void *context)
{
    APPSPAWN_LOGV("TimeoutCancel count %{public}d", g_maxCount);
    LE_StopTimer(LE_GetDefaultLoop(), taskHandle);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_001, TestSize.Level0)
{
    int ret = -1;
    TimerHandle timer = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer, WaitTimeout, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer, 100, 10); // 100ms 10
    g_maxCount = 10;
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(g_maxCount == 0, 1);
    APPSPAWN_LOGV("App_Spawn_Timer_001 %{public}d end", g_maxCount);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_002, TestSize.Level0)
{
    int ret = -1;
    TimerHandle timer = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer, WaitTimeout, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer, 100, 10); // 100ms 10
    g_maxCount = 5; // 5 test
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(g_maxCount == 0, 1);
    APPSPAWN_LOGV("App_Spawn_Timer_002 %{public}d end", g_maxCount);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_003, TestSize.Level0)
{
    int ret = -1;
    TimerHandle timer1 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer1, WaitTimeout, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer1, 100, 10); // 100ms 10
    TimerHandle timer2 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer2, TimeoutCancel, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer2, 101, 10); // 100ms 10
    g_maxCount = 3; // 3 test
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(g_maxCount == 0, 1);
    APPSPAWN_LOGV("App_Spawn_Timer_002 %{public}d end", g_maxCount);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_004, TestSize.Level0)
{
    int ret = -1;
    TimerHandle timer1 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer1, WaitTimeout, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer1, 100, 0); // 100ms 10
    TimerHandle timer2 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer2, TimeoutCancel, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer2, 101, 0); // 100ms 10
    g_maxCount = 1;
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(g_maxCount == 0, 1);
    APPSPAWN_LOGV("App_Spawn_Timer_002 %{public}d end", g_maxCount);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_005, TestSize.Level0)
{
    int ret = -1;
    TimerHandle timer1 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer1, WaitTimeout, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer1, 100, 10); // 100ms 10
    TimerHandle timer2 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer2, TimeoutCancel, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer2, 101, 10); // 101ms 10
    TimerHandle timer3 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer3, TimeoutCancel, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer3, 98, 10); // 98ms 10
    TimerHandle timer4 = nullptr;
    LE_CreateTimer(LE_GetDefaultLoop(), &timer4, TimeoutCancel, nullptr);
    LE_StartTimer(LE_GetDefaultLoop(), timer4, 100, 10); // 100ms 10
    g_maxCount = 2;
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    ASSERT_EQ(g_maxCount == 0, 1);
    APPSPAWN_LOGV("App_Spawn_Timer_002 %{public}d end", g_maxCount);
}

static void TimeoutCancel2(const TimerHandle taskHandle, void *context)
{
    APPSPAWN_LOGV("TimeoutCancel count %{public}d", g_maxCount);
    CancelTimer(GetDefaultTimerMgr(LE_GetDefaultLoop()), taskHandle);
}

HWTEST(AppSpawnCGroupTest, App_Spawn_Timer_006, TestSize.Level0)
{
    TimerMgr timerMgr = GetDefaultTimerMgr(LE_GetDefaultLoop());
    ASSERT_EQ(timerMgr != nullptr, 1);
    TimerHandle timer1 = StartPeriodicTimer(timerMgr, 100, 10, WaitTimeout, nullptr);
    ASSERT_EQ(timer1 != nullptr, 1);
    TimerHandle timer2 = StartTimer(timerMgr, 101, TimeoutCancel2, nullptr);
    ASSERT_EQ(timer2 != nullptr, 1);
    TimerHandle timer3 = StartTimer(timerMgr, 98, TimeoutCancel2, nullptr);
    ASSERT_EQ(timer3 != nullptr, 1);
    TimerHandle timer4 = StartPeriodicTimer(timerMgr, 100, 10, TimeoutCancel, nullptr);
    ASSERT_EQ(timer4 != nullptr, 1);
    TimerHandle timer5 = StartPeriodicTimer(timerMgr, 100, 10, TimeoutCancel, nullptr);
    ASSERT_EQ(timer5 != nullptr, 1);
    CancelTimer(timerMgr, timer5);
    g_maxCount = 2;
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    APPSPAWN_LOGV("App_Spawn_Timer_002 %{public}d end", g_maxCount);
}
}  // namespace OHOS
