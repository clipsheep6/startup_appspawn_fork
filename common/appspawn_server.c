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

#include "appspawn_server.h"
#include "appspawn_adapter.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdbool.h>

#include "syspara/parameter.h"
#include "securec.h"

#define DEFAULT_UMASK 0002
#define SANDBOX_STACK_SIZE (1024 * 1024 * 8)
#define APPSPAWN_CHECK_EXIT "AppSpawnCheckUnexpectedExitCall"

long long DiffTime(struct timespec *startTime)
{
    struct timespec tmEnd = {0};
    clock_gettime(CLOCK_REALTIME, &tmEnd);
    long long diff = (long long)((tmEnd.tv_sec - startTime->tv_sec) * 1000000); // 1000000 1000ms
    if (tmEnd.tv_nsec > startTime->tv_nsec) {
        diff += (tmEnd.tv_nsec - startTime->tv_nsec) / 1000; // 1000 ms
    } else {
        diff -= (startTime->tv_nsec - tmEnd.tv_nsec) / 1000; // 1000 ms
    }
    return diff;
}

static void NotifyResToParent(struct AppSpawnContent_ *content, AppSpawnClient *client, int result)
{
    if (content->notifyResToParent != NULL) {
        content->notifyResToParent(content, client, result);
    }
}

static void ProcessExit(int code)
{
    APPSPAWN_LOGI("App exit: %{public}d", code);
#ifdef OHOS_LITE
    _exit(0x7f); // 0x7f user exit
#else
#ifndef APPSPAWN_TEST
    quick_exit(0);
#endif
#endif
}

#ifdef APPSPAWN_HELPER
__attribute__((visibility("default")))
_Noreturn
void exit(int code)
{
    char *checkExit = getenv(APPSPAWN_CHECK_EXIT);
    if (checkExit && atoi(checkExit) == getpid()) {
        APPSPAWN_LOGF("Unexpected exit call: %{public}d", code);
        abort();
    }
    // hook `exit` to `ProcessExit` to ensure app exit in a clean way
    ProcessExit(code);
    // should not come here
    abort();
}
#endif

int DoStartApp(struct AppSpawnContent_ *content, AppSpawnClient *client, char *longProcName, uint32_t longProcNameLen)
{
    APPSPAWN_LOGI("zkx DoStartApp begin!");
    int32_t ret = 0;
    APPSPAWN_LOGV("DoStartApp id %{public}d longProcNameLen %{public}u", client->id, longProcNameLen);
    if (content->handleInternetPermission != NULL) {
        content->handleInternetPermission(client);
    }

    if (content->setAppSandbox) {
        ret = content->setAppSandbox(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set app sandbox");
    }

    (void)umask(DEFAULT_UMASK);
    if (content->setKeepCapabilities) {
        ret = content->setKeepCapabilities(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set KeepCapabilities");
    }

    if (content->setProcessName) {
        ret = content->setProcessName(content, client, longProcName, longProcNameLen);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set setProcessName");
    }

    if (content->setXpmRegion) {
        ret = content->setXpmRegion(content);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set setXpmRegion");
    }

    if (content->setUidGid) {
        ret = content->setUidGid(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to setUidGid");
    }

    if (content->setFileDescriptors) {
        ret = content->setFileDescriptors(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to setFileDescriptors");
    }

    if (content->setCapabilities) {
        ret = content->setCapabilities(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to setCapabilities");
    }

    if (content->waitForDebugger) {
        ret = content->waitForDebugger(client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to waitForDebugger");
    }

    // notify success to father process and start app process
    NotifyResToParent(content, client, 0);
    return 0;
}

static int AppSpawnChildRun(void *arg)
{
    APPSPAWN_LOGI("zkx AppSpawnChildRun begin!");
    APPSPAWN_CHECK(arg != NULL, return -1, "Invalid arg for appspawn child");
    AppSandboxArg *sandbox = (AppSandboxArg *)arg;
    struct AppSpawnContent_ *content = sandbox->content;
    AppSpawnClient *client = sandbox->client;

    APPSPAWN_LOGI("zkx AppSpawnChildRun begin2!");

#ifdef OHOS_DEBUG
    struct timespec tmStart = {0};
    clock_gettime(CLOCK_REALTIME, &tmStart);
#endif
    // close socket id and signal for child
    if (content->clearEnvironment != NULL) {
        APPSPAWN_LOGI("zkx AppSpawnChildRun begin3!");
        content->clearEnvironment(content, client);
    }
    APPSPAWN_LOGI("zkx AppSpawnChildRun begin3!");

    if (content->setAppAccessToken != NULL) {
        APPSPAWN_LOGI("zkx AppSpawnChildRun begin171!");
        content->setAppAccessToken(content, client);
    }

    APPSPAWN_LOGI("zkx AppSpawnChildRun begin175!");
    int ret = -1;
    if ((content->getWrapBundleNameValue != NULL && content->getWrapBundleNameValue(content, client) == 0) ||
        ((client->flags & APP_COLD_START) != 0)) {
        APPSPAWN_LOGI("zkx AppSpawnChildRun begin179!");
        // cold start fail, to start normal
        if (content->coldStartApp != NULL && content->coldStartApp(content, client) == 0) {
            APPSPAWN_LOGI("zkx AppSpawnChildRun begin182!");
            return 0;
        }
    }
    APPSPAWN_LOGI("zkx AppSpawnChildRun begin186!");
    ret = DoStartApp(content, client, content->longProcName, content->longProcNameLen);
    if (content->initDebugParams != NULL) {
        APPSPAWN_LOGI("zkx AppSpawnChildRun begin189!");
        content->initDebugParams(content, client);
    }
#ifdef OHOS_DEBUG
    long long diff = DiffTime(&tmStart);
    APPSPAWN_LOGI("App timeused %{public}d %lld ns.", getpid(), diff);
#endif
    if (ret == 0 && content->runChildProcessor != NULL) {
        APPSPAWN_LOGI("zkx AppSpawnChildRun begin197!");
        content->runChildProcessor(content, client);
    }
    APPSPAWN_LOGI("zkx AppSpawnChildRun begin200!");
    return 0;
}

static int AppSpawnChild(void *arg)
{
    char checkExit[16] = ""; // 16 is enough to store an int
    if (GetIntParameter("persist.init.debug.checkexit", true)) {
        (void)sprintf_s(checkExit, sizeof(checkExit), "%d", getpid());
    }
    setenv(APPSPAWN_CHECK_EXIT, checkExit, true);
    int ret = AppSpawnChildRun(arg);
    unsetenv(APPSPAWN_CHECK_EXIT);
    return ret;
}

static int CloneAppSpawn(void *arg)
{
    int ret = AppSpawnChild(arg);
    ProcessExit(ret);
    return ret;
}

#ifndef APPSPAWN_TEST
pid_t AppSpawnFork(int (*childFunc)(void *arg), void *args)
{
    pid_t pid = fork();
    if (pid == 0) {
        ProcessExit(childFunc(args));
    }
    return pid;
}
#endif

int AppSpawnProcessMsg(AppSandboxArg *sandbox, pid_t *childPid)
{
    APPSPAWN_CHECK(sandbox != NULL && sandbox->content != NULL, return -1, "Invalid content for appspawn");
    APPSPAWN_CHECK(sandbox->client != NULL && childPid != NULL, return -1, "Invalid client for appspawn");
    APPSPAWN_LOGI("AppSpawnProcessMsg id %{public}d 0x%{public}x", sandbox->client->id, sandbox->client->flags);

#ifndef OHOS_LITE
    
    AppSpawnClient *client = sandbox->client;
    if (client->cloneFlags & CLONE_NEWPID) {
        APPSPAWN_CHECK(client->cloneFlags & CLONE_NEWNS, return -1, "clone flags error");
        char *childStack = (char *)malloc(SANDBOX_STACK_SIZE);
        APPSPAWN_CHECK(childStack != NULL, return -1, "malloc failed");
        (void)InitAppSandboxInfo(client);
        pid_t pid = clone(CloneAppSpawn,
            childStack + SANDBOX_STACK_SIZE, client->cloneFlags | SIGCHLD, (void *)sandbox);
        if (pid > 0) {
            free(childStack);
            CleanAppSandboxInfo(client);
            *childPid = pid;
            return 0;
        }
        client->cloneFlags &= ~CLONE_NEWPID;
        free(childStack);
        CleanAppSandboxInfo(client);
    }
#endif
    (void)InitAppSandboxInfo(client);
    *childPid = AppSpawnFork(AppSpawnChild, (void *)sandbox);
    APPSPAWN_CHECK(*childPid >= 0, return -errno, "fork child process error: %{public}d", -errno);
    CleanAppSandboxInfo(client);
    return 0;
}

