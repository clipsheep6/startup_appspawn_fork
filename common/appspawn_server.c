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

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <malloc.h>
#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#ifdef SECURITY_COMPONENT_ENABLE
#include "sec_comp_enhance_kit_c.h"
#endif

#define DEFAULT_UMASK 0002

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
    APPSPAWN_LOGI("App exit code: %{public}d", code);
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
        APPSPAWN_LOGF("Unexpected call: exit(%{public}d)", code);
        abort();
    }
    // hook `exit` to `ProcessExit` to ensure app exit in a clean way
    ProcessExit(code);
    // should not come here
    abort();
}
#endif

static int DoStartAppFirst(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    int32_t ret = 0;
    if (content->handleInternetPermission != NULL) {
        content->handleInternetPermission(client);
    }

    if (content->setAppSandbox) {
        ret = content->setAppSandbox(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set app sandbox");
    }

    if (content->enableSilk) {
        content->enableSilk(content, client);
    }

    return ret;
}

int DoStartApp(struct AppSpawnContent_ *content, AppSpawnClient *client, char *longProcName, uint32_t longProcNameLen)
{
    int32_t ret = 0;
    APPSPAWN_LOGV("DoStartApp id %{public}d longProcNameLen %{public}u", client->id, longProcNameLen);
    ret = DoStartAppFirst(content, client);
    if (ret != 0) {
        return ret;
    }

    (void)umask(DEFAULT_UMASK);
    if (content->setKeepCapabilities) {
        ret = content->setKeepCapabilities(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set KeepCapabilities");
    }

    if (content->setXpmConfig) {
        ret = content->setXpmConfig(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set setXpmConfig");
    }

    if (content->setProcessName) {
        ret = content->setProcessName(content, client, content->longProcName, content->longProcNameLen);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set setProcessName");
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

#ifdef SECURITY_COMPONENT_ENABLE
    InitSecCompClientEnhance();
#endif

    // notify success to father process and start app process
    NotifyResToParent(content, client, 0);
    return 0;
}

static int AppSpawnChild(void *arg)
{
    APPSPAWN_CHECK(arg != NULL, return -1, "Invalid arg for appspawn child");
    AppSandboxArg *sandbox = (AppSandboxArg *)arg;
    struct AppSpawnContent_ *content = sandbox->content;
    AppSpawnClient *client = sandbox->client;
    int ret = -1;

    if (content->setProcessName) {
        ret = content->setProcessName(content, client, content->longProcName, content->longProcNameLen);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return ret, "Failed to set setProcessName");
    }

#ifdef OHOS_DEBUG
    struct timespec tmStart = {0};
    clock_gettime(CLOCK_REALTIME, &tmStart);
#endif
    // close socket id and signal for child
    if (content->clearEnvironment != NULL) {
        content->clearEnvironment(content, client);
    }

    if (content->setAppAccessToken != NULL) {
        ret = content->setAppAccessToken(content, client);
        if (ret != 0) {
            APPSPAWN_LOGE("AppSpawnChild, set app token id failed");
            return -1;
        }
    }

    if ((content->getWrapBundleNameValue != NULL && content->getWrapBundleNameValue(content, client) == 0) ||
        ((client->flags & APP_COLD_START) != 0)) {
        // cold start fail, to start normal
        if (content->coldStartApp != NULL && content->coldStartApp(content, client) == 0) {
            return 0;
        }
    }
#ifndef OHOS_LITE
    // enable cache for app process
    mallopt(M_OHOS_CONFIG, M_TCACHE_PERFORMANCE_MODE);
    mallopt(M_OHOS_CONFIG, M_ENABLE_OPT_TCACHE);
    mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_ENABLE);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_ENABLE);
#endif
    ret = DoStartApp(content, client, content->longProcName, content->longProcNameLen);
    if (content->initDebugParams != NULL) {
        content->initDebugParams(content, client);
    }
#ifdef OHOS_DEBUG
    long long diff = DiffTime(&tmStart);
    APPSPAWN_LOGI("App timeused %{public}d %lld ns.", getpid(), diff);
#endif
    if (ret == 0 && content->runChildProcessor != NULL) {
        content->runChildProcessor(content, client);
    }
    return 0;
}

static int CloneAppSpawn(void *arg)
{
    ProcessExit(AppSpawnChild(arg));
    return 0;
}

int AppSpawnProcessMsg(AppSandboxArg *sandbox, pid_t *childPid)
{
    APPSPAWN_CHECK(sandbox != NULL && sandbox->content != NULL, return -1, "Invalid content for appspawn");
    APPSPAWN_CHECK(sandbox->client != NULL && childPid != NULL, return -1, "Invalid client for appspawn");
    APPSPAWN_LOGI("AppSpawnProcessMsg id %{public}d 0x%{public}x", sandbox->client->id, sandbox->client->flags);

    pid_t pid = 0;
    if (sandbox->content->isNweb) {
        pid = clone(CloneAppSpawn, NULL, sandbox->client->cloneFlags | SIGCHLD, (void *)sandbox);
    } else {
        pid = fork();
        if (pid == 0) {
            ProcessExit(AppSpawnChild((void *)sandbox));
        }
    }
    APPSPAWN_CHECK(pid >= 0, return -errno, "fork child process error: %{public}d", -errno);
    *childPid = pid;
    return 0;
}

