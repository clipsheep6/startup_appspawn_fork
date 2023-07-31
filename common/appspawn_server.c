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
#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#ifdef SECURITY_COMPONENT_ENABLE
#include "sec_comp_enhance_kit_c.h"
#endif

#define DEFAULT_UMASK 0002
#define SANDBOX_STACK_SIZE (1024 * 1024 * 8)

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
#ifndef OHOS_LITE
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "appspawn_service.h"

static const char *g_extBundleName = "com.example.myapplication";
static const int FUSE_OPTIONS_MAX_LEN = 128;
static const int FUSE_FD = 15303;
int AppFuseMount(const char *bundleName)
{
    if (bundleName == NULL) {
        APPSPAWN_LOGE("bundleName = %p", bundleName);
        return 0;
    }
    static int  g_test_ctl = 0;
    if (g_test_ctl) {
        APPSPAWN_LOGE("g_test_ctl = %d", g_test_ctl);
        return 0;
    }
    if (strcmp(g_extBundleName, bundleName) == 0) {
        APPSPAWN_LOGE("start test flow, uid:%d, gid:%d", getuid(), getgid());
        mkdir("/mnt/sandbox/com.example.myapplication/system/data/", 0777);
        mkdir("/mnt/fuse", 0777);
        int fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
        APPSPAWN_CHECK(fd != -1, return 0, ", fd:%d, open /dev/fuse failed, errno is %d", fd, errno);
        char options[FUSE_OPTIONS_MAX_LEN];
        snprintf(options, sizeof(options), "fd=%i,rootmode=40000,user_id=%u,group_id=%u",
            fd, getuid(), getgid());
        const char *srcTestPath = "appFuse";
        const char *targetTestPath = "/mnt/fuse";
        const char *testFstype = "fuse.appFuse";
        int ret = 0;
        ret = mount(srcTestPath, targetTestPath, testFstype, 6, options);
        APPSPAWN_CHECK(ret == 0, return 0, " ext test failed, bind mount %s to %s failed %d",
            srcTestPath, targetTestPath, errno);

        close(FUSE_FD);
        ret = dup2(fd, FUSE_FD);
        APPSPAWN_CHECK_ONLY_LOG(ret != 0 ,"dup fuse fd %d failed, errno is %d", fd, errno);
        g_test_ctl = 1;
    }
    return 0;
}
#endif

int DoStartApp(struct AppSpawnContent_ *content, AppSpawnClient *client, char *longProcName, uint32_t longProcNameLen)
{
    int32_t ret = 0;
    APPSPAWN_LOGV("DoStartApp id %{public}d longProcNameLen %{public}u", client->id, longProcNameLen);
    if (content->handleInternetPermission != NULL) {
        content->handleInternetPermission(client);
    }
    #ifndef OHOS_LITE
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)(client);
    APPSPAWN_LOGE(", bundleName:%s, processName:%s",
        appProperty->property.bundleName, appProperty->property.processName);
    AppFuseMount(appProperty->property.bundleName);
    #endif
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
        pid_t pid = clone(CloneAppSpawn,
            childStack + SANDBOX_STACK_SIZE, client->cloneFlags | SIGCHLD, (void *)sandbox);
        if (pid > 0) {
            free(childStack);
            *childPid = pid;
            return 0;
        }
        client->cloneFlags &= ~CLONE_NEWPID;
        free(childStack);
    }
#endif
    *childPid = AppSpawnFork(AppSpawnChild, (void *)sandbox);
    APPSPAWN_CHECK(*childPid >= 0, return -errno, "fork child process error: %{public}d", -errno);
    return 0;
}

