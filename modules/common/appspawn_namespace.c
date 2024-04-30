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

#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "appspawn_hook.h"
#include "appspawn_manager.h"
#include "appspawn_utils.h"
#include "securec.h"
#ifdef WITH_SELINUX
#include "selinux/selinux.h"
#endif

#define PID_NS_INIT_UID 100000  // reserved for pid_ns_init process, avoid app, render proc, etc.
#define PID_NS_INIT_GID 100000

typedef struct {
    AppSpawnExtData extData;
    int nsSelfPidFd;  // ns pid fd of appspawn
    int nsInitPidFd;  // ns pid fd of pid_ns_init
} AppSpawnNamespace;

static int AppSpawnExtDataCompareDataId(ListNode *node, void *data)
{
    AppSpawnExtData *extData = (AppSpawnExtData *)ListEntry(node, AppSpawnExtData, node);
    return extData->dataId - *(uint32_t *)data;
}

static AppSpawnNamespace *GetAppSpawnNamespace(const AppSpawnMgr *content)
{
    APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return NULL);
    uint32_t dataId = EXT_DATA_NAMESPACE;
    ListNode *node = OH_ListFind(&content->extData, (void *)&dataId, AppSpawnExtDataCompareDataId);
    if (node == NULL) {
        return NULL;
    }
    return (AppSpawnNamespace *)ListEntry(node, AppSpawnNamespace, extData);
}

static void DeleteAppSpawnNamespace(AppSpawnNamespace *namespace)
{
    APPSPAWN_CHECK_ONLY_EXPER(namespace != NULL, return);
    APPSPAWN_LOGV("DeleteAppSpawnNamespace");
    OH_ListRemove(&namespace->extData.node);
    OH_ListInit(&namespace->extData.node);

    if (namespace->nsInitPidFd > 0) {
        close(namespace->nsInitPidFd);
        namespace->nsInitPidFd = -1;
    }
    if (namespace->nsSelfPidFd > 0) {
        close(namespace->nsSelfPidFd);
        namespace->nsSelfPidFd = -1;
    }
    free(namespace);
}

static void FreeAppSpawnNamespace(struct TagAppSpawnExtData *data)
{
    AppSpawnNamespace *namespace = ListEntry(data, AppSpawnNamespace, extData);
    APPSPAWN_CHECK_ONLY_EXPER(namespace != NULL, return);
    DeleteAppSpawnNamespace(namespace);
}

static AppSpawnNamespace *CreateAppSpawnNamespace(void)
{
    APPSPAWN_LOGV("CreateAppSpawnNamespace");
    AppSpawnNamespace *namespace = (AppSpawnNamespace *)calloc(1, sizeof(AppSpawnNamespace));
    APPSPAWN_CHECK(namespace != NULL, return NULL, "Failed to create sandbox");
    namespace->nsInitPidFd = -1;
    namespace->nsSelfPidFd = -1;
    // ext data init
    OH_ListInit(&namespace->extData.node);
    namespace->extData.dataId = EXT_DATA_NAMESPACE;
    namespace->extData.freeNode = FreeAppSpawnNamespace;
    namespace->extData.dumpNode = NULL;
    return namespace;
}

static int ReadFileToBuffer(char *buffer, uint32_t buffLen, const char *name)
{
    int ret = snprintf_s(buffer, buffLen, buffLen - 1, "/proc/%s/comm", name);
    APPSPAWN_CHECK(ret > 0, return -1, "Failed to format path %{public}s", name);

    FILE *file = fopen(buffer, "r");
    APPSPAWN_CHECK_ONLY_EXPER(file != NULL, return -1);

    char *tmp = fgets(buffer, buffLen, file);
    (void)fclose(file);
    if (tmp != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
        return 0;
    }
    return -1;
}

APPSPAWN_STATIC pid_t GetPidByName(const char *name)
{
    APPSPAWN_CHECK_ONLY_EXPER(name != NULL, return -1);
    int pid = -1;  // initial pid set to -1
    DIR *dir = opendir("/proc");
    APPSPAWN_CHECK_ONLY_EXPER(dir != NULL, return -1);

    char buffer[PATH_MAX];
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (ReadFileToBuffer(buffer, sizeof(buffer), entry->d_name) == 0) {
            if (strcmp(buffer, name) != 0) {
                continue;
            }
            long pidNum = strtol(entry->d_name, NULL, 10);  // pid will not exceed a 10-digit decimal number
            APPSPAWN_CHECK_ONLY_EXPER(pidNum > 0, return -1);
            APPSPAWN_LOGI("get pid of %{public}s success", name);
            pid = (int)pidNum;
            break;
        }
    }
    closedir(dir);
    return pid;
}

static int NsInitFunc()
{
    setuid(PID_NS_INIT_UID);
    setgid(PID_NS_INIT_GID);
#ifdef WITH_SELINUX
    setcon("u:r:pid_ns_init:s0");
#endif
    char *argv[] = {"/system/bin/pid_ns_init", NULL};
    execve("/system/bin/pid_ns_init", argv, NULL);
    _exit(0);
    return 0;
}

static int GetNsPidFd(pid_t pid)
{
    char nsPath[256];  // filepath of ns pid
    int ret = snprintf_s(nsPath, sizeof(nsPath), sizeof(nsPath) - 1, "/proc/%d/ns/pid", pid);
    APPSPAWN_CHECK(ret >= 0, return -1, "Failed to format path for %{public}d", pid);
    int nsFd = open(nsPath, O_RDONLY);
    APPSPAWN_CHECK(nsFd >= 0, return -1, "open ns pid:%{public}d failed, err:%{public}s", pid, strerror(errno));
    return nsFd;
}

APPSPAWN_STATIC int PreLoadEnablePidNs(AppSpawnMgr *content)
{
    APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return -1);
    APPSPAWN_LOGI("Enable pid namespace flags: 0x%{public}x", content->content.sandboxNsFlags);
    if (IsColdRunMode(content)) {
        return 0;
    }
    if (IsNWebSpawnMode(content)) {  // only for appspawn
        return 0;
    }
    if (!(content->content.sandboxNsFlags & CLONE_NEWPID)) {
        return 0;
    }
    AppSpawnNamespace *namespace = CreateAppSpawnNamespace();
    APPSPAWN_CHECK(namespace != NULL, return -1, "Failed to create namespace");

    // check if process pid_ns_init exists, this is the init process for pid namespace
    pid_t pid = GetPidByName("pid_ns_init");
    if (pid == -1) {
        APPSPAWN_LOGI("Start Create pid_ns_init %{public}d", pid);
        pid = clone(NsInitFunc, NULL, CLONE_NEWPID, NULL);
        APPSPAWN_CHECK(pid >= 0, DeleteAppSpawnNamespace(namespace);
            return APPSPAWN_SYSTEM_ERROR, "clone pid ns init failed");
    } else {
        APPSPAWN_LOGI("pid_ns_init exists, no need to create");
    }

    namespace->nsSelfPidFd = GetNsPidFd(getpid());
    namespace->nsInitPidFd = GetNsPidFd(pid);
    if (namespace->nsSelfPidFd < 0 || namespace->nsInitPidFd < 0) {
        DeleteAppSpawnNamespace(namespace);
        return APPSPAWN_SYSTEM_ERROR;
    }
    OH_ListAddTail(&content->extData, &namespace->extData.node);
    APPSPAWN_LOGI("Enable pid namespace success.");
    return 0;
}

// after calling setns, new process will be in the same pid namespace of the input pid
static int SetPidNamespace(int nsPidFd, int nsType)
{
    APPSPAWN_LOGI("SetPidNamespace 0x%{public}x", nsType);
#ifndef APPSPAWN_TEST
    if (setns(nsPidFd, nsType) < 0) {
        APPSPAWN_LOGE("set pid namespace nsType:%{public}d failed", nsType);
        return -1;
    }
#endif
    return 0;
}

static int PreForkSetPidNamespace(AppSpawnMgr *content, AppSpawningCtx *property)
{
    AppSpawnNamespace *namespace = GetAppSpawnNamespace(content);
    if (namespace == NULL) {
        return 0;
    }
    if (content->content.sandboxNsFlags & CLONE_NEWPID) {
        SetPidNamespace(namespace->nsInitPidFd, CLONE_NEWPID);  // pid_ns_init is the init process
    }
    return 0;
}

static int PostForkSetPidNamespace(AppSpawnMgr *content, AppSpawningCtx *property)
{
    AppSpawnNamespace *namespace = GetAppSpawnNamespace(content);
    if (namespace == NULL) {
        return 0;
    }
    if (content->content.sandboxNsFlags & CLONE_NEWPID) {
        SetPidNamespace(namespace->nsSelfPidFd, 0);  // go back to original pid namespace
    }

    return 0;
}

MODULE_CONSTRUCTOR(void)
{
    AddPreloadHook(HOOK_PRIO_LOWEST, PreLoadEnablePidNs);
    AddAppSpawnHook(STAGE_PARENT_PRE_FORK, HOOK_PRIO_LOWEST, PreForkSetPidNamespace);
    AddAppSpawnHook(STAGE_PARENT_POST_FORK, HOOK_PRIO_HIGHEST, PostForkSetPidNamespace);
}
