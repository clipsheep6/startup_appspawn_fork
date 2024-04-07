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

#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "appspawn_hook.h"
#include "appspawn_msg.h"
#include "appspawn_service.h"
#include "securec.h"

static void AppPropertyDestroyProc(ListNode *node)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    DeleteAppSpawningCtx(property);
}

int AppSpawnedProcessMgrInit(AppSpawnedProcessMgr *mgr)
{
    OH_ListInit(&mgr->appQueue);
    OH_ListInit(&mgr->diedQueue);
    OH_ListInit(&mgr->appSpawnQueue);
    mgr->diedAppCount = 0;
    return 0;
}

int AppSpawnedProcessMgrDestroy(AppSpawnedProcessMgr *mgr)
{
    OH_ListRemoveAll(&mgr->appQueue, NULL);
    OH_ListRemoveAll(&mgr->diedQueue, NULL);
    OH_ListRemoveAll(&mgr->appSpawnQueue, AppPropertyDestroyProc);
    return 0;
}

static int AppInfoPidComparePro(ListNode *node, void *data)
{
    AppSpawnedProcess *node1 = ListEntry(node, AppSpawnedProcess, node);
    pid_t pid = *(pid_t *)data;
    return node1->pid - pid;
}

static int AppInfoNameComparePro(ListNode *node, void *data)
{
    AppSpawnedProcess *node1 = ListEntry(node, AppSpawnedProcess, node);
    return strcmp(node1->name, (char *)data);
}

static int AppInfoCompareProc(ListNode *node, ListNode *newNode)
{
    AppSpawnedProcess *node1 = ListEntry(node, AppSpawnedProcess, node);
    AppSpawnedProcess *node2 = ListEntry(newNode, AppSpawnedProcess, node);
    return node1->pid - node2->pid;
}

AppSpawnedProcess *AddSpawnedProcess(AppSpawnedProcessMgr *mgr, pid_t pid, const char *processName)
{
    APPSPAWN_CHECK(mgr != NULL && processName != NULL, return NULL, "Invalid mgr or process name");
    APPSPAWN_CHECK(pid > 0, return NULL, "Invalid pid for %{public}s", processName);
    size_t len = strlen(processName) + 1;
    AppSpawnedProcess *node = (AppSpawnedProcess *)calloc(1, sizeof(AppSpawnedProcess) + len + 1);
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to malloc for appinfo");

    node->pid = pid;
    node->max = 0;
    node->uid = 0;
    node->exitStatus = 0;
    int ret = strcpy_s(node->name, len, processName);
    APPSPAWN_CHECK(ret == 0, free(node);
        return NULL, "Failed to strcpy process name");

    OH_ListInit(&node->node);
    APPSPAWN_LOGI("Add %{public}s, pid=%{public}d success", processName, pid);
    OH_ListAddWithOrder(&mgr->appQueue, &node->node, AppInfoCompareProc);
    return node;
}

void HandleProcessTerminate(AppSpawnedProcessMgr *mgr, AppSpawnedProcess *node, int nwebspawn)
{
    if (!nwebspawn) {
        OH_ListRemove(&node->node);
        free(node);
        return;
    }
    if (mgr->diedAppCount >= MAX_DIED_PROCESS_COUNT) {
        AppSpawnedProcess *oldApp = ListEntry(mgr->diedQueue.next, AppSpawnedProcess, node);
        OH_ListRemove(&oldApp->node);
        free(node);
        mgr->diedAppCount--;
    }
    OH_ListRemove(&node->node);
    OH_ListInit(&node->node);
    APPSPAWN_LOGI("HandleProcessTerminate %{public}s, pid=%{public}d", node->name, node->pid);
    OH_ListAddTail(&mgr->diedQueue, &node->node);
    mgr->diedAppCount++;
}

AppSpawnedProcess *GetSpawnedProcess(AppSpawnedProcessMgr *mgr, pid_t pid)
{
    ListNode *node = OH_ListFind(&mgr->appQueue, &pid, AppInfoPidComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnedProcess, node);
}

AppSpawnedProcess *GetSpawnedProcessByName(AppSpawnedProcessMgr *mgr, const char *name)
{
    ListNode *node = OH_ListFind(&mgr->appQueue, (void *)name, AppInfoNameComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnedProcess, node);
}

int GetProcessTerminationStatus(AppSpawnedProcessMgr *mgr, pid_t pid)
{
    APPSPAWN_LOGV("GetProcessTerminationStatus pid: %{public}d ", pid);
    if (pid <= 0) {
        return 0;
    }
    int exitStatus = 0;
    ListNode *node = OH_ListFind(&mgr->diedQueue, &pid, AppInfoPidComparePro);
    if (node != NULL) {
        AppSpawnedProcess *info = ListEntry(node, AppSpawnedProcess, node);
        exitStatus = info->exitStatus;
        OH_ListRemove(node);
        free(info);
        return exitStatus;
    }

    if (kill(pid, SIGKILL) != 0) {
        APPSPAWN_LOGE("unable to kill render process, pid: %{public}d ret %{public}d", pid, errno);
    }

    pid_t exitPid = waitpid(pid, &exitStatus, 0);
    if (exitPid != pid) {
        APPSPAWN_LOGE("waitpid failed, pid: %{public}d %{public}d, status: %{public}d", exitPid, pid, exitStatus);
        return -1;
    }
    return exitStatus;
}

AppSpawningCtx *CreateAppSpawningCtx(AppSpawnedProcessMgr *mgr)
{
    static uint32_t requestId = 0;
    AppSpawningCtx *property = (AppSpawningCtx *)malloc(sizeof(AppSpawningCtx));
    APPSPAWN_CHECK(property != NULL, return NULL, "Failed to create AppSpawningCtx ");
    property->client.id = ++requestId;
    property->client.flags = 0;
    property->forkCtx.watcherHandle = NULL;
    property->forkCtx.coldRunPath = NULL;
    property->forkCtx.timer = NULL;
    property->forkCtx.fd[0] = -1;
    property->forkCtx.fd[1] = -1;
    property->forkCtx.shmId = -1;
    property->message = NULL;
    property->pid = 0;
    property->state = APP_STATE_IDLE;
    OH_ListInit(&property->node);
    if (mgr) {
        OH_ListAddTail(&mgr->appSpawnQueue, &property->node);
    }
    return property;
}

void DeleteAppSpawningCtx(AppSpawningCtx *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    DeleteAppSpawnMsg(property->message);
    APPSPAWN_LOGV("DeleteAppSpawningCtx");
    OH_ListRemove(&property->node);
    if (property->forkCtx.timer) {
        LE_StopTimer(LE_GetDefaultLoop(), property->forkCtx.timer);
        property->forkCtx.timer = NULL;
    }
    if (property->forkCtx.watcherHandle) {
        LE_RemoveWatcher(LE_GetDefaultLoop(), property->forkCtx.watcherHandle);
        property->forkCtx.watcherHandle = NULL;
    }
    if (property->forkCtx.coldRunPath) {
        free(property->forkCtx.coldRunPath);
        property->forkCtx.coldRunPath = NULL;
    }
    if (property->forkCtx.fd[0] >= 0) {
        close(property->forkCtx.fd[0]);
    }
    if (property->forkCtx.fd[1] >= 0) {
        close(property->forkCtx.fd[1]);
    }
    if (property->forkCtx.shmId >= 0) {
        (void)shmctl(property->forkCtx.shmId, IPC_RMID, NULL);
        property->forkCtx.shmId = -1;
    }
    free(property);
}

static int AppPropertyComparePid(ListNode *node, void *data)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    if (property->pid == *(pid_t *)data) {
        return 0;
    }
    return 1;
}

AppSpawningCtx *GetAppSpawningCtxByPid(AppSpawnedProcessMgr *mgr, pid_t pid)
{
    ListNode *node = OH_ListFind(&mgr->appSpawnQueue, (void *)&pid, AppPropertyComparePid);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawningCtx, node);
}

int CheckAppPropertyFlags(const struct TagAppSpawningCtx *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return 0, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    uint32_t blockIndex = index / 32;  // 32 max bit in int
    uint32_t bitIndex = index % 32;    // 32 max bit in int
    APPSPAWN_CHECK(blockIndex < msgFlags->count, return 0,
        "Invalid index %{public}d max: %{public}d", index, msgFlags->count);
    return CHECK_FLAGS_BY_INDEX(msgFlags->flags[blockIndex], bitIndex);
}

static inline int SetAppSpawnMsgFlags(AppSpawnMsgFlags *msgFlags, uint32_t index)
{
    uint32_t blockIndex = index / 32;  // 32 max bit in int
    uint32_t bitIndex = index % 32;    // 32 max bit in int
    if (blockIndex >= msgFlags->count) {
        return -1;
    }
    msgFlags->flags[blockIndex] |= (1 << bitIndex);
    return 0;
}

int SetAppPropertyFlags(const struct TagAppSpawningCtx *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return -1, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    return SetAppSpawnMsgFlags(msgFlags, index);
}

int IsNWebSpawnMode(const struct TagAppSpawnMgr *content)
{
    return (content != NULL) &&
        (content->content.mode == MODE_FOR_NWEB_SPAWN || content->content.mode == MODE_FOR_NWEB_COLD_RUN);
}

int IsColdRunMode(const struct TagAppSpawnMgr *content)
{
    return (content != NULL) &&
        (content->content.mode == MODE_FOR_APP_COLD_RUN || content->content.mode == MODE_FOR_NWEB_COLD_RUN);
}

int IsDeveloperModeOn(const AppSpawningCtx *property)
{
    return (property != NULL && ((property->client.flags & APP_DEVELOPER_MODE) == APP_DEVELOPER_MODE));
}

static void DumpAppProperty(const AppSpawningCtx *property, const char *info)
{
    APPSPAPWN_DUMP("%{public}s app property id: %{public}u flags: %{public}x",
        info, property->client.id, property->client.flags);
    APPSPAPWN_DUMP("%{public}s app property state: %{public}d", info, property->state);
    if (property->message) {
        APPSPAPWN_DUMP("%{public}s app property msgId: %{public}u msgLen: %{public}u tlvCount: %{public}u",
            info, property->message->msgHeader.msgId, property->message->msgHeader.msgLen, property->message->tlvCount);
        APPSPAPWN_DUMP("%{public}s app property process name: %{public}s",
            info, property->message->msgHeader.processName);
    }
    DumpNormalProperty(property);
}

static int DumpAppSpawnQueue(ListNode *node, void *data)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    DumpAppProperty(property, "");
    return 0;
}

static int DumpAppQueue(ListNode *node, void *data)
{
    AppSpawnedProcess *appInfo = ListEntry(node, AppSpawnedProcess, node);
    int64_t diff = DiffTime(&appInfo->spawnStart, &appInfo->spawnEnd);
    APPSPAPWN_DUMP("APP in %{public}s info uid: %{public}u pid: %{public}x", (char *)data, appInfo->uid, appInfo->pid);
    APPSPAPWN_DUMP("APP in %{public}s info name: %{public}s exitStatus: %{public}d spawn time: %{public}" PRId64 " ns ",
        (char *)data, appInfo->name, appInfo->exitStatus, diff);
    return 0;
}

static int DumpExtData(ListNode *node, void *data)
{
    AppSpawnExtData *extData = ListEntry(node, AppSpawnExtData, node);
    extData->dumpNode(extData);
    return 0;
}

void DumpApSpawn(const AppSpawnMgr *content, const AppSpawnMsgNode *message)
{
    FILE *stream = NULL;
    uint32_t len = 0;
    char *ptyName = GetAppSpawnMsgExInfo(message, "pty-name", &len);
    if (ptyName != NULL) { //
        APPSPAWN_LOGI("Dump info to file '%{public}s'", ptyName);
        stream = fopen(ptyName, "w");
        SetDumpToStream(stream);
    } else {
        SetDumpToStream(stdout);
    }
    APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return);
    APPSPAPWN_DUMP("Dump appspawn info start ... ");
    APPSPAPWN_DUMP("APP spawning queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.appSpawnQueue, NULL, DumpAppSpawnQueue, 0);
    APPSPAPWN_DUMP("APP queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.appQueue, "App queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("APP died queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.diedQueue, "App died queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("Ext data: ");
    OH_ListTraversal((ListNode *)&content->extData, "Ext data", DumpExtData, 0);
    APPSPAPWN_DUMP("Dump appspawn info finish ");
    if (stream != NULL) {
        (void)fflush(stream);
        fclose(stream);
#ifdef APPSPAWN_TEST
        SetDumpToStream(stdout);
#else
        SetDumpToStream(NULL);
#endif
    }
}
