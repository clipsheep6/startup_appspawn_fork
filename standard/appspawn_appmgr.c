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
#include "appspawn_manager.h"
#include "securec.h"

static AppSpawnMgr *g_appSpawnMgr = NULL;

AppSpawnMgr *CreateAppSpawnMgr(int mode)
{
    AppSpawnMgr *appMgr = (AppSpawnMgr *)calloc(1, sizeof(AppSpawnMgr));
    APPSPAWN_CHECK(appMgr != NULL, return NULL, "Failed to alloc memory for appspawn");
    appMgr->content.longProcName = NULL;
    appMgr->content.longProcNameLen = 0;
    appMgr->content.mode = mode;
    appMgr->content.sandboxNsFlags = 0;
    appMgr->servicePid = getpid();
    appMgr->server = NULL;
    appMgr->sigHandler = NULL;
    OH_ListInit(&appMgr->appQueue);
    OH_ListInit(&appMgr->diedQueue);
    OH_ListInit(&appMgr->appSpawnQueue);
    appMgr->diedAppCount = 0;
    OH_ListInit(&appMgr->extData);
    g_appSpawnMgr = appMgr;
    return appMgr;
}

AppSpawnMgr *GetAppSpawnMgr(void)
{
    return g_appSpawnMgr;
}

AppSpawnContent *GetAppSpawnContent(void)
{
    return g_appSpawnMgr == NULL ? NULL : &g_appSpawnMgr->content;
}

static void SpawningQueueDestroy(ListNode *node)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    DeleteAppSpawningCtx(property);
}

static void ExtDataDestroy(ListNode *node)
{
    AppSpawnExtData *extData = ListEntry(node, AppSpawnExtData, node);
    AppSpawnExtDataFree freeNode = extData->freeNode;
    if (freeNode) {
        freeNode(extData);
    }
}

void DeleteAppSpawnMgr(AppSpawnMgr *mgr)
{
    APPSPAWN_CHECK_ONLY_EXPER(mgr != NULL, return);
    OH_ListRemoveAll(&mgr->appQueue, NULL);
    OH_ListRemoveAll(&mgr->diedQueue, NULL);
    OH_ListRemoveAll(&mgr->appSpawnQueue, SpawningQueueDestroy);
    OH_ListRemoveAll(&mgr->extData, ExtDataDestroy);

    APPSPAWN_LOGV("DeleteAppSpawnMgr %{public}d %{public}d", mgr->servicePid, getpid());
    free(mgr);
    if (g_appSpawnMgr == mgr) {
        g_appSpawnMgr = NULL;
    }
}

void TraversalSpawnedProcess(AppTraversal traversal, void *data)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL && traversal != NULL, return);
    ListNode *node = g_appSpawnMgr->appQueue.next;
    while (node != &g_appSpawnMgr->appQueue) {
        ListNode *next = node->next;
        AppSpawnedProcess *appInfo = ListEntry(node, AppSpawnedProcess, node);
        traversal(g_appSpawnMgr, appInfo, data);
        node = next;
    }
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

AppSpawnedProcess *AddSpawnedProcess(pid_t pid, const char *processName)
{
    APPSPAWN_CHECK(g_appSpawnMgr != NULL && processName != NULL, return NULL, "Invalid mgr or process name");
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
    OH_ListAddWithOrder(&g_appSpawnMgr->appQueue, &node->node, AppInfoCompareProc);
    return node;
}

void TerminateSpawnedProcess(AppSpawnedProcess *node)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL && node != NULL, return);
    if (!IsNWebSpawnMode(g_appSpawnMgr)) {
        OH_ListRemove(&node->node);
        free(node);
        return;
    }
    if (g_appSpawnMgr->diedAppCount >= MAX_DIED_PROCESS_COUNT) {
        AppSpawnedProcess *oldApp = ListEntry(g_appSpawnMgr->diedQueue.next, AppSpawnedProcess, node);
        OH_ListRemove(&oldApp->node);
        free(node);
        g_appSpawnMgr->diedAppCount--;
    }
    OH_ListRemove(&node->node);
    OH_ListInit(&node->node);
    APPSPAWN_LOGI("ProcessAppDied %{public}s, pid=%{public}d", node->name, node->pid);
    OH_ListAddTail(&g_appSpawnMgr->diedQueue, &node->node);
    g_appSpawnMgr->diedAppCount++;
}

AppSpawnedProcess *GetSpawnedProcess(pid_t pid)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL, return NULL);
    ListNode *node = OH_ListFind(&g_appSpawnMgr->appQueue, &pid, AppInfoPidComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnedProcess, node);
}

AppSpawnedProcess *GetSpawnedProcessByName(const char *name)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL, return NULL);
    ListNode *node = OH_ListFind(&g_appSpawnMgr->appQueue, (void *)name, AppInfoNameComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnedProcess, node);
}

int KillAndWaitStatus(pid_t pid, int sig)
{
    int exitStatus = 0;
    if (kill(pid, sig) != 0) {
        APPSPAWN_LOGE("unable to kill process, pid: %{public}d ret %{public}d", pid, errno);
    }

    pid_t exitPid = waitpid(pid, &exitStatus, 0);
    if (exitPid != pid) {
        APPSPAWN_LOGE("waitpid failed, pid: %{public}d %{public}d, status: %{public}d", exitPid, pid, exitStatus);
        return -1;
    }
    return exitStatus;
}

static int GetProcessTerminationStatus(pid_t pid)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL, return -1);
    APPSPAWN_LOGV("GetProcessTerminationStatus pid: %{public}d ", pid);
    if (pid <= 0) {
        return 0;
    }
    int exitStatus = 0;
    ListNode *node = OH_ListFind(&g_appSpawnMgr->diedQueue, &pid, AppInfoPidComparePro);
    if (node != NULL) {
        AppSpawnedProcess *info = ListEntry(node, AppSpawnedProcess, node);
        exitStatus = info->exitStatus;
        OH_ListRemove(node);
        free(info);
        return exitStatus;
    }
    return KillAndWaitStatus(pid, SIGKILL);
}

AppSpawningCtx *CreateAppSpawningCtx(void)
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
    if (g_appSpawnMgr) {
        OH_ListAddTail(&g_appSpawnMgr->appSpawnQueue, &property->node);
    }
    return property;
}

void DeleteAppSpawningCtx(AppSpawningCtx *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    DeleteAppSpawnMsg(property->message);
    APPSPAWN_LOGV("DeleteAppSpawningCtx %{public}d %{public}d", property->forkCtx.fd[0], property->forkCtx.fd[1]);
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

AppSpawningCtx *GetAppSpawningCtxByPid(pid_t pid)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL, return NULL);
    ListNode *node = OH_ListFind(&g_appSpawnMgr->appSpawnQueue, (void *)&pid, AppPropertyComparePid);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawningCtx, node);
}

void AppSpawningCtxTraversal(ProcessTraversal traversal, void *data)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL && traversal != NULL, return);
    ListNode *node = g_appSpawnMgr->appSpawnQueue.next;
    while (node != &g_appSpawnMgr->appSpawnQueue) {
        ListNode *next = node->next;
        AppSpawningCtx *ctx = ListEntry(node, AppSpawningCtx, node);
        traversal(g_appSpawnMgr, ctx, data);
        node = next;
    }
}

static inline int SetSpawnMsgFlags(AppSpawnMsgFlags *msgFlags, uint32_t index)
{
    uint32_t blockIndex = index / 32;  // 32 max bit in int
    uint32_t bitIndex = index % 32;    // 32 max bit in int
    if (blockIndex >= msgFlags->count) {
        return -1;
    }
    msgFlags->flags[blockIndex] |= (1 << bitIndex);
    return 0;
}

int SetAppSpawnMsgFlag(const AppSpawnMsgNode *message, uint32_t type, uint32_t index)
{
    APPSPAWN_CHECK_ONLY_EXPER(message != NULL, return -1);
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppSpawnMsgInfo(message, type);
    APPSPAWN_CHECK(msgFlags != NULL, return -1,
        "No tlv %{public}d in msg %{public}s", type, message->msgHeader.processName);
    return SetSpawnMsgFlags(msgFlags, index);
}

static int DumpAppSpawnQueue(ListNode *node, void *data)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    APPSPAPWN_DUMP("app property id: %{public}u flags: %{public}x",
        property->client.id, property->client.flags);
    APPSPAPWN_DUMP("app property state: %{public}d", property->state);

    DumpAppSpawnMsg(property->message);
    return 0;
}

static int DumpAppQueue(ListNode *node, void *data)
{
    AppSpawnedProcess *appInfo = ListEntry(node, AppSpawnedProcess, node);
    int64_t diff = DiffTime(&appInfo->spawnStart, &appInfo->spawnEnd);
    APPSPAPWN_DUMP("App info uid: %{public}u pid: %{public}x", appInfo->uid, appInfo->pid);
    APPSPAPWN_DUMP("App info name: %{public}s exitStatus: 0x%{public}x spawn time: %{public}" PRId64 " us ",
        appInfo->name, appInfo->exitStatus, diff);
    return 0;
}

static int DumpExtData(ListNode *node, void *data)
{
    AppSpawnExtData *extData = ListEntry(node, AppSpawnExtData, node);
    extData->dumpNode(extData);
    return 0;
}

void ProcessAppSpawnDumpMsg(const AppSpawnMsgNode *message)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL && message != NULL, return);
    FILE *stream = NULL;
    uint32_t len = 0;
    char *ptyName = GetAppSpawnMsgExtInfo(message, "pty-name", &len);
    if (ptyName != NULL) { //
        APPSPAWN_LOGI("Dump info to file '%{public}s'", ptyName);
        stream = fopen(ptyName, "w");
        SetDumpToStream(stream);
    } else {
        SetDumpToStream(stdout);
    }
    APPSPAPWN_DUMP("Dump appspawn info start ... ");
    APPSPAPWN_DUMP("APP spawning queue: ");
    OH_ListTraversal((ListNode *)&g_appSpawnMgr->appSpawnQueue, NULL, DumpAppSpawnQueue, 0);
    APPSPAPWN_DUMP("APP queue: ");
    OH_ListTraversal((ListNode *)&g_appSpawnMgr->appQueue, "App queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("APP died queue: ");
    OH_ListTraversal((ListNode *)&g_appSpawnMgr->diedQueue, "App died queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("Ext data: ");
    OH_ListTraversal((ListNode *)&g_appSpawnMgr->extData, "Ext data", DumpExtData, 0);
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

int ProcessTerminationStatusMsg(const AppSpawnMsgNode *message, AppSpawnResult *result)
{
    APPSPAWN_CHECK_ONLY_EXPER(g_appSpawnMgr != NULL && message != NULL, return -1);
    APPSPAWN_CHECK_ONLY_EXPER(result != NULL, return -1);
    if (!IsNWebSpawnMode(g_appSpawnMgr)) {
        return APPSPAWN_MSG_INVALID;
    }
    result->result = -1;
    result->pid = 0;
    pid_t *pid = (pid_t *)GetAppSpawnMsgInfo(message, TLV_RENDER_TERMINATION_INFO);
    if (pid == NULL) {
        return -1;
    }
    // get render process termination status, only nwebspawn need this logic.
    result->pid = *pid;
    result->result = GetProcessTerminationStatus(*pid);
    return 0;
}