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
    AppSpawnedProcess *node = (AppSpawnedProcess *)malloc(sizeof(AppSpawnedProcess) + len + 1);
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to malloc for appinfo");

    node->pid = pid;
    node->max = 0;
    node->uid = 0;
    node->exitStatus = 0;
    int ret = strcpy_s(node->name, len, processName);
    APPSPAWN_CHECK(ret == 0, free(node);
        return NULL, "Failed to strcpy process name");

    OH_ListInit(&node->node);
    OH_ListAddWithOrder(&mgr->appQueue, &node->node, AppInfoCompareProc);
    APPSPAWN_LOGI("Add %{public}s, pid=%{public}d success", processName, pid);
    return node;
}

void HandleProcessTerminate(AppSpawnedProcessMgr *mgr, AppSpawnedProcess *node, int nwebspawn)
{
    if (!nwebspawn) {
        OH_ListRemove(&node->node);
        free(node);
        return;
    }
    if (mgr->diedAppCount) {
        AppSpawnedProcess *oldApp = ListEntry(&mgr->diedQueue.next, AppSpawnedProcess, node);
        OH_ListRemove(&oldApp->node);
        free(node);
        mgr->diedAppCount--;
    }
    OH_ListRemove(&node->node);
    OH_ListInit(&node->node);
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

    pid_t exitPid = waitpid(pid, &exitStatus, WNOHANG);
    if (exitPid != pid) {
        APPSPAWN_LOGE("waitpid failed, return : %{public}d, pid: %{public}d, status: %{public}d",
            exitPid, pid, exitStatus);
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
    property->forkCtx.timer = NULL;
    property->forkCtx.fd[0] = -1;
    property->forkCtx.fd[1] = -1;
    property->connection = NULL;
    property->receiver = NULL;
    property->pid = 0;
    property->state = APP_STATE_IDLE;
    OH_ListInit(&property->node);
    OH_ListAddTail(&mgr->appSpawnQueue, &property->node);
    return property;
}

void DeleteAppSpawnMsgReceiver(AppSpawnMsgReceiverCtx *receiver)
{
    if (receiver == NULL) {
        return;
    }
    if (receiver->buffer) {
        free(receiver->buffer);
        receiver->buffer = NULL;
    }
    if (receiver->tlvOffset) {
        free(receiver->tlvOffset);
        receiver->tlvOffset = NULL;
    }
    if (receiver->timer) {
        LE_StopTimer(LE_GetDefaultLoop(), receiver->timer);
        receiver->timer = NULL;
    }
    receiver->msgRecvLen = 0;
    free(receiver);
}

void DeleteAppSpawningCtx(AppSpawningCtx *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    DeleteAppSpawnMsgReceiver(property->receiver);
    OH_ListRemove(&property->node);
    if (property->forkCtx.timer) {
        LE_StopTimer(LE_GetDefaultLoop(), property->forkCtx.timer);
        property->forkCtx.timer = NULL;
    }
    if (property->forkCtx.watcherHandle) {
        LE_RemoveWatcher(LE_GetDefaultLoop(), property->forkCtx.watcherHandle);
        property->forkCtx.watcherHandle = NULL;
    }
    if (property->forkCtx.fd[0] >= 0) {
        close(property->forkCtx.fd[0]);
    }
    if (property->forkCtx.fd[1] >= 0) {
        close(property->forkCtx.fd[1]);
    }
    free(property);
}

static int AppPropertyCompareConnection(ListNode *node, void *data)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    if (property->connection == (AppSpawnConnection *)data) {
        return 0;
    }
    return 1;
}

static int AppPropertyComparePid(ListNode *node, void *data)
{
    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    if (property->pid == *(pid_t *)data) {
        return 0;
    }
    return 1;
}

void AppMgrHandleConnectClose(AppSpawnedProcessMgr *mgr, const AppSpawnConnection *connection)
{
    ListNode *node = OH_ListFind(&mgr->appSpawnQueue, (void *)connection, AppPropertyCompareConnection);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return);

    AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
    if (property->state == APP_STATE_SPAWNING) {
        APPSPAWN_LOGI("Kill process, pid: %{public}d app: %{public}s", property->pid, GetProcessName(property));
        if (kill(property->pid, SIGKILL) != 0) {
            APPSPAWN_LOGE("unable to kill process, pid: %{public}d errno: %{public}d", property->pid, errno);
        }
        DeleteAppSpawningCtx(property);
    }
}

AppSpawningCtx *GetAppSpawningCtxByPid(AppSpawnedProcessMgr *mgr, pid_t pid)
{
    ListNode *node = OH_ListFind(&mgr->appSpawnQueue, (void *)&pid, AppPropertyComparePid);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawningCtx, node);
}

int TestAppPropertyFlags(const struct tagAppSpawningCtx *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return 0, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    uint32_t blockIndex = index / 32;  // 32 max bit in int
    uint32_t bitIndex = index % 32;    // 32 max bit in int
    APPSPAWN_CHECK(blockIndex < msgFlags->count, return 0,
        "Invalid index %{public}d max: %{public}d", index, msgFlags->count);
    return TEST_FLAGS_BY_INDEX(msgFlags->flags[blockIndex], bitIndex);
}

int SetAppPropertyFlags(const struct tagAppSpawningCtx *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return -1, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    return SetAppSpawnMsgFlags(msgFlags, index);
}

int IsNWebSpawnMode(const struct tagAppSpawnMgr *content)
{
    return content->content.mode == MODE_FOR_NWEBSPAWN || content->content.mode == MODE_FOR_NWEB_COLD_RUN;
}

int IsColdRunMode(const struct tagAppSpawnMgr *content)
{
    return content->content.mode == MODE_FOR_APP_COLD_RUN || content->content.mode == MODE_FOR_NWEB_COLD_RUN;
}

int IsDeveloperModeOn(const AppSpawningCtx *property)
{
    return (property->client.flags & APP_DEVELOPER_MODE) == APP_DEVELOPER_MODE;
}

int GetAppPropertyCode(const struct tagAppSpawningCtx *appProperty)
{
    return (appProperty != NULL && appProperty->receiver != NULL) ?
        appProperty->receiver->msgHeader.msgType : MAX_TYPE_INVALID;
}

const char *GetProcessName(const struct tagAppSpawningCtx *property)
{
    if (property == NULL || property->receiver == NULL) {
        return NULL;
    }
    return property->receiver->msgHeader.processName;
}

const char *GetBundleName(const struct tagAppSpawningCtx *property)
{
    AppSpawnMsgBundleInfo *info = GetAppProperty(property, TLV_BUNDLE_INFO);
    if (info != NULL) {
        return info->bundleName;
    }
    return NULL;
}

void *GetAppProperty(const struct tagAppSpawningCtx *property, uint32_t type)
{
    APPSPAWN_CHECK(type < TLV_MAX, return NULL, "Invalid tlv type %{public}u", type);
    APPSPAWN_CHECK(property != NULL && property->receiver != NULL && property->receiver->buffer != NULL,
        return NULL, "Invalid property for type %{public}u", type);
    APPSPAWN_CHECK(property->receiver->tlvOffset[type] < (property->receiver->msgHeader.msgLen - sizeof(AppSpawnMsg)),
        return NULL, "Invalid tlv tlvOffset %{public}u", property->receiver->tlvOffset[type]);
    return (void *)(property->receiver->buffer + property->receiver->tlvOffset[type] + sizeof(AppSpawnTlv));
}

uint8_t *GetAppPropertyEx(const struct tagAppSpawningCtx *property, const char *name, uint32_t *len)
{
    APPSPAWN_CHECK(name != NULL, return NULL, "Invalid name ");
    APPSPAWN_CHECK(property != NULL && property->receiver != NULL && property->receiver->buffer != NULL,
        return NULL, "Invalid property for name %{public}s", name);

    APPSPAWN_LOGV("GetAppPropertyEx tlvCount %{public}d name %{public}s", property->receiver->tlvCount, name);
    for (uint32_t index = TLV_MAX; index < (TLV_MAX + property->receiver->tlvCount); index++) {
        if (property->receiver->tlvOffset[index] >= (property->receiver->msgHeader.msgLen - sizeof(AppSpawnMsg))) {
            return NULL;
        }
        uint8_t *data = property->receiver->buffer + property->receiver->tlvOffset[index];
        if (((AppSpawnTlv *)data)->tlvType != TLV_MAX) {
            continue;
        }
        AppSpawnTlvEx *tlv = (AppSpawnTlvEx *)data;
        if (strcmp(tlv->tlvName, name) != 0) {
            continue;
        }
        if (len != NULL) {
            *len = tlv->dataLen;
        }
        return data + sizeof(AppSpawnTlvEx);
    }
    return NULL;
}

static void DumpAppProperty(const AppSpawningCtx *property, const char *info)
{
    APPSPAPWN_DUMP("%{public}s app property id: %{public}u flags: %{public}x",
        info, property->client.id, property->client.flags);
    APPSPAPWN_DUMP("%{public}s app property state: %{public}d", info, property->state);
    if (property->receiver) {
        APPSPAPWN_DUMP("%{public}s app property msgId: %{public}u msgLen: %{public}u tlvCount: %{public}u",
            info, property->receiver->msgHeader.msgId, property->receiver->msgHeader.msgLen, property->receiver->tlvCount);
        APPSPAPWN_DUMP("%{public}s app property process name: %{public}s", info, property->receiver->msgHeader.processName);
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
    APPSPAPWN_DUMP("APP in %{public}s info uid: %{public}u pid: %{public}x", (char *)data, appInfo->uid, appInfo->pid);
    APPSPAPWN_DUMP("APP in %{public}s info name: %{public}s exitStatus: %{public}d",
        (char *)data, appInfo->name, appInfo->exitStatus);
    return 0;
}

static int DumpExtData(ListNode *node, void *data)
{
    AppSpawnDataEx *dataEx = ListEntry(node, AppSpawnDataEx, node);
    dataEx->dumpNode(dataEx);
    return 0;
}

void DumpApSpawn(const AppSpawnMgr *content)
{
    APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return);
    APPSPAPWN_DUMP("APP spawning queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.appSpawnQueue, NULL, DumpAppSpawnQueue, 0);
    APPSPAPWN_DUMP("APP queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.appQueue, "App queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("APP died queue: ");
    OH_ListTraversal((ListNode *)&content->processMgr.diedQueue, "App died queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("Ext data: ");
    OH_ListTraversal((ListNode *)&content->extData, "Ext data", DumpExtData, 0);
}

static inline void DumpMsgFlags(const char *info, const AppSpawnMsgFlags *msgFlags)
{
    APPSPAPWN_DUMP("%{public}s count: %{public}u ", info, msgFlags->count);
    for (uint32_t i = 0; i < msgFlags->count; i++) {
        APPSPAPWN_DUMP("%{public}s flags: 0x%{public}x", info, msgFlags->flags[i]);
    }
}

void DumpNormalProperty(const AppSpawningCtx *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL && property->receiver != NULL, return);
    for (uint32_t i = 0; i < TLV_MAX + property->receiver->tlvCount; i++) {
        if (property->receiver->tlvOffset[i] == INVALID_OFFSET) {
            continue;
        }
        AppSpawnTlv *tlv = (AppSpawnTlv *)(property->receiver->buffer + property->receiver->tlvOffset[i]);
        switch (tlv->tlvType) {
            case TLV_MSG_FLAGS:
                DumpMsgFlags("property flags", (AppSpawnMsgFlags *)(tlv + 1));
                break;
            case TLV_PERMISSION:
                DumpMsgFlags("permission flags", (AppSpawnMsgFlags *)(tlv + 1));
                break;
            case TLV_ACCESS_TOKEN_INFO:
                APPSPAPWN_DUMP("App accessTokenId: %{public}u %{public}" PRId64 "",
                    ((AppSpawnMsgAccessToken *)(tlv + 1))->accessTokenId,
                    ((AppSpawnMsgAccessToken *)(tlv + 1))->accessTokenIdEx);
                break;
            case TLV_DAC_INFO: {
                AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)(tlv + 1);
                APPSPAPWN_DUMP("App dac info uid: %{public}d gid: %{public}d count: %{public}d userName: %{public}s",
                    dacInfo->uid, dacInfo->gid, dacInfo->gidCount, dacInfo->userName);
                break;
            }
            case TLV_BUNDLE_INFO:
                APPSPAPWN_DUMP("bundle info bundleName: \"%{public}s\" %{public}d",
                    ((AppSpawnMsgBundleInfo *)(tlv + 1))->bundleName,
                    ((AppSpawnMsgBundleInfo *)(tlv + 1))->bundleIndex);
                break;
            case TLV_OWNER_INFO:
                APPSPAPWN_DUMP("owner info: \"%{public}s\" ", ((AppSpawnMsgOwnerId *)(tlv + 1))->ownerId);
                break;
            case TLV_DOMAIN_INFO:
                APPSPAPWN_DUMP("domain info hap flags: 0x%{public}x apl: \"%{public}s\"",
                    ((AppSpawnMsgDomainInfo *)(tlv + 1))->hapFlags, ((AppSpawnMsgDomainInfo *)(tlv + 1))->apl);
                break;
            case TLV_MAX: {
                AppSpawnTlvEx *tlvEx = (AppSpawnTlvEx *)(tlv);
                APPSPAPWN_DUMP("App extend tlv name: %{public}s %{public}u '%{public}s'",
                    tlvEx->tlvName, tlvEx->dataLen, (char *)(tlvEx + 1));
                break;
            }
            default:
                break;
        }
    }
}