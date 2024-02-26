/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
    AppProperty *property = ListEntry(node, AppProperty, node);
    AppMgrDeleteAppProperty(property);
}

int AppSpawnAppMgrInit(AppSpawnAppMgr *mgr)
{
    OH_ListInit(&mgr->appQueue);
    OH_ListInit(&mgr->diedQueue);
    OH_ListInit(&mgr->appSpawnQueue);
    mgr->diedAppCount = 0;
    return 0;
}

int AppSpawnAppMgrDestroy(AppSpawnAppMgr *mgr)
{
    OH_ListRemoveAll(&mgr->appQueue, NULL);
    OH_ListRemoveAll(&mgr->diedQueue, NULL);
    OH_ListRemoveAll(&mgr->appSpawnQueue, AppPropertyDestroyProc);
    return 0;
}

static int AppInfoPidComparePro(ListNode *node, void *data)
{
    AppSpawnAppInfo *node1 = ListEntry(node, AppSpawnAppInfo, node);
    pid_t pid = *(pid_t *)data;
    return node1->pid - pid;
}

static int AppInfoNameComparePro(ListNode *node, void *data)
{
    AppSpawnAppInfo *node1 = ListEntry(node, AppSpawnAppInfo, node);
    return strcmp(node1->name, (char *)data);
}

static int AppInfoCompareProc(ListNode *node, ListNode *newNode)
{
    AppSpawnAppInfo *node1 = ListEntry(node, AppSpawnAppInfo, node);
    AppSpawnAppInfo *node2 = ListEntry(newNode, AppSpawnAppInfo, node);
    return node1->pid - node2->pid;
}

AppSpawnAppInfo *AppMgrAddApp(AppSpawnAppMgr *mgr, pid_t pid, const char *processName)
{
    size_t len = strlen(processName) + 1;
    AppSpawnAppInfo *node = (AppSpawnAppInfo *)malloc(sizeof(AppSpawnAppInfo) + len + 1);
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to malloc for appinfo");

    node->pid = pid;
    node->max = 0;
    node->exitStatus = 0;
    int ret = strcpy_s(node->name, len, processName);
    APPSPAWN_CHECK(ret == 0, free(node);
        return NULL, "Failed to strcpy process name");

    OH_ListInit(&node->node);
    OH_ListAddWithOrder(&mgr->appQueue, &node->node, AppInfoCompareProc);
    APPSPAWN_LOGI("Add %{public}s, pid=%{public}d success", processName, pid);
    return node;
}

void AppMgrHandleAppDied(AppSpawnAppMgr *mgr, AppSpawnAppInfo *node, int nwebspawn)
{
    if (!nwebspawn) {
        OH_ListRemove(&node->node);
        free(node);
        return;
    }
    if (mgr->diedAppCount) {
        AppSpawnAppInfo *oldApp = ListEntry(&mgr->diedQueue.next, AppSpawnAppInfo, node);
        OH_ListRemove(&oldApp->node);
        free(node);
        mgr->diedAppCount--;
    }
    OH_ListRemove(&node->node);
    OH_ListInit(&node->node);
    OH_ListAddTail(&mgr->diedQueue, &node->node);
    mgr->diedAppCount++;
}

AppSpawnAppInfo *GetAppInfo(AppSpawnAppMgr *mgr, pid_t pid)
{
    ListNode *node = OH_ListFind(&mgr->appQueue, &pid, AppInfoPidComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnAppInfo, node);
}

AppSpawnAppInfo *GetAppInfoByName(AppSpawnAppMgr *mgr, const char *name)
{
    ListNode *node = OH_ListFind(&mgr->appQueue, (void *)name, AppInfoNameComparePro);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppSpawnAppInfo, node);
}

int GetProcessTerminationStatus(AppSpawnAppMgr *mgr, pid_t pid)
{
    APPSPAWN_LOGE("GetProcessTerminationStatus pid: %{public}d ", pid);
    if (pid <= 0) {
        return 0;
    }
    int exitStatus = 0;
    ListNode *node = OH_ListFind(&mgr->diedQueue, &pid, AppInfoPidComparePro);
    if (node != NULL) {
        AppSpawnAppInfo *info = ListEntry(node, AppSpawnAppInfo, node);
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

AppProperty *AppMgrCreateAppProperty(AppSpawnAppMgr *mgr, uint32_t tlvCount)
{
    static uint32_t requestId = 0;
    size_t size = sizeof(AppProperty) + tlvCount * sizeof(uint32_t);
    AppProperty *property = (AppProperty *)malloc(size);
    APPSPAWN_CHECK(property != NULL, return NULL, "Failed to create AppProperty ");
    (void)memset_s(property, size, 0, size);
    property->client.id = ++requestId;
    property->watcherHandle = NULL;
    property->connection = NULL;
    property->timer = NULL;
    property->msg = NULL;
    property->pid = 0;
    property->fd[0] = -1;
    property->fd[1] = -1;
    property->state = APP_STATE_IDLE;
    property->tlvCount = tlvCount;
    OH_ListInit(&property->node);
    OH_ListAddTail(&mgr->appSpawnQueue, &property->node);
    return property;
}

void AppMgrDeleteAppProperty(AppProperty *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    if (property->msg) {
        free(property->msg);
        property->msg = NULL;
    }
    OH_ListRemove(&property->node);
    if (property->timer) {
        LE_StopTimer(LE_GetDefaultLoop(), property->timer);
        property->timer = NULL;
    }
    if (property->watcherHandle) {
        LE_RemoveWatcher(LE_GetDefaultLoop(), property->watcherHandle);
        property->watcherHandle = NULL;
    }
    if (property->fd[0] >= 0) {
        close(property->fd[0]);
    }
    if (property->fd[1] >= 0) {
        close(property->fd[1]);
    }
    free(property);
}

static int AppPropertyCompareConnection(ListNode *node, void *data)
{
    AppProperty *property = ListEntry(node, AppProperty, node);
    if (property->connection == (AppSpawnConnection *)data) {
        return 0;
    }
    return 1;
}

static int AppPropertyComparePid(ListNode *node, void *data)
{
    AppProperty *property = ListEntry(node, AppProperty, node);
    if (property->pid == *(pid_t *)data) {
        return 0;
    }
    return 1;
}

void AppMgrHandleConnectClose(AppSpawnAppMgr *mgr, const AppSpawnConnection *connection)
{
    ListNode *node = OH_ListFind(&mgr->appSpawnQueue, (void *)connection, AppPropertyCompareConnection);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return);

    AppProperty *property = ListEntry(node, AppProperty, node);
    if (property->state == APP_STATE_SPAWNING) {
        APPSPAWN_LOGI("Kill process, pid: %{public}d app: %{public}s", property->pid, GetProcessName(property));
        if (kill(property->pid, SIGKILL) != 0) {
            APPSPAWN_LOGE("unable to kill process, pid: %{public}d errno: %{public}d", property->pid, errno);
        }
        AppMgrDeleteAppProperty(property);
    }
}

AppProperty *GetAppPropertyByPid(AppSpawnAppMgr *mgr, pid_t pid)
{
    ListNode *node = OH_ListFind(&mgr->appSpawnQueue, (void *)&pid, AppPropertyComparePid);
    APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return NULL);
    return ListEntry(node, AppProperty, node);
}

int TestAppPropertyFlags(const struct AppProperty_ *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return 0, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    uint32_t blockIndex = index / 32;  // 32 max bit in int
    uint32_t bitIndex = index % 32;    // 32 max bit in int
    APPSPAWN_CHECK(blockIndex < msgFlags->count, return 0,
        "Invalid index %{public}d max: %{public}d", index, msgFlags->count);
    return TEST_FLAGS_BY_INDEX(msgFlags->flags[blockIndex], bitIndex); //msgFlags->flags[blockIndex] & (1 << bitIndex);
}

int SetAppPropertyFlags(const struct AppProperty_ *property, uint32_t type, uint32_t index)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, type);
    APPSPAWN_CHECK(msgFlags != NULL, return -1, "No tlv %{public}d in msg %{public}s", type, GetProcessName(property));
    return SetAppSpawnMsgFlags(msgFlags, index);
}

int IsNWebSpawnMode(const struct AppSpawnContentExt_ *content)
{
    return content->content.mode == MODE_FOR_NWEBSPAWN || content->content.mode == MODE_FOR_NWEB_COLD_RUN;
}

int IsColdRunMode(const struct AppSpawnContentExt_ *content)
{
    return content->content.mode == MODE_FOR_APP_COLD_RUN || content->content.mode == MODE_FOR_NWEB_COLD_RUN;
}

int IsDeveloperModeOn(const AppProperty *property)
{
    return (property->client.flags & APP_DEVELOPER_MODE) == APP_DEVELOPER_MODE;
}

int GetAppPropertyCode(const struct AppProperty_ *appProperty)
{
    return appProperty != NULL && appProperty->msg != NULL ? appProperty->msg->msgType : MAX_TYPE_INVALID;
}

const char *GetProcessName(const struct AppProperty_ *property)
{
    if (property == NULL || property->msg == NULL) {
        return NULL;
    }
    return property->msg->processName;
}

const char *GetBundleName(const struct AppProperty_ *property)
{
    AppSpawnMsgBundleInfo *info = GetAppProperty(property, TLV_BUNDLE_INFO);
    if (info != NULL) {
        return info->bundleName;
    }
    return NULL;
}

void *GetAppProperty(const struct AppProperty_ *property, uint32_t type)
{
    if (type >= TLV_MAX || property == NULL || property->msg == NULL ) {
        return NULL;
    }
    if (property->tlvOffset[type] < sizeof(AppSpawnMsg) || property->tlvOffset[type] >= property->msg->msgLen) {
        return NULL;
    }
    return (void *)(((uint8_t *)property->msg) + property->tlvOffset[type] + sizeof(AppSpawnTlv));
}

uint8_t *GetAppPropertyEx(const struct AppProperty_ *property, const char *name, uint32_t *len)
{
    if (name == NULL || property == NULL || property->msg == NULL) {
        return NULL;
    }
    APPSPAWN_LOGI("GetAppPropertyEx tlvCount %{public}d name %{public}s", property->tlvCount, name);
    for (uint32_t index = TLV_MAX; index < (TLV_MAX + property->tlvCount); index++) {
        if (property->tlvOffset[index] < sizeof(AppSpawnMsg) || property->tlvOffset[index] >= property->msg->msgLen) {
            continue;
        }
        uint8_t *data = ((uint8_t *)property->msg) + property->tlvOffset[index];
        if (((AppSpawnTlv *)data)->tlvType != TLV_MAX) {
            continue;
        }
        AppSpawnTlvEx *tlv = (AppSpawnTlvEx *)data;
        APPSPAWN_LOGI("GetAppPropertyEx name %{public}s", tlv->tlvName);
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

static void DumpAppProperty(const AppProperty *property, const char *info)
{
    APPSPAPWN_DUMP("%{public}s app property id: %{public}u flags: %{public}x",
        info, property->client.id, property->client.flags);
    APPSPAPWN_DUMP("%{public}s app property state: %{public}d", info, property->state);
    if (property->msg) {
        APPSPAPWN_DUMP("%{public}s app property msgId: %{public}u msgLen: %{public}u tlvCount: %{public}u",
            info, property->msg->msgId, property->msg->msgLen, property->msg->tlvCount);
        APPSPAPWN_DUMP("%{public}s app property process name: %{public}s", info, property->msg->processName);
    }
    DumpNormalProperty(property, ((uint8_t *)property->msg) + sizeof(AppSpawnTlv));

    for (uint32_t index = TLV_MAX; index < property->tlvCount; index++) {
        if (property->tlvOffset[index] < sizeof(AppSpawnMsg) || property->tlvOffset[index] >= property->msg->msgLen) {
            continue;;
        }
        AppSpawnTlvEx *tlv = (AppSpawnTlvEx *)(((uint8_t *)property->msg) + property->tlvOffset[index]);
        APPSPAPWN_DUMP("%{public}s app property tlv: %{public}u %{public}u name: %{public}s dataLen: %{public}u",
            info, tlv->tlvType, tlv->tlvLen, tlv->tlvName, tlv->dataLen);
    }
}

static int DumpAppSpawnQueue(ListNode *node, void *data)
{
    AppProperty *property = ListEntry(node, AppProperty, node);
    DumpAppProperty(property, "");
    return 0;
}

static int DumpAppQueue(ListNode *node, void *data)
{
    AppSpawnAppInfo *appInfo = ListEntry(node, AppSpawnAppInfo, node);
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

void DumpApSpawn(const AppSpawnContentExt *content)
{
    APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return);
    APPSPAPWN_DUMP("APP spawning queue: ");
    OH_ListTraversal((ListNode *)&content->appMgr.appSpawnQueue, NULL, DumpAppSpawnQueue, 0);
    APPSPAPWN_DUMP("APP queue: ");
    OH_ListTraversal((ListNode *)&content->appMgr.appQueue, "App queue", DumpAppQueue, 0);
    APPSPAPWN_DUMP("APP died queue: ");
    OH_ListTraversal((ListNode *)&content->appMgr.diedQueue, "App died queue", DumpAppQueue, 0);
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

void DumpNormalProperty(const AppProperty *property, const uint8_t *buffer)
{
    DumpMsgFlags("property flags", (AppSpawnMsgFlags *)(buffer + property->tlvOffset[TLV_MSG_FLAGS]));
    DumpMsgFlags("permission flags", (AppSpawnMsgFlags *)(buffer + property->tlvOffset[TLV_PERMISSION]));
    AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)(buffer + property->tlvOffset[TLV_DAC_INFO]);
    APPSPAPWN_DUMP("App dac info uid: %{public}d gid: %{public}d count: %{public}d userName: %{public}s",
        dacInfo->uid, dacInfo->gid, dacInfo->gidCount, dacInfo->userName);

    if (property->tlvOffset[TLV_BUNDLE_INFO] > 0) {
        AppSpawnMsgBundleInfo *bundleInfo = (AppSpawnMsgBundleInfo *)(buffer + property->tlvOffset[TLV_BUNDLE_INFO]);
        APPSPAPWN_DUMP("bundle info bundleName: \"%{public}s\" %{public}d",
            bundleInfo->bundleName, bundleInfo->bundleIndex);
    }
    if (property->tlvOffset[TLV_DOMAIN_INFO] > 0) {
        AppSpawnMsgDomainInfo *info = (AppSpawnMsgDomainInfo *)(buffer + property->tlvOffset[TLV_DOMAIN_INFO]);
        APPSPAPWN_DUMP("domain info hap flags: 0x%{public}x apl: \"%{public}s\"", info->hapFlags, info->apl);
    }
    if (property->tlvOffset[TLV_OWNER_INFO] > 0) {
        AppSpawnMsgOwnerId *info = (AppSpawnMsgOwnerId *)(buffer + property->tlvOffset[TLV_OWNER_INFO]);
        APPSPAPWN_DUMP("owner info: \"%{public}s\" ", info->ownerId);
    }
    if (property->tlvOffset[TLV_RENDER_CMD] > 0) {
        AppSpawnMsgRenderCmd *info = (AppSpawnMsgRenderCmd *)(buffer + property->tlvOffset[TLV_RENDER_CMD]);
        APPSPAPWN_DUMP("Render cmd: \"%{public}s\" ", info->renderCmd);
    }
    if (property->tlvOffset[TLV_ACCESS_TOKEN_INFO] > 0) {
        AppAccessTokenInfo *tokenInfo = (AppAccessTokenInfo *)(buffer + property->tlvOffset[TLV_ACCESS_TOKEN_INFO]);
        APPSPAPWN_DUMP("App accessTokenId: %{public}u %{public}" PRId64 "",
            tokenInfo->accessTokenId, tokenInfo->accessTokenIdEx);
    }
}