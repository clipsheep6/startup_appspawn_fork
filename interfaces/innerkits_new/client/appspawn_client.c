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

#include "appspawn_client.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "appspawn_mount_permission.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "securec.h"

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static AppSpawnReqMgr *g_clientInstance[CLIENT_NAX] = {NULL};

static AppSpawnMsgBlock *CreateAppSpawnMsgBlock(AppSpawnReqNode *reqNode)
{
    uint32_t realLen = sizeof(AppSpawnMsgBlock) + MAX_MSG_BLOCK_LEN;
    AppSpawnMsgBlock *block = (AppSpawnMsgBlock *)calloc(1, realLen);
    APPSPAWN_CHECK(block != NULL, return NULL, "Failed to create block");
    OH_ListInit(&block->node);
    block->blockSize = MAX_MSG_BLOCK_LEN;
    block->currentIndex = 0;
    OH_ListAddTail(&reqNode->msgBlocks, &block->node);
    return block;
}

static AppSpawnMsgBlock *GetValidMsgBlock(const AppSpawnReqNode *reqNode, uint32_t realLen)
{
    AppSpawnMsgBlock *block = NULL;
    struct ListNode *node = reqNode->msgBlocks.next;
    while (node != &reqNode->msgBlocks) {
        block = ListEntry(node, AppSpawnMsgBlock, node);
        if ((block->blockSize - block->currentIndex) >= realLen) {
            return block;
        }
        node = node->next;
    }
    return NULL;
}

static AppSpawnMsgBlock *GetTailMsgBlock(const AppSpawnReqNode *reqNode)
{
    AppSpawnMsgBlock *block = NULL;
    struct ListNode *node = reqNode->msgBlocks.next;
    if (node != &reqNode->msgBlocks) {
        block = ListEntry(node, AppSpawnMsgBlock, node);
        return block;
    }
    return NULL;
}

static void FreeMsgBlock(ListNode *node)
{
    AppSpawnMsgBlock *block = ListEntry(node, AppSpawnMsgBlock, node);
    OH_ListRemove(node);
    OH_ListInit(node);
    free(block);
}

static int AddAppDataToBlock(AppSpawnMsgBlock *block, const uint8_t *data, uint32_t dataLen)
{
    APPSPAWN_CHECK(block->blockSize > block->currentIndex, return -1, "Not enough buffer for data");
    uint32_t reminderLen = block->blockSize - block->currentIndex;
    APPSPAWN_CHECK(reminderLen >= APPSPAWN_ALIGN(dataLen), return -1, "Not enough buffer for data");

    int ret = memcpy_s(block->buffer + block->currentIndex, reminderLen, data, dataLen);
    APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy data");
    block->currentIndex += APPSPAWN_ALIGN(dataLen);
    //APPSPAWN_LOGV("AddAppDataToBlock currentIndex: %{public}u dataLen: %{public}u", block->currentIndex, dataLen);
    return 0;
}

static int AddAppDataToTail(AppSpawnReqNode *reqNode, const uint8_t *data, uint32_t dataLen)
{
    // 最后一个block有有效空间, 则保存部分数据，剩余的申请新的block保存
    uint32_t currLen = 0;
    AppSpawnMsgBlock *block = GetTailMsgBlock(reqNode);
    APPSPAWN_CHECK(block != NULL, return -1, "Not block info reqNode");
    APPSPAWN_LOGV("AddAppDataToTail currentIndex: %{public}u dataLen: %{public}u ", block->currentIndex, dataLen);
    do {
        uint32_t reminderBufferLen = block->blockSize - block->currentIndex;
        uint32_t reminderDataLen = dataLen - currLen;
        uint32_t realLen = APPSPAWN_ALIGN(reminderDataLen);
        uint32_t realCopy = 0;
        APPSPAWN_LOGV("AddAppDataToTail reminderBuffer: %{public}u currLen: %{public}u reminderData: %{public}u ",
            reminderBufferLen, currLen, reminderDataLen);
        if (reminderBufferLen >= realLen) {  // 足够存储，直接保存
            int ret = memcpy_s(block->buffer + block->currentIndex, reminderBufferLen, data + currLen, reminderDataLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy data");
            block->currentIndex += realLen;
            break;
        } else if (reminderBufferLen > 0) {  // 按实际大小保存
            realCopy = reminderDataLen > reminderBufferLen ? reminderBufferLen : reminderDataLen;
            int ret = memcpy_s(block->buffer + block->currentIndex, reminderBufferLen, data + currLen, realCopy);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy data");
            block->currentIndex += realCopy;
            currLen += realCopy;
        }
        block = CreateAppSpawnMsgBlock(reqNode);
        APPSPAWN_CHECK(block != NULL, return -1, "Not enough buffer for data");
        if (currLen == dataLen) {  // 实际数据已经完成，但是需要补齐对齐造成的扩展
            block->currentIndex += realLen - realCopy;
        }
        APPSPAWN_LOGV("AddAppDataToTail currentIndex: %{public}u currLen: %{public}u", block->currentIndex, currLen);
    } while (currLen < dataLen);
    return 0;
}

static int AddAppDataEx(AppSpawnReqNode *reqNode, const char *name, const AppSpawnAppData *data)
{
    APPSPAWN_CHECK(reqNode != NULL && reqNode->msg != NULL, return -1, "Invalid msg node for %{public}s", name);
    AppSpawnTlvEx tlv = {};
    tlv.tlvLen = APPSPAWN_ALIGN(data->dataLen) + sizeof(AppSpawnTlvEx);
    tlv.tlvType = TLV_MAX;
    tlv.dataLen = data->dataLen;
    int ret = strcpy_s(tlv.tlvName, sizeof(tlv.tlvName), name);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}s", name);
    APPSPAWN_LOGV("AddAppDataEx tlv [%{public}s %{public}u %{public}u] current msgLen: %{public}u",
        name, tlv.tlvLen, data->dataLen, reqNode->msg->msgLen);

    // 获取一个能保存改完整tlv的block
    AppSpawnMsgBlock *block = GetValidMsgBlock(reqNode, tlv.tlvLen);
    if (block != NULL) {
        int ret = AddAppDataToBlock(block, (uint8_t *)&tlv, sizeof(tlv));
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv for %{public}s", name);
        ret = AddAppDataToBlock(block, data->data, data->dataLen);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}s", name);
    } else {
        // 没有一个可用的block，最队列最后添加数据
        ret = AddAppDataToTail(reqNode, (uint8_t *)&tlv, sizeof(tlv));
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv to tail for %{public}s", name);
        ret = AddAppDataToTail(reqNode, data->data, data->dataLen);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data to tail for %{public}s", name);
    }
    reqNode->msg->tlvCount++;
    reqNode->msg->msgLen += tlv.tlvLen;
    APPSPAWN_LOGV("AddAppDataEx success name '%{public}s' msgLen: %{public}u", name, reqNode->msg->msgLen);
    return 0;
}

static int AddAppData(AppSpawnReqNode *reqNode, uint32_t tlvType, const AppSpawnAppData data[MAX_DATA_IN_TLV])
{
    // 计算实际数据的长度
    uint32_t realLen = sizeof(AppSpawnTlv);
    for (uint32_t index = 0; index < MAX_DATA_IN_TLV; index++) {
        if (data[index].data == NULL) {
            continue;
        }
        realLen += APPSPAWN_ALIGN(data[index].dataLen);
    }
    AppSpawnTlv tlv;
    tlv.tlvLen = realLen;
    tlv.tlvType = tlvType;
    //APPSPAWN_LOGV("AddAppData tlv: [%{public}d %{public}u] msgLen: %{public}u",
    //    tlvType, tlv.tlvLen, reqNode->msg->msgLen);

    // 获取一个能保存改完整tlv的block
    AppSpawnMsgBlock *block = GetValidMsgBlock(reqNode, tlv.tlvLen);
    if (block != NULL) {
        int ret = AddAppDataToBlock(block, (uint8_t *)&tlv, sizeof(tlv));
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv for %{public}d", tlvType);

        for (uint32_t index = 0; index < MAX_DATA_IN_TLV; index++) {
            if (data[index].data == NULL) {
                continue;
            }
            ret = AddAppDataToBlock(block, (uint8_t *)data[index].data, data[index].dataLen);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}d", tlvType);
        }
    } else {
        // 没有一个可用的block，最队列最后添加数据
        int ret = AddAppDataToTail(reqNode, (uint8_t *)&tlv, sizeof(tlv));
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv to tail for %{public}d", tlvType);
        // 添加tlv信息
        for (uint32_t index = 0; index < MAX_DATA_IN_TLV; index++) {
            if (data[index].data == NULL) {
                continue;
            }
            ret = AddAppDataToTail(reqNode, (uint8_t *)data[index].data, data[index].dataLen);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}d", tlvType);
        }
    }
    reqNode->msg->tlvCount++;
    reqNode->msg->msgLen += tlv.tlvLen;
    //APPSPAWN_LOGV("AddAppData tlv: [%{public}d] success msgLen: %{public}u", tlvType, reqNode->msg->msgLen);
    return 0;
}

static void SetCondAttr(pthread_cond_t *cond)
{
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(cond, &attr);
    pthread_condattr_destroy(&attr);
}

static int InitClientInstance(AppSpawnClientType type)
{
    pthread_mutex_lock(&g_mutex);
    if (g_clientInstance[type] != NULL) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }
    AppSpawnReqMgr *clientInstance = malloc(sizeof(AppSpawnReqMgr) + RECV_BLOCK_LEN);
    if (clientInstance == NULL) {
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    // init
    clientInstance->type = type;
    clientInstance->msgId = 0;
    clientInstance->keepMsg = NULL;
    clientInstance->keepTimeout = 0;
    OH_ListInit(&clientInstance->msgQueue);
    OH_ListInit(&clientInstance->sendQueue);
    OH_ListInit(&clientInstance->waitingQueue);
    pthread_mutex_init(&clientInstance->mutex, NULL);
    SetCondAttr(&clientInstance->notifyMsg);
    atomic_init(&clientInstance->threadExit, 0);
    // init recvBlock
    OH_ListInit(&clientInstance->recvBlock.node);
    clientInstance->recvBlock.blockSize = RECV_BLOCK_LEN;
    clientInstance->recvBlock.currentIndex = 0;

    int ret = pthread_create(&clientInstance->msgThread, NULL, ClientProcessMsg, (void *)clientInstance);
    if (ret != 0) {
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    g_clientInstance[type] = clientInstance;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

int GetMsgSerialNo(AppSpawnReqMgr *reqMgr)
{
    uint32_t msgId = 0;
    pthread_mutex_lock(&g_mutex);
    msgId = ++reqMgr->msgId;
    pthread_mutex_unlock(&g_mutex);
    return msgId;
}

static int SetFlagsTlv(AppSpawnReqNode *reqNode,
    AppSpawnMsgBlock *block, AppSpawnMsgFlags **msgFlags, int type, int maxCount)
{
    uint32_t units = CalcFlagsUnits(maxCount);
    APPSPAWN_LOGV("SetFlagsTlv maxCount %{public}d type %{public}d units %{public}d", maxCount, type, units);
    uint32_t flagsLen = sizeof(AppSpawnTlv) + sizeof(AppSpawnMsgFlags) + sizeof(uint32_t) * units;
    APPSPAWN_CHECK((block->blockSize - block->currentIndex) > flagsLen,
        return -1, "Invalid block to set flags tlv type %{public}d", type);

    AppSpawnTlv *tlv = (AppSpawnTlv *)(block->buffer + block->currentIndex);
    tlv->tlvLen = flagsLen;
    tlv->tlvType = type;
    *msgFlags = (AppSpawnMsgFlags *)(block->buffer + block->currentIndex + sizeof(AppSpawnTlv));
    (*msgFlags)->count = units;
    block->currentIndex += flagsLen;
    reqNode->msg->msgLen += flagsLen;
    reqNode->msg->tlvCount++;
    return 0;
}

static int CreateBaseMsg(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode, uint32_t msgType, const char *processName)
{
    AppSpawnMsgBlock *block = CreateAppSpawnMsgBlock(reqNode);
    APPSPAWN_CHECK(block != NULL, return -1, "Failed to create block for %{public}s", processName);

    // 保留消息头的大小
    reqNode->msg = (AppSpawnMsg *)(block->buffer + block->currentIndex);
    reqNode->msg->magic = APPSPAWN_MSG_MAGIC;
    reqNode->msg->msgId = GetMsgSerialNo(reqMgr);
    reqNode->msg->msgType = msgType;
    reqNode->msg->msgLen = sizeof(AppSpawnMsg);
    reqNode->msg->tlvCount = 0;
    int ret = strcpy_s(reqNode->msg->processName, sizeof(reqNode->msg->processName), processName);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create block for %{public}s", processName);
    block->currentIndex = sizeof(AppSpawnMsg);
    ret = SetFlagsTlv(reqNode, block, &reqNode->msgFlags, TLV_MSG_FLAGS, MAX_FLAGS_INDEX);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    ret = SetFlagsTlv(reqNode, block, &reqNode->permissionFlags, TLV_PERMISSION, GetMaxPermissionIndex());
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    APPSPAWN_LOGV("CreateBaseMsg msgLen: %{public}u %{public}u", reqNode->msg->msgLen, block->currentIndex);
    return 0;
}

AppSpawnReqNode *CreateAppSpawnReq(AppSpawnReqMgr *reqMgr, uint32_t msgType, const char *processName)
{
    AppSpawnReqNode *reqNode = (AppSpawnReqNode *)malloc(sizeof(AppSpawnReqNode));
    APPSPAWN_CHECK(reqNode != NULL, return NULL, "Failed to create msg node for %{public}s", processName);

    OH_ListInit(&reqNode->node);
    OH_ListInit(&reqNode->msgBlocks);
    pthread_mutex_init(&reqNode->mutex, NULL);
    SetCondAttr(&reqNode->cond);
    reqNode->retryCount = 0;
    reqNode->msg = NULL;
    reqNode->msgFlags = NULL;
    reqNode->permissionFlags = NULL;
    reqNode->result.result = APPSPAWN_TIMEOUT;
    reqNode->result.pid = -1;
    atomic_init(&reqNode->state, MSG_STATE_IDLE);

    int ret = CreateBaseMsg(reqMgr, reqNode, msgType, processName);
    APPSPAWN_CHECK(ret == 0, return NULL;
        DeleteAppSpawnReq(reqMgr, reqNode), "Failed to create base msg for %{public}s", processName);
    APPSPAWN_LOGV("CreateAppSpawnReq reqNode: %{public}d msg type: %{public}u processName: %{public}s",
        reqNode->msg->msgId, msgType, processName);
    return reqNode;
}

void DeleteAppSpawnReq(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode)
{
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return);
    if (reqNode->msg) {
        APPSPAWN_LOGV("DeleteAppSpawnReq reqNode: %{public}d", reqNode->msg->msgId);
    }
    reqNode->msgFlags = NULL;
    reqNode->permissionFlags = NULL;
    reqNode->msg = NULL;
    // 释放block
    OH_ListRemoveAll(&reqNode->msgBlocks, FreeMsgBlock);
    pthread_cond_destroy(&reqNode->cond);
    pthread_mutex_destroy(&reqNode->mutex);
    free(reqNode);
    if (reqMgr->keepMsg == reqNode) {
        reqMgr->keepMsg = NULL;
    }
}

static void DestroyReqQueue(AppSpawnReqMgr *reqMgr, struct ListNode *queue)
{
    ListNode *node = queue->next;
    while (node != queue) {
        AppSpawnReqNode *reqNode = ListEntry(node, AppSpawnReqNode, node);
        OH_ListRemove(&reqNode->node);
        OH_ListInit(&reqNode->node);
        DeleteAppSpawnReq(reqMgr, reqNode);
        node = queue->next;
    }
}

static uint32_t GetDefaultTimeout(uint32_t def)
{
    uint32_t value = def;
    char data[32] = {};  // 32 length
    int ret = GetParameter("persist.appspawn.reqMgr.timeout", "0", data, sizeof(data));
    if (ret > 0 && strcmp(data, "0") != 0) {
        errno = 0;
        value = atoi(data);
        return (errno != 0) ? def : value;
    }
    return value;
}

static void GetSpecialGid(const char *bundleName, gid_t gidTable[], uint32_t *gidCount)
{
    // special handle bundle name medialibrary and scanner
    const char *specialBundleNames[] = {
        "com.ohos.medialibrary.medialibrarydata", "com.ohos.medialibrary.medialibrarydata:backup"
    };

    for (size_t i = 0; i < sizeof(specialBundleNames) / sizeof(specialBundleNames[0]); i++) {
        if (strcmp(bundleName, specialBundleNames[i]) == 0) {
            if (*gidCount < APP_MAX_GIDS) {
                gidTable[(*gidCount)++] = GID_USER_DATA_RW;
                gidTable[(*gidCount)++] = GID_FILE_ACCESS;
            }
            break;
        }
    }
}

int AppSpawnClientInit(const char *serviceName, AppSpawnClientHandle *handle)
{
    APPSPAWN_LOGV("AppSpawnClientInit serviceName %{public}s", serviceName);
    AppSpawnClientType type = CLIENT_FOR_APPSPAWN;
    if (strcmp(serviceName, NWEBSPAWN_SERVER_NAME) == 0 || strstr(serviceName, NWEBSPAWN_SOCKET_NAME) != NULL) {
        type = CLIENT_FOR_NWEBSPAWN;
    }
    int ret = InitClientInstance(type);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create reqMgr");
    *handle = (AppSpawnClientHandle)g_clientInstance[type];
    return 0;
}

int AppSpawnClientDestroy(AppSpawnClientHandle handle)
{
    AppSpawnReqMgr *reqMgr = (AppSpawnReqMgr *)handle;
    APPSPAWN_CHECK(reqMgr != NULL, return -1, "Invalid reqMgr");
    pthread_mutex_lock(&g_mutex);
    if (reqMgr->type < sizeof(g_clientInstance) / sizeof(g_clientInstance[0])) {
        g_clientInstance[reqMgr->type] = NULL;
    }
    pthread_mutex_unlock(&g_mutex);

    atomic_store(&reqMgr->threadExit, 1);
    pthread_mutex_lock(&reqMgr->mutex);
    pthread_cond_signal(&reqMgr->notifyMsg);
    pthread_mutex_unlock(&reqMgr->mutex);

    // 等待线程结束
    pthread_join(reqMgr->msgThread, NULL);

    if (reqMgr->keepMsg) {
        OH_ListRemove(&reqMgr->keepMsg->node);
        OH_ListInit(&reqMgr->keepMsg->node);
        DeleteAppSpawnReq(reqMgr, reqMgr->keepMsg);
        reqMgr->keepMsg = NULL;
    }
    DestroyReqQueue(reqMgr, &reqMgr->msgQueue);
    DestroyReqQueue(reqMgr, &reqMgr->sendQueue);
    DestroyReqQueue(reqMgr, &reqMgr->waitingQueue);

    pthread_cond_destroy(&reqMgr->notifyMsg);
    pthread_mutex_destroy(&reqMgr->mutex);
    free(reqMgr);
    // delete all permission
    DeletePermissions();
    return 0;
}

APPSPAWN_STATIC AppSpawnReqNode *GetReqNode(AppSpawnClientHandle handle, uint32_t msgId, int state)
{
    AppSpawnReqMgr *reqMgr = (AppSpawnReqMgr *)handle;
    APPSPAWN_CHECK(reqMgr != NULL, return NULL, "Invalid reqMgr instance");
    AppSpawnReqNode *reqNode = NULL;
    pthread_mutex_lock(&reqMgr->mutex);
    reqNode = FindReqNodeByMsgId(reqMgr, msgId, &reqMgr->msgQueue);
    pthread_mutex_unlock(&reqMgr->mutex);
    APPSPAWN_CHECK(reqNode != NULL, return NULL, "Invalid msg handle");
    APPSPAWN_CHECK(reqNode->msg != NULL, return NULL, "Invalid req message");
    APPSPAWN_CHECK(TEST_REQ_NODE_STATE(reqNode, state), return NULL, "Invalid req state %{public}d", reqNode->state);
    return reqNode;
}

int AppSpawnClientSendMsg(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, AppSpawnResult *result)
{
    APPSPAWN_CHECK(result != NULL, return APPSPAWN_INVALID_ARG, "Invalid result");
    result->result = APPSPAWN_INVALID_ARG;
    result->pid = 0;
    AppSpawnReqMgr *reqMgr = (AppSpawnReqMgr *)handle;
    APPSPAWN_CHECK(reqMgr != NULL, return APPSPAWN_INVALID_ARG, "Invalid reqMgr");
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    uint32_t timeout = GetDefaultTimeout(TIMEOUT_DEF);
    int ret = ClientSendMsg(reqMgr, reqNode, timeout, result);
    if (ret != 0) {
        result->result = ret;
    }
    return result->result;
}

int AppSpawnReqCreate(AppSpawnClientHandle handle,
    uint32_t msgType, const char *processName, AppSpawnReqHandle *reqHandle)
{
    APPSPAWN_CHECK(handle != NULL, return -1, "Invalid reqMgr");
    APPSPAWN_CHECK(processName != NULL, return -1, "Invalid bundle name");
    APPSPAWN_CHECK(reqHandle != NULL, return -1, "Invalid request handle");
    AppSpawnReqMgr *reqMgr = (AppSpawnReqMgr *)handle;
    AppSpawnReqNode *reqNode = CreateAppSpawnReq(reqMgr, msgType, processName);
    APPSPAWN_CHECK(reqNode != NULL, return -1, "Failed to create msg node for %{public}s", processName);
    SafePushReqNode(reqMgr, reqNode, &reqMgr->msgQueue, MSG_STATE_COLLECTION);
    *reqHandle = (AppSpawnReqHandle)(reqNode->msg->msgId);
    return 0;
}

void AppSpawnReqDestroy(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return);
    SafeRemoveReqNode((AppSpawnReqMgr *)handle, reqNode);
    DeleteAppSpawnReq((AppSpawnReqMgr *)handle, reqNode);
}

int AppSpawnReqSetAppDacInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppDacInfo *dacInfo)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(dacInfo != NULL, return -1, "Invalid dacInfo ");

    AppDacInfo tmpDacInfo = {0};
    (void)memcpy_s(&tmpDacInfo, sizeof(tmpDacInfo), dacInfo, sizeof(tmpDacInfo));
    GetSpecialGid(reqNode->msg->processName, tmpDacInfo.gidTable, &tmpDacInfo.gidCount);

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&tmpDacInfo;
    data[0].dataLen = sizeof(AppSpawnMsgDacInfo);
    return AddAppData(reqNode, TLV_DAC_INFO, data);
}

int AppSpawnReqSetBundleInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppBundleInfo *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)info;
    data[0].dataLen = sizeof(AppSpawnMsgBundleInfo);
    data[1].data = (uint8_t *)info->bundleName;
    data[1].dataLen = strlen(info->bundleName) + 1;
    return AddAppData(reqNode, TLV_BUNDLE_INFO, data);
}

int AppSpawnReqSetAppFlag(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, uint32_t flagIndex)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    return SetAppSpawnMsgFlags(reqNode->msgFlags, flagIndex);
}

int AppSpawnReqAddExtInfo(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const char *name, const uint8_t *value, uint32_t valueLen)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(name != NULL && strlen(name) < APPSPAWN_TLV_NAME_LEN, return -1, "Invalid tlv name ");
    APPSPAWN_CHECK(value != NULL, return -1, "Invalid tlv data ");
    APPSPAWN_CHECK((valueLen > 0) && (valueLen < EXTRAINFO_TOTAL_LENGTH_MAX),
        return -1, "Invalid data len %{public}d", valueLen);
    APPSPAWN_LOGV("AppSpawnReqAddExtInfo name %{public}s", name);
    AppSpawnAppData data[1] = {};  // 1 max data count
    data[0].data = (uint8_t *)value;
    data[0].dataLen = valueLen;
    return AddAppDataEx(reqNode, name, data);  // 2 max count
}

int AppSpawnReqSetPermission(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const char **permissions, uint32_t count)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(permissions != NULL, return -1, "Invalid permission ");

    int32_t maxIndex = GetMaxPermissionIndex();
    for (uint32_t i = 0; i < count; i++) {
        int index = GetPermissionIndex(permissions[i]);
        APPSPAWN_CHECK(index >= 0 && index < maxIndex, return -1, "Invalid permission %{public}s", permissions[i]);
        APPSPAWN_LOGV("SetPermission index %{public}d name %{public}s", index, permissions[i]);
        int ret = SetAppSpawnMsgFlags(reqNode->permissionFlags, index);
        APPSPAWN_CHECK(ret == 0, return ret, "Invalid permission %{public}s", permissions[i]);
    }
    return 0;
}

int AppSpawnReqSetAppDomainInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppDomainInfo *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnMsgDomainInfo msgDomainInfo;
    msgDomainInfo.hapFlags = info->hapFlags;

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&msgDomainInfo;
    data[0].dataLen = sizeof(AppSpawnMsgDomainInfo);
    data[1].data = (uint8_t *)info->apl;
    data[1].dataLen = strlen(info->apl) + 1;
    return AddAppData(reqNode, TLV_DOMAIN_INFO, data);
}

int AppSpawnReqSetAppInternetPermissionInfo(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const AppInternetPermissionInfo *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)info;
    data[0].dataLen = sizeof(AppInternetPermissionInfo);
    return AddAppData(reqNode, TLV_INTERNET_INFO, data);
}

int AppSpawnReqSetAppOwnerId(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppOwnerId *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)info->ownerId;
    data[0].dataLen = strlen(info->ownerId) + 1;
    return AddAppData(reqNode, TLV_OWNER_INFO, data);
}

int AppSpawnReqSetAppRenderCmd(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppRenderCmd *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)info->renderCmd;
    data[0].dataLen = strlen(info->renderCmd) + 1;
    return AddAppData(reqNode, TLV_RENDER_CMD, data);
}

int AppSpawnReqSetAppAccessToken(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const AppAccessTokenInfo *info)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(info != NULL, return -1, "Invalid bundle info data");

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)info;
    data[0].dataLen = sizeof(AppAccessTokenInfo);
    return AddAppData(reqNode, TLV_ACCESS_TOKEN_INFO, data);
}

int AppSpawnReqSeFlags(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, uint32_t tlv, uint32_t flags)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    if (tlv == TLV_MSG_FLAGS) {
        *(uint32_t *)reqNode->msgFlags->flags = flags;
    } else if (tlv == TLV_PERMISSION) {
        *(uint32_t *)reqNode->permissionFlags->flags = flags;
    }
    return 0;
}

int AppSpawnReqSetTerminationPid(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, uint32_t pid)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    if (reqNode->msg->msgType != MSG_GET_RENDER_TERMINATION_STATUS) {
        return APPSPAWN_TLV_NOT_SUPPORT;
    }
    AppSpawnResult result = {};
    result.pid = pid;
    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&result;
    data[0].dataLen = sizeof(AppSpawnResult);
    return AddAppData(reqNode, TLV_RENDER_TERMINATION_INFO, data);
}