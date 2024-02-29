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
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <linux/in.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "appspawn_mount_permission.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "securec.h"

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static AppSpawnReqMsgMgr *g_clientInstance[CLIENT_NAX] = {NULL};

static AppSpawnMsgBlock *CreateAppSpawnMsgBlock(AppSpawnReqMsgNode *reqNode)
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

static AppSpawnMsgBlock *GetValidMsgBlock(const AppSpawnReqMsgNode *reqNode, uint32_t realLen)
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

static AppSpawnMsgBlock *GetTailMsgBlock(const AppSpawnReqMsgNode *reqNode)
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

static int AddAppDataToBlock(AppSpawnMsgBlock *block, const uint8_t *data, uint32_t dataLen, int32_t dataType)
{
    APPSPAWN_CHECK(block->blockSize > block->currentIndex, return -1, "Not enough buffer for data");
    uint32_t reminderLen = block->blockSize - block->currentIndex;
    uint32_t realDataLen = (dataType == DATA_TYPE_STRING) ? APPSPAWN_ALIGN(dataLen + 1) : APPSPAWN_ALIGN(dataLen);
    APPSPAWN_CHECK(reminderLen >= realDataLen, return -1, "Not enough buffer for data");
    APPSPAWN_LOGV("AddAppDataToBlock currentIndex: %{public}u dataLen: %{public}u ", block->currentIndex, dataLen);
    int ret = memcpy_s(block->buffer + block->currentIndex, reminderLen, data, dataLen);
    APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy data");
    block->currentIndex += realDataLen;
    if (dataType == DATA_TYPE_STRING) {
        *((char *)block->buffer + block->currentIndex + dataLen) = '\0';
    }
    APPSPAWN_LOGV("AddAppDataToBlock success currentIndex: %{public}u ", block->currentIndex);
    return 0;
}

static int AddAppDataToTail(AppSpawnReqMsgNode *reqNode, const uint8_t *data, uint32_t dataLen, int32_t dataType)
{
    // 最后一个block有有效空间, 则保存部分数据，剩余的申请新的block保存
    uint32_t currLen = 0;
    AppSpawnMsgBlock *block = GetTailMsgBlock(reqNode);
    APPSPAWN_CHECK(block != NULL, return -1, "Not block info reqNode");
    APPSPAWN_LOGV("AddAppDataToTail currentIndex: %{public}u dataLen: %{public}u ", block->currentIndex, dataLen);
    do {
        uint32_t reminderBufferLen = block->blockSize - block->currentIndex;
        uint32_t reminderDataLen = (dataType == DATA_TYPE_STRING) ? dataLen + 1 - currLen : dataLen - currLen;
        uint32_t realLen = APPSPAWN_ALIGN(reminderDataLen);
        uint32_t realCopy = 0;
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

static int AddAppDataEx(AppSpawnReqMsgNode *reqNode, const char *name, const AppSpawnAppData *data)
{
    APPSPAWN_CHECK(reqNode != NULL && reqNode->msg != NULL, return -1, "Invalid msg node for %{public}s", name);
    AppSpawnTlvEx tlv = {};
    if (data->dataType == DATA_TYPE_STRING) {
        tlv.tlvLen = APPSPAWN_ALIGN(data->dataLen + 1) + sizeof(AppSpawnTlvEx);
    } else {
        tlv.tlvLen = APPSPAWN_ALIGN(data->dataLen) + sizeof(AppSpawnTlvEx);
    }
    tlv.tlvType = TLV_MAX;
    tlv.dataLen = data->dataLen;
    tlv.dataType = data->dataType;
    int ret = strcpy_s(tlv.tlvName, sizeof(tlv.tlvName), name);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}s", name);
    APPSPAWN_LOGV("AddAppDataEx tlv [%{public}s %{public}u ] dataLen: %{public}u start: %{public}u",
        name, tlv.tlvLen, data->dataLen, reqNode->msg->msgLen);

    // 获取一个能保存改完整tlv的block
    AppSpawnMsgBlock *block = GetValidMsgBlock(reqNode, tlv.tlvLen);
    if (block != NULL) {
        int ret = AddAppDataToBlock(block, (uint8_t *)&tlv, sizeof(tlv), 0);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv for %{public}s", name);
        ret = AddAppDataToBlock(block, data->data, data->dataLen, data->dataType);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}s", name);
    } else {
        // 没有一个可用的block，最队列最后添加数据
        ret = AddAppDataToTail(reqNode, (uint8_t *)&tlv, sizeof(tlv), 0);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv to tail for %{public}s", name);
        ret = AddAppDataToTail(reqNode, data->data, data->dataLen, data->dataType);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data to tail for %{public}s", name);
    }
    reqNode->msg->tlvCount++;
    reqNode->msg->msgLen += tlv.tlvLen;
    APPSPAWN_LOGV("AddAppDataEx success name '%{public}s' end: %{public}u", name, reqNode->msg->msgLen);
    return 0;
}

static int AddAppData(AppSpawnReqMsgNode *reqNode, uint32_t tlvType, const AppSpawnAppData *data, uint32_t count)
{
    // 计算实际数据的长度
    uint32_t realLen = sizeof(AppSpawnTlv);
    uint32_t dataLen = 0;
    for (uint32_t index = 0; index < count; index++) {
        dataLen += data[index].dataLen;
        realLen += (data[index].dataType == DATA_TYPE_STRING) ?
            APPSPAWN_ALIGN(data[index].dataLen + 1) : APPSPAWN_ALIGN(data[index].dataLen);
    }
    AppSpawnTlv tlv;
    tlv.tlvLen = realLen;
    tlv.tlvType = tlvType;
    APPSPAWN_LOGV("AddAppData tlv [%{public}u %{public}u] dataLen: %{public}u start: %{public}u",
        tlvType, tlv.tlvLen, dataLen, reqNode->msg->msgLen);

    // 获取一个能保存改完整tlv的block
    AppSpawnMsgBlock *block = GetValidMsgBlock(reqNode, tlv.tlvLen);
    if (block != NULL) {
        int ret = AddAppDataToBlock(block, (uint8_t *)&tlv, sizeof(tlv), 0);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv for %{public}d", tlvType);

        for (uint32_t index = 0; index < count; index++) {
            ret = AddAppDataToBlock(block, (uint8_t *)data[index].data, data[index].dataLen, data[index].dataType);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}d", tlvType);
        }
    } else {
        // 没有一个可用的block，最队列最后添加数据
        int ret = AddAppDataToTail(reqNode, (uint8_t *)&tlv, sizeof(tlv), 0);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add tlv to tail for %{public}d", tlvType);
        // 添加tlv信息
        for (uint32_t index = 0; index < count; index++) {
            ret = AddAppDataToTail(reqNode, (uint8_t *)data[index].data, data[index].dataLen, data[index].dataType);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to add data for %{public}d", tlvType);
        }
    }
    reqNode->msg->msgLen += tlv.tlvLen;
    APPSPAWN_LOGV("AddAppData success tlvType %{public}u end: %{public}u", tlvType, reqNode->msg->msgLen);
    return 0;
}

static int InitClientInstance(AppSpawnClientType type)
{
    pthread_mutex_lock(&g_mutex);
    if (g_clientInstance[type] != NULL) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }
    AppSpawnReqMsgMgr *clientInstance = malloc(sizeof(AppSpawnReqMsgMgr) + RECV_BLOCK_LEN);
    if (clientInstance == NULL) {
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    // init
    clientInstance->type = type;
    clientInstance->msgId = 0;
    clientInstance->maxRetryCount = 5;  // 5 max retry count
    clientInstance->socketId = -1;
    pthread_mutex_init(&clientInstance->mutex, NULL);
    // init recvBlock
    OH_ListInit(&clientInstance->recvBlock.node);
    clientInstance->recvBlock.blockSize = RECV_BLOCK_LEN;
    clientInstance->recvBlock.currentIndex = 0;
    g_clientInstance[type] = clientInstance;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

static int SetFlagsTlv(AppSpawnReqMsgNode *reqNode,
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

static int CreateBaseMsg(AppSpawnReqMsgNode *reqNode, uint32_t msgType, const char *processName)
{
    AppSpawnMsgBlock *block = CreateAppSpawnMsgBlock(reqNode);
    APPSPAWN_CHECK(block != NULL, return -1, "Failed to create block for %{public}s", processName);

    // 保留消息头的大小
    reqNode->msg = (AppSpawnMsg *)(block->buffer + block->currentIndex);
    reqNode->msg->magic = APPSPAWN_MSG_MAGIC;
    reqNode->msg->msgId = 0;
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

static void DeleteAppSpawnReqMsg(AppSpawnReqMsgNode *reqNode)
{
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return);
    APPSPAWN_LOGV("DeleteAppSpawnReqMsg reqId: %{public}u", reqNode->reqId);
    reqNode->msgFlags = NULL;
    reqNode->permissionFlags = NULL;
    reqNode->msg = NULL;
    // 释放block
    OH_ListRemoveAll(&reqNode->msgBlocks, FreeMsgBlock);
    free(reqNode);
}

static AppSpawnReqMsgNode *CreateAppSpawnReqMsg(uint32_t msgType, const char *processName)
{
    static uint32_t reqId = 0;
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)malloc(sizeof(AppSpawnReqMsgNode));
    APPSPAWN_CHECK(reqNode != NULL, return NULL, "Failed to create msg node for %{public}s", processName);

    OH_ListInit(&reqNode->node);
    OH_ListInit(&reqNode->msgBlocks);
    reqNode->reqId = ++reqId;
    reqNode->msg = NULL;
    reqNode->msgFlags = NULL;
    reqNode->permissionFlags = NULL;
    reqNode->state = MSG_STATE_IDLE;
    int ret = CreateBaseMsg(reqNode, msgType, processName);
    APPSPAWN_CHECK(ret == 0, return NULL;
        DeleteAppSpawnReqMsg(reqNode), "Failed to create base msg for %{public}s", processName);
    APPSPAWN_LOGV("CreateAppSpawnReqMsg reqId: %{public}d msg type: %{public}u processName: %{public}s",
        reqNode->reqId, msgType, processName);
    return reqNode;
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
    AppSpawnReqMsgMgr *reqMgr = (AppSpawnReqMsgMgr *)handle;
    APPSPAWN_CHECK(reqMgr != NULL, return -1, "Invalid reqMgr");
    pthread_mutex_lock(&g_mutex);
    if (reqMgr->type < sizeof(g_clientInstance) / sizeof(g_clientInstance[0])) {
        g_clientInstance[reqMgr->type] = NULL;
    }
    pthread_mutex_unlock(&g_mutex);
    pthread_mutex_destroy(&reqMgr->mutex);
    free(reqMgr);
    return 0;
}

APPSPAWN_STATIC void CloseClientSocket(int socketId)
{
    APPSPAWN_LOGV("Closed socket with fd %{public}d", socketId);
    if (socketId >= 0) {
        int flag = 0;
        setsockopt(socketId, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        close(socketId);
    }
}

APPSPAWN_STATIC int CreateClientSocket(uint32_t type, uint32_t timeout)
{
    const char *socketName = type == CLIENT_FOR_APPSPAWN ? APPSPAWN_SOCKET_NAME : NWEBSPAWN_SOCKET_NAME;
    int socketFd = socket(AF_UNIX, SOCK_STREAM, 0);  // SOCK_SEQPACKET
    APPSPAWN_CHECK(socketFd >= 0, return -1, "Socket socket fd: %{public}s error: %{public}d", socketName, errno);

    int flag = 1;
    int ret = setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    flag = 1;
    ret = setsockopt(socketFd, SOL_SOCKET, SO_PASSCRED, &flag, sizeof(flag));
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd);
        return -1, "Set socket opt SO_PASSCRED socket fd: %{public}s error: %{public}d", socketName, errno);

    struct timeval timeoutVal = {timeout, 0};
    ret = setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &timeoutVal, sizeof(timeoutVal));
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd);
        return -1, "Set socket opt SO_SNDTIMEO socket fd: %{public}s error: %{public}d", socketName, errno);
    ret = setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeoutVal, sizeof(timeoutVal));
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd);
        return -1, "Set socket opt SO_RCVTIMEO socket fd: %{public}s error: %{public}d", socketName, errno);

    struct sockaddr_un addr;
    socklen_t pathSize = sizeof(addr.sun_path);
    int pathLen = snprintf_s(addr.sun_path, pathSize, (pathSize - 1), "%s%s", APPSPAWN_SOCKET_DIR, socketName);
    APPSPAWN_CHECK(pathLen > 0, CloseClientSocket(socketFd); return -1,
        "Format path socket fd: %{public}s %{public}d error: %{public}d", socketName, socketFd, errno);
    addr.sun_family = AF_LOCAL;
    socklen_t socketAddrLen = offsetof(struct sockaddr_un, sun_path) + pathLen + 1;
    ret = connect(socketFd, (struct sockaddr *)(&addr), socketAddrLen);
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd); return -1,
        "Failed to connect socket fd: %{public}d %{public}s error: %{public}d", socketFd, addr.sun_path, errno);
    APPSPAWN_LOGI("Create socket success %{public}s socketFd: %{public}d", addr.sun_path, socketFd);
    return socketFd;
}

static int ReadMessage(int socketFd, uint32_t sendMsgId, uint8_t *buf, int len, AppSpawnResult *result)
{
    ssize_t rLen = TEMP_FAILURE_RETRY(read(socketFd, buf, len));
    APPSPAWN_CHECK(rLen >= 0, return APPSPAWN_TIMEOUT,
        "Read message from fd %{public}d rLen %{public}zd errno: %{public}d", socketFd, rLen, errno);
    if (rLen >= sizeof(AppSpawnResponseMsg)) {
        AppSpawnResponseMsg *msg = (AppSpawnResponseMsg *)(buf);
        APPSPAWN_CHECK_ONLY_LOG(sendMsgId == msg->msgHdr.msgId,
            "Invalid msg recvd %{public}u %{public}u", sendMsgId, msg->msgHdr.msgId);
        return memcpy_s(result, sizeof(AppSpawnResult), &msg->result, sizeof(msg->result));
    }
    return APPSPAWN_TIMEOUT;
}

static int WriteMessage(int socketFd, const uint8_t *buf, ssize_t len)
{
    ssize_t written = 0;
    ssize_t remain = len;
    const uint8_t *offset = buf;
    for (ssize_t wLen = 0; remain > 0; offset += wLen, remain -= wLen, written += wLen) {
        wLen = send(socketFd, offset, remain, MSG_NOSIGNAL);
        APPSPAWN_LOGV("Write msg errno: %{public}d %{public}d", errno, wLen);
        APPSPAWN_CHECK((wLen > 0) || (errno == EINTR), return -errno,
            "Failed to write message to fd %{public}d, wLen %{public}zd errno: %{public}d", socketFd, wLen, errno);
    }
    return written == len ? 0 : -EFAULT;
}

static int HandleMsgSend(AppSpawnReqMsgMgr *reqMgr, int socketId, AppSpawnReqMsgNode *reqNode)
{
    APPSPAWN_LOGV("HandleMsgSend reqId: %{public}u msgId: %{public}d", reqNode->reqId, reqNode->msg->msgId);
    ListNode *sendNode = reqNode->msgBlocks.next;
    uint32_t currentIndex = 0;
    while (sendNode != NULL && sendNode != &reqNode->msgBlocks) {
        AppSpawnMsgBlock *sendBlock = (AppSpawnMsgBlock *)ListEntry(sendNode, AppSpawnMsgBlock, node);
        int ret = WriteMessage(socketId, sendBlock->buffer, sendBlock->currentIndex);
        currentIndex += sendBlock->currentIndex;
        APPSPAWN_LOGV("Write msg ret: %{public}d msgId: %{public}u %{public}u %{public}u",
            ret, reqNode->msg->msgId, reqNode->msg->msgLen, currentIndex);
        if (ret == 0) {
            sendNode = sendNode->next;
            continue;
        }
        APPSPAWN_LOGE("Send msg fail reqId: %{public}u msgId: %{public}d ret: %{public}d",
            reqNode->reqId, reqNode->msg->msgId, ret);
        return ret;
    }
    return 0;
}

static int ClientSendMsg(AppSpawnReqMsgMgr *reqMgr, AppSpawnReqMsgNode *reqNode, AppSpawnResult *result)
{
    uint32_t timeout = GetDefaultTimeout(TIMEOUT_DEF);
    int retryCount = 0;
    while (retryCount < reqMgr->maxRetryCount) {
        if (reqMgr->socketId < 0) {
            reqMgr->socketId = CreateClientSocket(reqMgr->type, timeout);
        }
        if (reqMgr->socketId < 0) {
            usleep(200000);  // 200000 wait 200ms
            retryCount++;
            continue;
        }

        if (reqNode->msg->msgId != 0) {
            reqNode->msg->msgId = reqMgr->msgId++;
        }
        int ret = HandleMsgSend(reqMgr, reqMgr->socketId, reqNode);
        if (ret == 0) {
            ret = ReadMessage(reqMgr->socketId, reqNode->msg->msgId,
                reqMgr->recvBlock.buffer, reqMgr->recvBlock.blockSize, result);
        }
        if (ret == 0) {
            return 0;
        }
        // retry
        CloseClientSocket(reqMgr->socketId);
        reqMgr->socketId = -1;
        reqMgr->msgId = 0;
        reqNode->msg->msgId = 0;
        usleep(20000);  // 20000 wait 20ms
        retryCount++;
    }
    return APPSPAWN_TIMEOUT;
}

int AppSpawnClientSendMsg(AppSpawnClientHandle handle, AppSpawnReqMsgHandle reqHandle, AppSpawnResult *result)
{
    APPSPAWN_CHECK(result != NULL, return APPSPAWN_INVALID_ARG, "Invalid result");
    result->result = APPSPAWN_INVALID_ARG;
    result->pid = 0;
    AppSpawnReqMsgMgr *reqMgr = (AppSpawnReqMsgMgr *)handle;
    APPSPAWN_CHECK(reqMgr != NULL, return APPSPAWN_INVALID_ARG, "Invalid reqMgr");
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK(reqNode != NULL && reqNode->msg != NULL, return APPSPAWN_INVALID_ARG, "Invalid msgReq");

    APPSPAWN_LOGI("AppSpawnClientSendMsg reqId: %{public}u msgLen: %{public}u %{public}s",
        reqNode->reqId, reqNode->msg->msgLen, reqNode->msg->processName);
    pthread_mutex_lock(&reqMgr->mutex);
    int ret = ClientSendMsg(reqMgr, reqNode, result);
    if (ret != 0) {
        result->result = ret;
    }
    pthread_mutex_unlock(&reqMgr->mutex);
    APPSPAWN_LOGI("AppSpawnClientSendMsg reqId: %{public}u end result: 0x%{public}x", reqNode->reqId, result->result);
    DeleteAppSpawnReqMsg(reqNode);
    return result->result;
}

int AppSpawnReqMsgCreate(uint32_t msgType, const char *processName, AppSpawnReqMsgHandle *reqHandle)
{
    APPSPAWN_CHECK(processName != NULL, return -1, "Invalid bundle name");
    APPSPAWN_CHECK(reqHandle != NULL, return -1, "Invalid request handle");
    AppSpawnReqMsgNode *reqNode = CreateAppSpawnReqMsg(msgType, processName);
    APPSPAWN_CHECK(reqNode != NULL, return -1, "Failed to create msg node for %{public}s", processName);
    *reqHandle = (AppSpawnReqMsgHandle)(reqNode);
    return 0;
}

void AppSpawnReqMsgFree(AppSpawnReqMsgHandle reqHandle)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return);
    DeleteAppSpawnReqMsg(reqNode);
}

int AppSpawnReqMsgSetAppDacInfo(AppSpawnReqMsgHandle reqHandle, const AppDacInfo *dacInfo)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(dacInfo != NULL, return -1, "Invalid dacInfo ");

    AppDacInfo tmpDacInfo = {0};
    (void)memcpy_s(&tmpDacInfo, sizeof(tmpDacInfo), dacInfo, sizeof(tmpDacInfo));
    GetSpecialGid(reqNode->msg->processName, tmpDacInfo.gidTable, &tmpDacInfo.gidCount);

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&tmpDacInfo;
    data[0].dataLen = sizeof(AppSpawnMsgDacInfo);
    return AddAppData(reqNode, TLV_DAC_INFO, data, 1);
}

static inline int CheckInputString(const char *info, const char *value, uint32_t maxLen)
{
    APPSPAWN_CHECK(value != NULL, return APPSPAWN_INVALID_ARG, "Invalid input for %{public}s ", info);
    uint32_t valueLen = (uint32_t)strlen(value);
    APPSPAWN_CHECK(valueLen > 0 && valueLen < maxLen, return APPSPAWN_INVALID_ARG,
        "Invalid input string length %{public}s for %{public}s", value, info);
    return 0;
}

int AppSpawnReqMsgSetBundleInfo(AppSpawnReqMsgHandle reqHandle, int32_t bundleIndex, const char *bundleName)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK_ONLY_EXPER(CheckInputString("Bundle info", bundleName, APP_LEN_BUNDLE_NAME) == 0,
        return APPSPAWN_INVALID_ARG);

    AppSpawnMsgBundleInfo info = {};
    info.bundleIndex = bundleIndex;
    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&info;
    data[0].dataLen = sizeof(AppSpawnMsgBundleInfo);
    data[1].data = (uint8_t *)bundleName;
    data[1].dataLen = strlen(bundleName);
    data[1].dataType = DATA_TYPE_STRING;
    return AddAppData(reqNode, TLV_BUNDLE_INFO, data, MAX_DATA_IN_TLV);
}

int AppSpawnReqMsgSetAppFlag(AppSpawnReqMsgHandle reqHandle, uint32_t flagIndex)
{
    AppSpawnReqMsgNode *reqNode =(AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    return SetAppSpawnMsgFlags(reqNode->msgFlags, flagIndex);
}

int AppSpawnReqMsgAddExtInfo(AppSpawnReqMsgHandle reqHandle, const char *name, const uint8_t *value, uint32_t valueLen)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(name != NULL && strlen(name) < APPSPAWN_TLV_NAME_LEN,
        return APPSPAWN_INVALID_ARG, "Invalid tlv name ");
    APPSPAWN_CHECK(value != NULL, return APPSPAWN_INVALID_ARG, "Invalid tlv data ");
    APPSPAWN_CHECK((valueLen > 0) && (valueLen < EXTRAINFO_TOTAL_LENGTH_MAX),
        return APPSPAWN_INVALID_ARG, "Invalid data len %{public}d", valueLen);
    APPSPAWN_LOGV("AppSpawnReqMsgAddExtInfo name %{public}s", name);
    AppSpawnAppData data[1] = {};  // 1 max data count
    data[0].data = (uint8_t *)value;
    data[0].dataLen = valueLen;
    return AddAppDataEx(reqNode, name, data);  // 2 max count
}

int AppSpawnReqMsgAddStringInfo(AppSpawnReqMsgHandle reqHandle, const char *name, const char *value)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(name != NULL && strlen(name) < APPSPAWN_TLV_NAME_LEN,
        return APPSPAWN_INVALID_ARG, "Invalid tlv name ");
    APPSPAWN_CHECK_ONLY_EXPER(CheckInputString("ext info", value, EXTRAINFO_TOTAL_LENGTH_MAX) == 0,
        return APPSPAWN_INVALID_ARG);

    APPSPAWN_LOGV("AppSpawnReqMsgAddStringInfo name %{public}s", name);
    AppSpawnAppData data[1] = {};  // 1 max data count
    data[0].data = (uint8_t *)value;
    data[0].dataLen = strlen(value);
    data[0].dataType = DATA_TYPE_STRING;
    return AddAppDataEx(reqNode, name, data);  // 2 max count
}

int AppSpawnReqMsgSetPermission(AppSpawnReqMsgHandle reqHandle, const char *permission)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK(permission != NULL, return -1, "Invalid permission ");

    int32_t maxIndex = GetMaxPermissionIndex();
    int index = GetPermissionIndex(permission);
    APPSPAWN_CHECK(index >= 0 && index < maxIndex, return -1, "Invalid permission %{public}s", permission);
    APPSPAWN_LOGV("SetPermission index %{public}d name %{public}s", index, permission);
    int ret = SetAppSpawnMsgFlags(reqNode->permissionFlags, index);
    APPSPAWN_CHECK(ret == 0, return ret, "Invalid permission %{public}s", permission);
    return 0;
}

int AppSpawnReqMsgSetAppDomainInfo(AppSpawnReqMsgHandle reqHandle, uint32_t hapFlags, const char *apl)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK_ONLY_EXPER(CheckInputString("Domain info", apl, APP_APL_MAX_LEN) == 0, return APPSPAWN_INVALID_ARG);

    AppSpawnMsgDomainInfo msgDomainInfo;
    msgDomainInfo.hapFlags = hapFlags;

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&msgDomainInfo;
    data[0].dataLen = sizeof(AppSpawnMsgDomainInfo);
    data[1].data = (uint8_t *)apl;
    data[1].dataLen = strlen(apl);
    data[1].dataType = DATA_TYPE_STRING;
    return AddAppData(reqNode, TLV_DOMAIN_INFO, data, MAX_DATA_IN_TLV);
}

int AppSpawnReqMsgSetAppInternetPermissionInfo(AppSpawnReqMsgHandle reqHandle, uint8_t allow, uint8_t setAllow)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);

    AppSpawnMsgInternetInfo info = {};
    info.allowInternet = allow;
    info.setAllowInternet = setAllow;
    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&info;
    data[0].dataLen = sizeof(AppSpawnMsgInternetInfo);
    return AddAppData(reqNode, TLV_INTERNET_INFO, data, 1);
}

int AppSpawnReqMsgSetAppOwnerId(AppSpawnReqMsgHandle reqHandle, const char *ownerId)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK_ONLY_EXPER(CheckInputString("Owner info", ownerId, APP_OWNER_ID_LEN) == 0,
        return APPSPAWN_INVALID_ARG);

    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)ownerId;
    data[0].dataLen = strlen(ownerId);
    data[0].dataType = DATA_TYPE_STRING;
    return AddAppData(reqNode, TLV_OWNER_INFO, data, 1);
}

int AppSpawnReqMsgSetAppAccessToken(AppSpawnReqMsgHandle reqHandle, uint32_t accessTokenId, uint64_t accessTokenIdEx)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);

    AppSpawnMsgAccessToken accessToken = {accessTokenId, accessTokenIdEx};
    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&accessToken;
    data[0].dataLen = sizeof(accessToken);
    return AddAppData(reqNode, TLV_ACCESS_TOKEN_INFO, data, 1);
}

int AppSpawnReqMsgSetFlags(AppSpawnReqMsgHandle reqHandle, uint32_t tlv, uint32_t flags)
{
    AppSpawnReqMsgNode *reqNode = (AppSpawnReqMsgNode *)reqHandle;
    APPSPAWN_CHECK_ONLY_EXPER(reqNode != NULL, return APPSPAWN_INVALID_ARG);
    if (tlv == TLV_MSG_FLAGS) {
        *(uint32_t *)reqNode->msgFlags->flags = flags;
    } else if (tlv == TLV_PERMISSION) {
        *(uint32_t *)reqNode->permissionFlags->flags = flags;
    }
    return 0;
}

int AppSpawnTerminateMsgCreate(pid_t pid, AppSpawnReqMsgHandle *reqHandle)
{
    APPSPAWN_CHECK(reqHandle != NULL, return -1, "Invalid request handle");
    AppSpawnReqMsgNode *reqNode = CreateAppSpawnReqMsg(MSG_GET_RENDER_TERMINATION_STATUS, "terminate-process");
    APPSPAWN_CHECK(reqNode != NULL, return -1, "Failed to create msg node");

    AppSpawnResult result = {};
    result.pid = pid;
    AppSpawnAppData data[MAX_DATA_IN_TLV] = {};
    data[0].data = (uint8_t *)&result;
    data[0].dataLen = sizeof(AppSpawnResult);
    int ret = AddAppData(reqNode, TLV_RENDER_TERMINATION_INFO, data, 1);
    APPSPAWN_CHECK(ret == 0, AppSpawnReqMsgFree((AppSpawnReqMsgHandle)(reqNode));
        return -1, "Failed to create msg node for %{public}d", pid);
    *reqHandle = (AppSpawnReqMsgHandle)(reqNode);
    return 0;
}
