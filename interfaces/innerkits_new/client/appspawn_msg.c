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

#include "appspawn_client.h"
#include "appspawn_mount_permission.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "securec.h"

static void RemoveReqNode(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode)
{
    OH_ListRemove(&reqNode->node);
    OH_ListInit(&reqNode->node);
}

void SafeRemoveReqNode(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode)
{
    pthread_mutex_lock(&reqMgr->mutex);
    RemoveReqNode(reqMgr, reqNode);
    pthread_mutex_unlock(&reqMgr->mutex);
}

static AppSpawnReqNode *GetFirstReqNode(const ListNode *queue)
{
    if (ListEmpty(*queue)) {
        return NULL;
    }
    return ListEntry(queue->next, AppSpawnReqNode, node);
}

static AppSpawnReqNode *GetNextReqNode(const ListNode *queue, const AppSpawnReqNode *reqNode)
{
    if (ListEmpty(*queue)) {
        return NULL;
    }
    if (reqNode->node.next == queue) {
        return NULL;
    }
    return ListEntry(reqNode->node.next, AppSpawnReqNode, node);
}

static void PushReqNode(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode, struct ListNode *queue, uint32_t state)
{
    OH_ListRemove(&reqNode->node);
    OH_ListInit(&reqNode->node);
    OH_ListAddTail(queue, &reqNode->node);
    atomic_store(&reqNode->state, state);
}

void SafePushReqNode(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode, struct ListNode *queue, uint32_t state)
{
    pthread_mutex_lock(&reqMgr->mutex);
    PushReqNode(reqMgr, reqNode, queue, state);
    pthread_mutex_unlock(&reqMgr->mutex);
}

static int SafeCheckQueueEmpty(AppSpawnReqMgr *reqMgr, const struct ListNode *queue)
{
    int empty = 0;
    pthread_mutex_lock(&reqMgr->mutex);
    empty = ListEmpty(*queue);
    pthread_mutex_unlock(&reqMgr->mutex);
    return empty;
}

static AppSpawnReqNode *SafePopReqNode(AppSpawnReqMgr *reqMgr, struct ListNode *queue)
{
    AppSpawnReqNode *reqNode = NULL;
    pthread_mutex_lock(&reqMgr->mutex);
    if (ListEmpty(*queue)) {
        pthread_mutex_unlock(&reqMgr->mutex);
        return NULL;
    }
    reqNode = ListEntry(queue->next, AppSpawnReqNode, node);
    OH_ListRemove(&reqNode->node);
    OH_ListInit(&reqNode->node);
    pthread_mutex_unlock(&reqMgr->mutex);
    return reqNode;
}

static int MsgNodeCompareMsgId(ListNode *node, void *data)
{
    AppSpawnReqNode *reqNode = ListEntry(node, AppSpawnReqNode, node);
    return reqNode->msg->msgId - *(uint32_t *)data;
}

AppSpawnReqNode *FindReqNodeByMsgId(AppSpawnReqMgr *reqMgr, uint32_t msgId, const ListNode *queue)
{
    AppSpawnReqNode *reqNode = NULL;
    ListNode *node = OH_ListFind(queue, (void *)&msgId, MsgNodeCompareMsgId);
    if (node != NULL) {
        reqNode = ListEntry(node, AppSpawnReqNode, node);
    }
    return reqNode;
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

APPSPAWN_STATIC int CreateClientSocket(uint32_t type, int block)
{
    const char *socketName = type == CLIENT_FOR_APPSPAWN ? APPSPAWN_SOCKET_NAME : NWEBSPAWN_SOCKET_NAME;
    int socketFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);  // SOCK_SEQPACKET
    APPSPAWN_CHECK(socketFd >= 0, return -1, "Socket socket fd: %{public}s error: %{public}d", socketName, errno);

    int flag = 1;
    int ret = setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    flag = 1;
    ret = setsockopt(socketFd, SOL_SOCKET, SO_PASSCRED, &flag, sizeof(flag));
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd); return -1,
        "Set socket opt SO_PASSCRED socket fd: %{public}s %{public}d error: %{public}d", socketName, socketFd, errno);
    if (!block) {
        flag = fcntl(socketFd, F_GETFD); // Set O_NONBLOCK
        (void)fcntl(socketFd, F_SETFD, flag | O_NONBLOCK);
    }

    struct sockaddr_un addr;
    socklen_t pathSize = sizeof(addr.sun_path);
    int pathLen = snprintf_s(addr.sun_path, pathSize, (pathSize - 1), "%s%s", APPSPAWN_SOCKET_DIR, socketName);
    APPSPAWN_CHECK(pathLen > 0, CloseClientSocket(socketFd); return -1,
        "Format path socket fd: %{public}s %{public}d error: %{public}d", socketName, socketFd, errno);

    addr.sun_family = AF_LOCAL;
    socklen_t socketAddrLen = offsetof(struct sockaddr_un, sun_path) + pathLen + 1;
    ret = connect(socketFd, (struct sockaddr *)(&addr), socketAddrLen);
    APPSPAWN_CHECK(ret == 0, CloseClientSocket(socketFd); return -1,
        "Connect socket fd: %{public}d %{public}s error: %{public}d", socketFd, addr.sun_path, errno);

    APPSPAWN_LOGI("Create socket success %{public}s socketFd: %{public}d", addr.sun_path, socketFd);
    return socketFd;
}

APPSPAWN_STATIC void AddKeepMsgToSendQueue(AppSpawnReqMgr *reqMgr)
{
    // 在锁的中间操作，不要加锁
    AppSpawnReqNode *reqNode = reqMgr->keepMsg;
    if (reqNode == NULL) {
        reqNode = CreateAppSpawnReq(reqMgr, MSG_KEEPALIVE, KEEPALIVE_NAME);
        APPSPAWN_CHECK(reqNode != NULL, return, "Failed to create keepalive msg node for %{public}s", KEEPALIVE_NAME);
        reqMgr->keepMsg = reqNode;
    }
    reqNode->retryCount = 0;
    reqNode->msg->msgId = GetMsgSerialNo(reqMgr);
    clock_gettime(CLOCK_MONOTONIC, &reqMgr->keepStartTm);
    PushReqNode(reqMgr, reqNode, &reqMgr->sendQueue, MSG_STATE_SEND);
    APPSPAWN_LOGV("Add keep message to send %{public}d", reqNode->msg->msgId);
}

static void HandleMsgResponse(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode, const AppSpawnResult *result)
{
    SafeRemoveReqNode(reqMgr, reqNode);
    if (TEST_REQ_NODE_STATE(reqNode, MSG_STATE_TIMEOUT)) {
        DeleteAppSpawnReq(reqMgr, reqNode);
        return;
    }
    if (reqNode->msg->msgType == MSG_KEEPALIVE) {
        return;
    }

    // 通知发送
    (void)memcpy_s(&reqNode->result, sizeof(reqNode->result), result, sizeof(AppSpawnResult));
    atomic_store(&reqNode->state, MSG_STATE_FINISH);
    pthread_mutex_lock(&reqNode->mutex);
    pthread_cond_signal(&reqNode->cond);
    pthread_mutex_unlock(&reqNode->mutex);
}

static int HandleMsgSend(AppSpawnReqMgr *reqMgr, int socketId, AppSpawnReqNode *reqNode, ListNode **nextNode)
{
    // send 队列处理，多线程中处理
    if (reqNode == NULL || reqNode->msg == NULL) {
        return 0;
    }
    APPSPAWN_LOGI("Client send reqNode: %{public}d socketId: %{public}d retryCount: %{public}d",
        socketId, reqNode->msg->msgId, reqNode->retryCount);

    if (TEST_REQ_NODE_STATE(reqNode, MSG_STATE_TIMEOUT)) {
        SafeRemoveReqNode(reqMgr, reqNode);
        DeleteAppSpawnReq(reqMgr, reqNode);
        return 0;
    }
    if (reqNode->retryCount >= MAX_RETRY_COUNT_MSG_SEND) {
        AppSpawnResult result = {APPSPAWN_TIMEOUT, 0};
        HandleMsgResponse(reqMgr, reqNode, &result);
        return 0;
    }

    ListNode *sendNode = *nextNode;
    if (sendNode == NULL) {
        sendNode = reqNode->msgBlocks.next;
        reqNode->retryCount++;
    }
    while (sendNode != NULL && sendNode != &reqNode->msgBlocks) {
        AppSpawnMsgBlock *sendBlock = (AppSpawnMsgBlock *)ListEntry(sendNode, AppSpawnMsgBlock, node);
        ssize_t wLen = send(socketId, sendBlock->buffer, sendBlock->currentIndex, MSG_DONTWAIT | MSG_NOSIGNAL);
        APPSPAWN_LOGV("Write msg len: %{public}d msgId: %{public}u %{public}u %{public}u",
            wLen, reqNode->msg->msgId, reqNode->msg->msgLen, sendBlock->currentIndex);
        if ((wLen < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
            return APPSPAWN_RETRY_AGAIN;
        }
        if ((uint32_t)wLen == sendBlock->currentIndex) {
            sendNode = sendNode->next;
            *nextNode = sendNode;
            continue;
        }
        APPSPAWN_LOGE("Send msg fail reqNode: %{public}d errno: %{public}d", reqNode->msg->msgId, errno);
        if (reqNode->msg->msgType != MSG_KEEPALIVE) {
            SafePushReqNode(reqMgr, reqNode, &reqMgr->sendQueue, MSG_STATE_SEND);
            return APPSPAWN_RETRY_CONNECT;
        }
        return APPSPAWN_CLOSE_CONNECT;
    }
    *nextNode = NULL;
    SafePushReqNode(reqMgr, reqNode, &reqMgr->waitingQueue, MSG_STATE_WAITING);
    return 0;
}

static int HandleMsgRecv(AppSpawnReqMgr *reqMgr, int socketId)
{
    const uint32_t msgSize = sizeof(AppSpawnResponseMsg);
    uint8_t *buffer = reqMgr->recvBlock.buffer + reqMgr->recvBlock.currentIndex;
    uint32_t bufferSize = reqMgr->recvBlock.blockSize - reqMgr->recvBlock.currentIndex;
    ssize_t rLen = TEMP_FAILURE_RETRY(read(socketId, buffer, bufferSize));
    while ((rLen < 0) && (errno == EAGAIN)) {
        rLen = TEMP_FAILURE_RETRY(read(socketId, buffer, bufferSize));
    }
    APPSPAWN_LOGV("Recv message info rLen: %{public}d errno: %{public}d", rLen, (rLen != msgSize) ? errno : 0);
    if (rLen == 0) {  // 断开连接，把等待回复的节点从新发送，如果是重试次数超过最大，则释放
        AppSpawnReqNode *reqNode = GetFirstReqNode(&reqMgr->waitingQueue);
        while (reqNode != NULL) {
            SafePushReqNode(reqMgr, reqNode, &reqMgr->sendQueue, MSG_STATE_SEND);
            reqNode = GetFirstReqNode(&reqMgr->waitingQueue);
        }
        return APPSPAWN_RETRY_CONNECT;
    }
    if ((uint32_t)rLen < msgSize) {  // 不足，继续等待
        APPSPAWN_LOGW("Recv partial message rLen: %{public}d real msg size: %{public}d", rLen, msgSize);
        return 0;
    }
    // decode msg and find
    AppSpawnResponseMsg *msg = (AppSpawnResponseMsg *)reqMgr->recvBlock.buffer;
    APPSPAWN_CHECK(msg->msgHdr.magic == APPSPAWN_MSG_MAGIC,
        return APPSPAWN_RETRY_CONNECT, "Invalid message, reconnect");
    APPSPAWN_LOGV("Client recv msg socketId: %{public}d processName: %{public}s msg id: %{public}u",
        socketId, msg->msgHdr.processName, msg->msgHdr.msgId);
    AppSpawnReqNode *reqNode = FindReqNodeByMsgId(reqMgr, msg->msgHdr.msgId, &reqMgr->waitingQueue);
    if (reqNode != NULL) {
        HandleMsgResponse(reqMgr, reqNode, &msg->result);
    }
    // 处理后，移动多余的数据到开始为止
    reqMgr->recvBlock.currentIndex = 0;
    if ((uint32_t)rLen > msgSize) {
        int ret = memmove_s(buffer, reqMgr->recvBlock.blockSize, buffer + msgSize, rLen - msgSize);
        APPSPAWN_CHECK(ret == EOK, return APPSPAWN_RETRY_CONNECT, "Mem move buffer fail, reconnect");
        reqMgr->recvBlock.currentIndex = rLen - msgSize;
    }
    return 0;
}

static int CheckTimeout(const struct timespec *startTime, const struct timespec *endTime, uint32_t timeout)
{
    uint64_t diff = (uint64_t)((endTime->tv_sec - startTime->tv_sec) * 1000);  // 1000 s-ms
    if (endTime->tv_nsec > startTime->tv_nsec) {
        diff += (endTime->tv_nsec - startTime->tv_nsec) / 1000000;  // 1000000 ns - ms
    } else {
        diff -= (startTime->tv_nsec - endTime->tv_nsec) / 1000000;  // 1000000 ns - ms
    }
    return (diff > (timeout * 1000)) ? 1 : 0;
}

static int HandleMsgTimeout(AppSpawnReqMgr *reqMgr, int socketId)
{
    // wait 队列，只在发送线程中处理
    struct timespec currTm;
    clock_gettime(CLOCK_MONOTONIC, &currTm);
    int timeout = 0;
    AppSpawnReqNode *reqNode = GetFirstReqNode(&reqMgr->waitingQueue);
    while (reqNode != NULL) {
        AppSpawnReqNode *nextNode = GetNextReqNode(&reqMgr->waitingQueue, reqNode);
        if (reqNode->msg->msgType == MSG_KEEPALIVE) {
            if (CheckTimeout(&reqMgr->keepStartTm, &currTm, KEEK_LIVE_TIMEOUT)) {  // 2s timeout
                APPSPAWN_LOGI("Keep msg time out ");
                RemoveReqNode(reqMgr, reqNode);
                timeout = 1;
            }
        } else if (TEST_REQ_NODE_STATE(reqNode, MSG_STATE_TIMEOUT)) {
            RemoveReqNode(reqMgr, reqNode);
            DeleteAppSpawnReq(reqMgr, reqNode);
        }
        reqNode = nextNode;
    }

    if (!timeout) {
        return 0;
    }
    if (ListEmpty(reqMgr->waitingQueue)) {  // no other message, close connect
        APPSPAWN_LOGI("No data to send, so close socket waiting other msg send");
        return APPSPAWN_CLOSE_CONNECT;
    }
    // 断开重连，把等待回复的节点从新发送，如果是重试次数超过最大，则释放
    reqNode = GetFirstReqNode(&reqMgr->waitingQueue);
    while (reqNode != NULL) {
        SafePushReqNode(reqMgr, reqNode, &reqMgr->sendQueue, MSG_STATE_SEND);
        reqNode = GetFirstReqNode(&reqMgr->waitingQueue);
    }
    APPSPAWN_LOGI("Recreate socket, and send message retry");
    return APPSPAWN_RETRY_CONNECT;
}

static void GetSelectInfo(const AppSpawnReqNode *reqNode, int socketId, fd_set *fds, int empty, struct timeval *timeout)
{
    FD_ZERO(&fds[0]);
    FD_ZERO(&fds[1]);

    if (reqNode != NULL) {  // need send
        FD_SET(socketId, &fds[1]);
    }
    if (!empty) {  // need waiting recv
        FD_SET(socketId, &fds[0]);
    }
    timeout->tv_sec = 0;
    timeout->tv_usec = SELECT_TIMEOUT;
}

static int HandleSocketEvent(AppSpawnReqMgr *reqMgr, int socketId)
{
    fd_set fds[2];  // 2 read and write
    struct timeval timeout;
    ListNode *nextBlock = NULL;
    AppSpawnReqNode *reqNode = NULL;
    while (!reqMgr->threadExit) {
        if (reqNode == NULL) {  // retry send
            reqNode = SafePopReqNode(reqMgr, &reqMgr->sendQueue);
        }
        int empty = SafeCheckQueueEmpty(reqMgr, &reqMgr->waitingQueue);
        APPSPAWN_LOGV("Client select socket event IsQueueEmpty %{public}d", empty);
        if (reqNode == NULL && empty) {  // no msg
            return 0;
        }
        GetSelectInfo(reqNode, socketId, fds, empty, &timeout);
        int ret = select(socketId + 1, &fds[0], &fds[1], NULL, &timeout);
        APPSPAWN_LOGV("Client select socket event ret %{public}d", ret);
        if (ret < 0) {  // send fail，so recreate socket
            return ret;
        }

        if (FD_ISSET(socketId, &fds[0])) {  // recv
            ret = HandleMsgRecv(reqMgr, socketId);
            APPSPAWN_LOGV("HandleMsgRecv ret %{public}d", ret);
            if (ret != 0) {
                return ret;
            }
            continue;
        }
        if (FD_ISSET(socketId, &fds[1])) {  // send
            ret = HandleMsgSend(reqMgr, socketId, reqNode, &nextBlock);
            APPSPAWN_LOGV("HandleMsgSend ret %{public}d", ret);
            if (ret == APPSPAWN_RETRY_AGAIN) {  // retry send
                continue;
            } else if (ret != 0) { // recreate socket
                return ret;
            }
            nextBlock = NULL;
            reqNode = NULL;
            continue;
        }
        ret = HandleMsgTimeout(reqMgr, socketId);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

static void ConvertToTimespec(int time, struct timespec *tm)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    uint64_t ns = time;
    ns *= APPSPAWN_MSEC_TO_NSEC;
    ns += start.tv_sec * APPSPAWN_SEC_TO_NSEC + start.tv_nsec;
    tm->tv_sec = ns / APPSPAWN_SEC_TO_NSEC;
    tm->tv_nsec = ns % APPSPAWN_SEC_TO_NSEC;
}

static void ClientWait(AppSpawnReqMgr *reqMgr, int result, int socketId)
{
    struct timespec abstime;
    pthread_mutex_lock(&reqMgr->mutex);
    APPSPAWN_LOGV("ClientWait sendQueue: %{public}d result: %{public}d", ListEmpty(reqMgr->sendQueue), result);
    do {
        uint32_t timeout = CLIENT_SEND_KEEP * APPSPAWN_SEC_TO_MSEC;
        if (result == APPSPAWN_CLOSE_CONNECT) {
            timeout = ListEmpty(reqMgr->sendQueue) ? APPSPAWN_SOCKET_CLOSE : APPSPAWN_SOCKET_RETRY;
        } else if (result != 0) {
            timeout = APPSPAWN_SOCKET_RETRY;
        } else if (!ListEmpty(reqMgr->sendQueue)) {
            break;
        }
        ConvertToTimespec(timeout, &abstime);
        int ret = pthread_cond_timedwait(&reqMgr->notifyMsg, &reqMgr->mutex, &abstime);
        if (!ListEmpty(reqMgr->sendQueue)) {
            break;
        }
        if (ret == ETIMEDOUT && socketId >= 0) {  // 超时，发送保活消息到APPSPAWN
            AddKeepMsgToSendQueue(reqMgr);
            break;
        }
    } while (!reqMgr->threadExit);
    pthread_mutex_unlock(&reqMgr->mutex);
}

void *ClientProcessMsg(void *args)
{
    AppSpawnReqMgr *reqMgr = (AppSpawnReqMgr *)args;
    int socketId = -1;
    int ret = 0;
    while (!reqMgr->threadExit) {
        ClientWait(reqMgr, ret, socketId);
        if (socketId < 0) {
            socketId = CreateClientSocket(reqMgr->type, 0);
        }
        if (socketId < 0) {
            ret = APPSPAWN_SYSTEM_ERROR;
            continue;
        }
        int ret = HandleSocketEvent(reqMgr, socketId);
        if (ret != 0) {
            CloseClientSocket(socketId);
            socketId = -1;
            continue;
        }
    }
    if (socketId >= 0) {
        CloseClientSocket(socketId);
    }
    APPSPAWN_LOGV("Client msg send thread finish");
    return NULL;
}

int ClientSendMsg(AppSpawnReqMgr *reqMgr, AppSpawnReqNode *reqNode, uint32_t timeout, AppSpawnResult *result)
{
    APPSPAWN_CHECK_ONLY_EXPER(reqMgr != NULL && reqNode != NULL && reqNode->msg != NULL, return APPSPAWN_INVALID_ARG);
    struct timespec beginTime;
    struct timespec endTime;
    clock_gettime(CLOCK_MONOTONIC, &beginTime);
    APPSPAWN_LOGV("Client send msg: [%{public}u %{public}u %{public}s] timeout: %{public}d",
        reqNode->msg->msgId, reqNode->msg->msgType, reqNode->msg->processName, timeout);

    pthread_mutex_lock(&reqMgr->mutex);
    PushReqNode(reqMgr, reqNode, &reqMgr->sendQueue, MSG_STATE_SEND);
    pthread_cond_signal(&reqMgr->notifyMsg);
    pthread_mutex_unlock(&reqMgr->mutex);
    // timedwait，等待结果
    struct timespec abstime;
    ConvertToTimespec(timeout * APPSPAWN_SEC_TO_MSEC, &abstime);
    pthread_mutex_lock(&reqNode->mutex);
    int ret = pthread_cond_timedwait(&reqNode->cond, &reqNode->mutex, &abstime);
    if (ret == ETIMEDOUT) {  // 超时
        APPSPAWN_LOGW("Client recv msg reqId: %{public}d processName: %{public}s timeout",
            reqNode->msg->msgId, reqNode->msg->processName);
        atomic_store(&reqNode->state, MSG_STATE_TIMEOUT);
        return APPSPAWN_TIMEOUT;
    }
    pthread_mutex_unlock(&reqNode->mutex);
    (void)memcpy_s(result, sizeof(AppSpawnResult), &reqNode->result, sizeof(reqNode->result));
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    uint64_t diff = DiffTime(&beginTime, &endTime);
    APPSPAWN_LOGV("Client recv msg [%{public}u %{public}u %{public}s] used %{public}" PRId64
        "ns result: [%{public}d %{public}d]",
        reqNode->msg->msgId, reqNode->msg->msgType, reqNode->msg->processName,
        diff, reqNode->result.result, reqNode->result.pid);
    DeleteAppSpawnReq(reqMgr, reqNode);
    return 0;
}
