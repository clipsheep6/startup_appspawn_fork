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

#include "appspawn_service.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_hook.h"
#include "appspawn_modulemgr.h"
#include "appspawn_msg.h"
#include "appspawn_server.h"
#include "appspawn_utils.h"
#include "init_socket.h"
#include "init_utils.h"
#include "parameter.h"
#include "securec.h"

static AppSpawnMgr *g_appSpawnMgr = NULL;

static void WaitChildTimeout(const TimerHandle taskHandle, void *context);
static void ProcessChildResponse(const WatcherHandle taskHandle, int fd, uint32_t *events, const void *context);
static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen);
static void ProcessRecvMsg(AppSpawnConnection *connection, AppSpawnMsgReceiverCtx *receiver);
static void WaitChildDied(pid_t pid);

static void DataExDestroyProc(ListNode *node)
{
    AppSpawnDataEx *dataEx = ListEntry(node, AppSpawnDataEx, node);
    AppSpawnDataExFree freeNode = dataEx->freeNode;
    if (freeNode) {
        freeNode(dataEx);
    }
}

static void AppQueueDestroyProc(ListNode *node)
{
    AppSpawnedProcess *appInfo = ListEntry(node, AppSpawnedProcess, node);
    pid_t pid = appInfo->pid;
    APPSPAWN_LOGI("kill app, pid = %{public}d, processName = %{public}s", appInfo->pid, appInfo->name);
    OH_ListRemove(&appInfo->node);
    OH_ListInit(&appInfo->node);
    free(appInfo);
    if (pid > 0) {
        kill(pid, SIGKILL);
    }
}

static void StopAppSpawn(void)
{
    if (g_appSpawnMgr != NULL) {
        OH_ListRemoveAll(&g_appSpawnMgr->processMgr.appQueue, AppQueueDestroyProc);
    }
    APPSPAWN_LOGI("StopAppSpawn ");
    LE_StopLoop(LE_GetDefaultLoop());
}

static inline void DumpStatus(const char *appName, pid_t pid, int status)
{
    if (WIFSIGNALED(status)) {
        APPSPAWN_LOGW("%{public}s with pid %{public}d exit with signal:%{public}d", appName, pid, WTERMSIG(status));
    }
    if (WIFEXITED(status)) {
        APPSPAWN_LOGW("%{public}s with pid %{public}d exit with code:%{public}d", appName, pid, WEXITSTATUS(status));
    }
}

static void HandleDiedPid(pid_t pid, uid_t uid, int status)
{
    AppSpawnedProcess *appInfo = GetSpawnedProcess(&g_appSpawnMgr->processMgr, pid);
    if (appInfo == NULL) {
        WaitChildDied(pid);
        DumpStatus("unknown", pid, status);
        return;
    }

    appInfo->exitStatus = status;
    APPSPAWN_CHECK_ONLY_LOG(appInfo->uid == uid, "Invalid uid %{public}u %{public}u", appInfo->uid, uid);
    DumpStatus(appInfo->name, pid, status);
    AppChangeHookExecute(HOOK_APP_DIED, &g_appSpawnMgr->content, appInfo);

    // if current process of death is nwebspawn, restart appspawn
    if (strcmp(appInfo->name, NWEBSPAWN_SERVER_NAME) == 0) {
        OH_ListRemove(&appInfo->node);
        free(appInfo);
        APPSPAWN_LOGW("Current process of death is nwebspawn, pid = %{public}d, restart appspawn", pid);
        StopAppSpawn();
        return;
    }
    // move app info to died queue in NWEBSPAWN, or delete appinfo
    HandleProcessTerminate(&g_appSpawnMgr->processMgr, appInfo, IsNWebSpawnMode(g_appSpawnMgr));
}

APPSPAWN_STATIC void ProcessSignal(const struct signalfd_siginfo *siginfo)
{
    APPSPAWN_LOGI("ProcessSignal signum %{public}d", siginfo->ssi_signo);
    switch (siginfo->ssi_signo) {
        case SIGCHLD: {  // delete pid from app map
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                HandleDiedPid(pid, siginfo->ssi_uid, status);
            }
            break;
        }
        case SIGTERM: {  // appswapn killed, use kill without parameter
            StopAppSpawn();
            break;
        }
        default:
            APPSPAWN_LOGI("SigHandler, unsupported signal %{public}d.", siginfo->ssi_signo);
            break;
    }
}

static AppSpawnMsgReceiverCtx *CreateAppSpawnMsgReceiver(void)
{
    AppSpawnMsgReceiverCtx *receiver = (AppSpawnMsgReceiverCtx *)calloc(1, sizeof(AppSpawnMsgReceiverCtx));
    APPSPAWN_CHECK(receiver != NULL, return NULL, "Failed to create receiver");
    receiver->msgRecvLen = 0;
    receiver->timer = NULL;
    receiver->buffer = NULL;
    receiver->tlvOffset = NULL;
    (void)memset_s(&receiver->msgHeader, sizeof(receiver->msgHeader), 0, sizeof(receiver->msgHeader));
    return receiver;
}

static void OnClose(const TaskHandle taskHandle)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, return, "Invalid connection");
    APPSPAWN_LOGI("OnClose connectionId: %{public}u socket %{public}d",
        connection->connectionId, LE_GetSocketFd(taskHandle));
    DeleteAppSpawnMsgReceiver(connection->receiver);
    connection->receiver = NULL;
    AppMgrHandleConnectClose(&g_appSpawnMgr->processMgr, connection);
}

static void SendMessageComplete(const TaskHandle taskHandle, BufferHandle handle)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, return, "Invalid connection");
    uint32_t bufferSize = sizeof(AppSpawnResponseMsg);
    AppSpawnResponseMsg *msg = (AppSpawnResponseMsg *)LE_GetBufferInfo(handle, NULL, &bufferSize);
    if (msg == NULL) {
        return;
    }
    AppSpawnedProcess *appInfo = GetSpawnedProcess(&g_appSpawnMgr->processMgr, msg->result.pid);
    if (appInfo == NULL) {
        return;
    }
    APPSPAWN_LOGI("SendMessageComplete connectionId: %{public}u result %{public}d app %{public}s pid %{public}d",
        connection->connectionId, LE_GetSendResult(handle), appInfo->name, msg->result.pid);
    if (LE_GetSendResult(handle) != 0 && msg->result.pid > 0) {
        kill(msg->result.pid, SIGKILL);
    }
}

static int SendResponse(const AppSpawnConnection *connection, const AppSpawnMsg *msg, int result, pid_t pid)
{
    APPSPAWN_LOGV("SendResponse connectionId %{public}u result: %{public}d pid: %{public}d",
        connection->connectionId, result, pid);
    uint32_t bufferSize = sizeof(AppSpawnResponseMsg);
    BufferHandle handle = LE_CreateBuffer(LE_GetDefaultLoop(), bufferSize);
    AppSpawnResponseMsg *buffer = (AppSpawnResponseMsg *)LE_GetBufferInfo(handle, NULL, &bufferSize);
    int ret = memcpy_s(buffer, bufferSize, msg, sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(ret == 0, LE_FreeBuffer(LE_GetDefaultLoop(), NULL, handle);
        return -1, "Failed to memcpy_s bufferSize");
    buffer->result.result = result;
    buffer->result.pid = pid;
    return LE_Send(LE_GetDefaultLoop(), connection->stream, handle, bufferSize);
}

static void WaitMsgCompleteTimeOut(const TimerHandle taskHandle, void *context)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)context;
    APPSPAWN_LOGE("Long time no msg complete so close connectionId: %{public}u", connection->connectionId);
    DeleteAppSpawnMsgReceiver(connection->receiver);
    connection->receiver = NULL;
    LE_CloseStreamTask(LE_GetDefaultLoop(), connection->stream);
}

static inline int StartTimerForCheckMsg(AppSpawnConnection *connection)
{
    if (connection->receiver->timer != NULL) {
        return 0;
    }
    int ret = LE_CreateTimer(LE_GetDefaultLoop(), &connection->receiver->timer, WaitMsgCompleteTimeOut, connection);
    if (ret == 0) {
        ret = LE_StartTimer(LE_GetDefaultLoop(), connection->receiver->timer, MAX_WAIT_MSG_COMPLETE, 1);
    }
    return ret;
}

static TaskHandle AcceptClient(const LoopHandle loopHandle, const TaskHandle server, uint32_t flags)
{
    static uint32_t connectionId = 0;
    TaskHandle stream;
    LE_StreamInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_CONNECT;
    info.baseInfo.flags |= flags;
    info.baseInfo.close = OnClose;
    info.baseInfo.userDataSize = sizeof(AppSpawnConnection);
    info.disConnectComplete = NULL;
    info.sendMessageComplete = SendMessageComplete;
    info.recvMessage = OnReceiveRequest;
    LE_STATUS ret = LE_AcceptStreamClient(loopHandle, server, &stream, &info);
    APPSPAWN_CHECK(ret == 0, return NULL, "Failed to alloc stream");

    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(stream);
    APPSPAWN_CHECK(connection != NULL, return NULL, "Failed to alloc stream");
    struct ucred cred = {-1, -1, -1};
    socklen_t credSize = sizeof(struct ucred);
    if ((getsockopt(LE_GetSocketFd(stream), SOL_SOCKET, SO_PEERCRED, &cred, &credSize) < 0) ||
        (cred.uid != DecodeUid("foundation") && cred.uid != DecodeUid("root"))) {
        APPSPAWN_LOGE("Invalid uid %{public}d from client", cred.uid);
        LE_CloseStreamTask(LE_GetDefaultLoop(), stream);
        return NULL;
    }
    connection->connectionId = ++connectionId;
    connection->stream = stream;
    APPSPAWN_LOGI("OnConnection connectionId: %{public}u fd %{public}d ",
        connection->connectionId, LE_GetSocketFd(stream));
    return stream;
}

static int OnConnection(const LoopHandle loopHandle, const TaskHandle server)
{
    APPSPAWN_CHECK(server != NULL && loopHandle != NULL, return -1, "Error server");
    (void)AcceptClient(loopHandle, server, 0);
    return 0;
}

static inline int CheckRecvMsg(const AppSpawnMsg *msg)
{
    APPSPAWN_CHECK(msg != NULL, return -1, "Invalid msg");
    APPSPAWN_CHECK(msg->magic == APPSPAWN_MSG_MAGIC, return -1, "Invalid magic 0x%{public}x", msg->magic);
    APPSPAWN_CHECK(msg->msgLen < MAX_MSG_TOTAL_LENGTH, return -1, "Message too long %{public}u", msg->msgLen);
    APPSPAWN_CHECK(msg->msgLen >= sizeof(AppSpawnMsg), return -1, "Message too long %{public}u", msg->msgLen);
    APPSPAWN_CHECK(msg->tlvCount < MAX_TLV_COUNT, return -1, "Message too long %{public}u", msg->tlvCount);
    APPSPAWN_CHECK(msg->tlvCount < (msg->msgLen / sizeof(AppSpawnTlv)),
        return -1, "Message too long %{public}u", msg->tlvCount);
    return 0;
}

static int AllocBuffer(AppSpawnMsgReceiverCtx *receiver, const AppSpawnMsg *msg)
{
    APPSPAWN_CHECK_ONLY_EXPER(CheckRecvMsg(&receiver->msgHeader) == 0, return -1);
    if (msg->msgLen == sizeof(receiver->msgHeader)) {  // only has msg header
        return 0;
    }
    receiver->buffer = calloc(1, msg->msgLen - sizeof(receiver->msgHeader));
    APPSPAWN_CHECK(receiver->buffer != NULL, return -1, "Failed to alloc memory for recv message");
    uint32_t totalCount = msg->tlvCount + TLV_MAX;
    receiver->tlvOffset = malloc(totalCount * sizeof(uint32_t));
    APPSPAWN_CHECK(receiver->tlvOffset != NULL, return -1, "Failed to alloc memory for recv message");
    for (uint32_t i = 0; i < totalCount; i++) {
        receiver->tlvOffset[i] = INVALID_OFFSET;
    }
    return 0;
}

static int HandleRecvBuffer(AppSpawnMsgReceiverCtx *receiver,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *reminder)
{
    *reminder = 0;
    uint32_t reminderLen = bufferLen;
    const uint8_t *reminderBuffer = buffer;
    if (receiver->msgRecvLen < sizeof(receiver->msgHeader)) {  // recv partial message
        if ((bufferLen + receiver->msgRecvLen) >= sizeof(receiver->msgHeader)) {
            int ret = memcpy_s(((uint8_t *)&receiver->msgHeader) + receiver->msgRecvLen,
                sizeof(receiver->msgHeader) - receiver->msgRecvLen,
                buffer, sizeof(receiver->msgHeader) - receiver->msgRecvLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");

            ret = AllocBuffer(receiver, &receiver->msgHeader);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc buffer for receive msg");
            reminderLen = bufferLen - (sizeof(receiver->msgHeader) - receiver->msgRecvLen);
            reminderBuffer = buffer + sizeof(receiver->msgHeader) - receiver->msgRecvLen;
            receiver->msgRecvLen = sizeof(receiver->msgHeader);
        } else {
            int ret = memcpy_s(((uint8_t *)&receiver->msgHeader) + receiver->msgRecvLen,
                sizeof(receiver->msgHeader) - receiver->msgRecvLen, buffer, bufferLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
            receiver->msgRecvLen += bufferLen;
            return 0;
        }
    }
    // do not copy msg header
    uint32_t realCopy = (reminderLen + receiver->msgRecvLen) > receiver->msgHeader.msgLen ?
        receiver->msgHeader.msgLen - receiver->msgRecvLen : reminderLen;
    if (receiver->buffer == NULL) {  // only has msg header
        return 0;
    }
    APPSPAWN_LOGV("HandleRecvBuffer msgRecvLen: %{public}u reminderLen %{public}u realCopy %{public}u",
        receiver->msgRecvLen, reminderLen, realCopy);
    int ret = memcpy_s(receiver->buffer + receiver->msgRecvLen - sizeof(receiver->msgHeader),
        receiver->msgHeader.msgLen - receiver->msgRecvLen, reminderBuffer, realCopy);
    APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
    receiver->msgRecvLen += realCopy;
    if (realCopy < reminderLen) {
        *reminder = reminderLen - realCopy;
    }
    return 0;
}

static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Failed to get client form socket");
    APPSPAWN_CHECK(buffLen < MAX_MSG_TOTAL_LENGTH, return, "Message too long");
    uint32_t reminder = 0;
    uint32_t currLen = 0;
    int ret = 0;
    do {
        if (connection->receiver == NULL) {
            connection->receiver = CreateAppSpawnMsgReceiver();
            APPSPAWN_CHECK(connection->receiver != NULL, LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
                return, "Failed to create receiver");
        }
        APPSPAWN_LOGV("OnReceiveRequest buffer: 0x%{public}x buffLen %{public}d",
            *(uint32_t *)(buffer + currLen), buffLen - currLen);
        ret = HandleRecvBuffer(connection->receiver, buffer + currLen, buffLen - currLen, &reminder);
        if (ret != 0) {
            LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
            return;
        }
        if (connection->receiver->msgRecvLen == connection->receiver->msgHeader.msgLen) {  // recv complete msg
            if (connection->receiver->timer) {
                LE_StopTimer(LE_GetDefaultLoop(), connection->receiver->timer);
                connection->receiver->timer = NULL;
            }
            ProcessRecvMsg(connection, connection->receiver);
            connection->receiver = NULL;
        } else {
            APPSPAWN_CHECK(reminder == 0, return, "reminder must be zero");
            break;
        }
        currLen += buffLen - reminder;
    } while (reminder > 0);

    // 有部分数据，启动检测定时器
    if (connection->receiver != NULL && connection->receiver->msgRecvLen > 0) {
        ret = StartTimerForCheckMsg(connection);
        APPSPAWN_CHECK(ret == 0, LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
            return, "Failed to create time for connection");
    }
}

static int CheckMsgReceiver(const AppSpawningCtx *property, const AppSpawnMsgReceiverCtx *receiver)
{
    APPSPAWN_CHECK(strlen(receiver->msgHeader.processName) > 0,
        return APPSPAWN_INVALID_MSG, "Invalid property processName %{public}s", receiver->msgHeader.processName);
    APPSPAWN_CHECK(receiver->tlvOffset != NULL,
        return APPSPAWN_INVALID_MSG, "Invalid property tlv offset for %{public}s", receiver->msgHeader.processName);
    APPSPAWN_CHECK(receiver->buffer != NULL,
        return APPSPAWN_INVALID_MSG, "Invalid property buffer for %{public}s", receiver->msgHeader.processName);

    if (receiver->tlvOffset[TLV_BUNDLE_INFO] == INVALID_OFFSET ||
        receiver->tlvOffset[TLV_MSG_FLAGS] == INVALID_OFFSET ||
        receiver->tlvOffset[TLV_ACCESS_TOKEN_INFO] == INVALID_OFFSET ||
        receiver->tlvOffset[TLV_DAC_INFO] == INVALID_OFFSET) {
        APPSPAWN_LOGE("No must tlv: %{public}u %{public}u %{public}u", receiver->tlvOffset[TLV_BUNDLE_INFO],
            receiver->tlvOffset[TLV_MSG_FLAGS], receiver->tlvOffset[TLV_DAC_INFO]);
        return APPSPAWN_INVALID_MSG;
    }
    AppSpawnMsgBundleInfo *bundleInfo = GetAppProperty(property, TLV_BUNDLE_INFO);
    if (bundleInfo != NULL) {
        if (strstr(bundleInfo->bundleName, "\\") != NULL || strstr(bundleInfo->bundleName, "/") != NULL) {
            APPSPAWN_LOGE("Invalid bundle name %{public}s", bundleInfo->bundleName);
            return APPSPAWN_INVALID_MSG;
        }
    }
    return 0;
}

static int CheckExtTlvInfo(const AppSpawnTlv *tlv, uint32_t remainLen)
{
    AppSpawnTlvEx *tlvEx = (AppSpawnTlvEx *)(tlv);
    APPSPAWN_LOGV("Recv type [%{public}s %{public}u] real len: %{public}u",
        tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen);
    if (tlvEx->dataLen > tlvEx->tlvLen - sizeof(AppSpawnTlvEx)) {
        APPSPAWN_LOGE("Invalid tlv [%{public}s %{public}u] real len: %{public}u %{public}u",
            tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen, sizeof(AppSpawnTlvEx));
        return APPSPAWN_INVALID_MSG;
    }
    return 0;
}

static int CheckMsgTlv(const AppSpawnTlv *tlv, uint32_t remainLen)
{
    uint32_t tlvLen = 0;
    switch (tlv->tlvType) {
        case TLV_MSG_FLAGS:
            tlvLen = ((AppSpawnMsgFlags *)(tlv + 1))->count * sizeof(uint32_t);
            break;
        case TLV_ACCESS_TOKEN_INFO:
            tlvLen = sizeof(AppSpawnMsgAccessToken);
            break;
        case TLV_DAC_INFO:
            tlvLen = sizeof(AppSpawnMsgDacInfo);
            break;
        case TLV_BUNDLE_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= (sizeof(AppSpawnMsgBundleInfo) + APP_LEN_BUNDLE_NAME),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_OWNER_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= APP_OWNER_ID_LEN,
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_DOMAIN_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= (APP_APL_MAX_LEN + sizeof(AppSpawnMsgDomainInfo)),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_MAX:
            return CheckExtTlvInfo(tlv, remainLen);
        default:
            break;
    }
    APPSPAWN_CHECK(tlvLen <= tlv->tlvLen,
        return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
    return 0;
}

APPSPAWN_STATIC int DecodeRecvMsg(AppSpawnMsgReceiverCtx *receiver)
{
    int ret = 0;
    uint32_t tlvCount = 0;
    uint32_t bufferLen = receiver->msgHeader.msgLen - sizeof(AppSpawnMsg);
    uint32_t currLen = 0;
    while (currLen < bufferLen) {
        AppSpawnTlv *tlv = (AppSpawnTlv *)(receiver->buffer + currLen);
        APPSPAWN_CHECK(tlv->tlvLen <= (bufferLen - currLen), break,
            "Invalid tlv [%{public}d %{public}d] curr: %{public}u",
            tlv->tlvType, tlv->tlvLen, currLen + sizeof(AppSpawnMsg));
        APPSPAWN_LOGV("DecodeRecvMsg tlv %{public}u %{public}u start: %{public}u ",
            tlv->tlvType, tlv->tlvLen, currLen + sizeof(AppSpawnMsg)); // show in msg offset
        ret = CheckMsgTlv(tlv, bufferLen - currLen);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        if (tlv->tlvType < TLV_MAX) {  // normal
            receiver->tlvOffset[tlv->tlvType] = currLen;
            currLen += tlv->tlvLen;
        } else {
            APPSPAWN_CHECK((tlvCount + 1) < receiver->msgHeader.tlvCount, break,
                "Invalid tlv number tlv %{public}d tlvCount: %{public}d", tlv->tlvType, tlvCount);
            receiver->tlvOffset[TLV_MAX + tlvCount] = currLen;
            tlvCount++;
            currLen += tlv->tlvLen;
        }
    }
    APPSPAWN_CHECK_ONLY_EXPER(currLen >= bufferLen, return APPSPAWN_INVALID_MSG);
    // save real ext tlv count
    receiver->tlvCount = tlvCount;
    return 0;
}

static int CreateAndWatchPipe(AppSpawningCtx *property)
{
    if (pipe(property->forkCtx.fd) == -1) {
        APPSPAWN_LOGE("create pipe fail, errno: %{public}d", errno);
        return errno;
    }
    int option = fcntl(property->forkCtx.fd[0], F_GETFD);
    if (option > 0) {
        (void)fcntl(property->forkCtx.fd[0], F_SETFD, option | O_NONBLOCK);
    }

    LE_WatchInfo watchInfo = {};
    watchInfo.fd = property->forkCtx.fd[0];
    watchInfo.flags = WATCHER_ONCE;
    watchInfo.events = Event_Read;
    watchInfo.processEvent = ProcessChildResponse;
    LE_STATUS status = LE_StartWatcher(LE_GetDefaultLoop(), &property->forkCtx.watcherHandle, &watchInfo, property);
    if (status == LE_SUCCESS) {  // start time wait child response
        status = LE_CreateTimer(LE_GetDefaultLoop(), &property->forkCtx.timer, WaitChildTimeout, property);
        status = LE_StartTimer(LE_GetDefaultLoop(), property->forkCtx.timer, WAIT_CHILD_RESPONSE_TIMEOUT, 0);
    }
    return status == LE_SUCCESS ? 0 : APPSPAWN_SYSTEM_ERROR;
}

static void ProcessSpawnReqMsg(AppSpawnConnection *connection, AppSpawnMsgReceiverCtx *receiver)
{
    AppSpawningCtx *property = CreateAppSpawningCtx(&g_appSpawnMgr->processMgr);
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    property->connection = connection;  // 由property管理消息
    property->receiver = receiver;
    int ret = DecodeRecvMsg(receiver);
    if (ret == 0) {
        ret = CheckMsgReceiver(property, receiver);
    }
    if (ret != 0) {
        SendResponse(connection, &receiver->msgHeader, ret, 0);
        DeleteAppSpawningCtx(property);
        return;
    }

    if (CreateAndWatchPipe(property) != 0) {
        SendResponse(connection, &receiver->msgHeader, APPSPAWN_SYSTEM_ERROR, 0);
        DeleteAppSpawningCtx(property);
        return;
    }
    property->state = APP_STATE_SPAWNING;

    // mount el2 dir
    // getWrapBundleNameValue
    AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, &g_appSpawnMgr->content, &property->client);
    if (IsDeveloperModeOn(property)) {
        DumpNormalProperty(property);
    }
    ret = AppSpawnProcessMsg(&g_appSpawnMgr->content, &property->client, &property->pid);
    if (ret != 0) {  // wait child process result
        SendResponse(connection, &receiver->msgHeader, ret, 0);
        DeleteAppSpawningCtx(property);
        return;
    }
}

static pid_t GetPidFromTerminationMsg(AppSpawnMsgReceiverCtx *receiver)
{
    int ret = DecodeRecvMsg(receiver);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);
    if (receiver->tlvOffset[TLV_RENDER_TERMINATION_INFO] > 0) {
        AppSpawnResult *pid = (AppSpawnResult *)(
            receiver->buffer + receiver->tlvOffset[TLV_RENDER_TERMINATION_INFO] + sizeof(AppSpawnTlv));
        return pid->pid;
    }
    return -1;
}

static void WaitChildDied(pid_t pid)
{
    AppSpawningCtx *property = GetAppSpawningCtxByPid(&g_appSpawnMgr->processMgr, pid);
    if (property != NULL && property->state == APP_STATE_SPAWNING) {
        APPSPAWN_LOGI("Child process %{public}s fail \'child crash \'pid %{public}d appId: %{public}d",
            GetProcessName(property), property->pid, property->client.id);
        SendResponse(property->connection, &property->receiver->msgHeader, APPSPAWN_CHILD_CRASH, 0);
        DeleteAppSpawningCtx(property);
    }
}

static void WaitChildTimeout(const TimerHandle taskHandle, void *context)
{
    AppSpawningCtx *property = (AppSpawningCtx *)context;
    APPSPAWN_LOGI("Child process %{public}s fail \'wait child timeout \'pid %{public}d appId: %{public}d",
        GetProcessName(property), property->pid, property->client.id);
    if (property->pid > 0) {
        kill(property->pid, SIGKILL);
    }
    SendResponse(property->connection, &property->receiver->msgHeader, APPSPAWN_CLIENT_TIMEOUT, 0);
    DeleteAppSpawningCtx(property);
}

static void ProcessChildResponse(const WatcherHandle taskHandle, int fd, uint32_t *events, const void *context)
{
    AppSpawningCtx *property = (AppSpawningCtx *)context;
    property->forkCtx.watcherHandle = NULL;  // delete watcher
    LE_RemoveWatcher(LE_GetDefaultLoop(), (WatcherHandle)taskHandle);

    int result = 0;
    (void)read(fd, &result, sizeof(result));
    APPSPAWN_LOGI("Child process %{public}s success pid %{public}d appId: %{public}d result: %{public}d",
        GetProcessName(property), property->pid, property->client.id, result);

    if (result == 0) {
        AppSpawnedProcess *appInfo = AddSpawnedProcess(
            &g_appSpawnMgr->processMgr, property->pid, GetBundleName(property));
        if (appInfo) {
            AppSpawnMsgDacInfo *dacInfo = GetAppProperty(property, TLV_DAC_INFO);
            appInfo->uid = dacInfo != NULL ? dacInfo->uid : 0;
            // 添加max信息
        }
        AppChangeHookExecute(HOOK_APP_ADD, &g_appSpawnMgr->content, appInfo);
    }
    SendResponse(property->connection, &property->receiver->msgHeader, result, property->pid);
    DeleteAppSpawningCtx(property);
}

static void NotifyResToParent(AppSpawnContent *content, AppSpawnClient *client, int result)
{
    AppSpawningCtx *property = (AppSpawningCtx *)client;
    int fd = property->forkCtx.fd[1];
    if (fd >= 0) {
        (void)write(fd, &result, sizeof(result));
        (void)close(fd);
    }
    APPSPAWN_LOGV("NotifyResToParent client id: %{public}u fd %{public}d result: %{public}d", client->id, fd, result);
}

static int CreateAppSpawnServer(TaskHandle *server, const char *socketName)
{
    char path[128] = {0};  // 128 max path
    int ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s%s", APPSPAWN_SOCKET_DIR, socketName);
    APPSPAWN_CHECK(ret >= 0, return -1, "Failed to snprintf_s %{public}d", ret);
    int socketId = GetControlSocket(socketName);
    APPSPAWN_LOGI("get socket form env %{public}s socketId %{public}d", socketName, socketId);

    LE_StreamServerInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_SERVER;
    info.socketId = socketId;
    info.server = path;
    info.baseInfo.close = NULL;
    info.incommingConnect = OnConnection;

    MakeDirRec(path, 0711, 0);  // 0711 default mask
    ret = LE_CreateStreamServer(LE_GetDefaultLoop(), server, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create socket for %{public}s errno: %{public}d", path, errno);
    APPSPAWN_LOGI("CreateAppSpawnServer path %{public}s fd %{public}d", path, LE_GetSocketFd(*server));
    return 0;
}

void AppSpawnDestroyContent(AppSpawnContent *content)
{
    if (content == NULL) {
        return;
    }
    AppSpawnMgr *appSpawnContent = (AppSpawnMgr *)content;
    if (appSpawnContent->sigHandler != NULL) {
        LE_CloseSignalTask(LE_GetDefaultLoop(), appSpawnContent->sigHandler);
    }
    // release resource
    AppSpawnedProcessMgrDestroy(&appSpawnContent->processMgr);
    OH_ListRemoveAll(&appSpawnContent->extData, DataExDestroyProc);
    if (appSpawnContent->server != NULL) {
        LE_CloseStreamTask(LE_GetDefaultLoop(), appSpawnContent->server);
    }
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    free(appSpawnContent);
    g_appSpawnMgr = NULL;
}

static int AppSpawnColdStartApp(struct tagAppSpawnContent *content, AppSpawnClient *client)
{
    AppSpawningCtx *property = (AppSpawningCtx *)client;
    APPSPAWN_LOGI("ColdStartApp::processName: %{public}s", GetProcessName(property));

    char buffer[64] = {0};  // 64 buffer for fd
    int len = sprintf_s(buffer, sizeof(buffer), " %d %u  ", property->forkCtx.fd[1], property->client.flags);
    APPSPAWN_CHECK(len > 0, return APPSPAWN_SYSTEM_ERROR, "Invalid to format fd");
    char *appSpawnPath = "/system/bin/appspawn";
    if ((client->flags & APP_ASAN_DETECTOR) == APP_ASAN_DETECTOR) {  // asan detector
        appSpawnPath = "/system/asan/bin/appspawn";
    }

    char *param = Base64Encode(property->receiver->buffer, property->receiver->msgRecvLen - sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(param != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to encode msg");
    char *msgHeader = Base64Encode((uint8_t *)&property->receiver->msgHeader, sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(msgHeader != NULL, free(param);
        return APPSPAWN_SYSTEM_ERROR, "Failed to encode msg");
    char *mode = IsNWebSpawnMode((AppSpawnMgr *)content) ? "nweb_cold" : "app_cold";
    const char *const formatCmds[] = {appSpawnPath, "-mode", mode, "-param", param, "-fd", buffer, msgHeader, NULL};
    int ret = execv(appSpawnPath, (char **)formatCmds);
    if (ret) {
        APPSPAWN_LOGE("Failed to execv, errno = %{public}d", errno);
    }
    free(param);
    free(msgHeader);
    APPSPAWN_LOGV("ColdStartApp::processName: %{public}s end", GetProcessName(property));
    return 0;
}

static AppSpawnMsgReceiverCtx *GetAppSpawnMsgReceiverFromArg(AppSpawnMgr *content, int argc, char *const argv[])
{
    AppSpawnMsgReceiverCtx *receiver = CreateAppSpawnMsgReceiver();
    APPSPAWN_CHECK(receiver != NULL, return NULL, "Failed to create receiver");

    uint8_t *msgHeader = NULL;
    int ret = -1;
    do {
        // decode msg header
        uint32_t msgLen = 0;
        msgHeader = Base64Decode(argv[MSG_HEADER_INDEX], strlen(argv[MSG_HEADER_INDEX]), &msgLen);
        APPSPAWN_CHECK(msgHeader != NULL && msgLen == sizeof(AppSpawnMsg), break, "Failed to decode msg header ");
        ret = memcpy_s(&receiver->msgHeader, sizeof(receiver->msgHeader), msgHeader, msgLen);
        APPSPAWN_CHECK(ret == 0, break, "Failed to copy msg header");

        // decode msg
        ret = -1;
        receiver->buffer = Base64Decode(argv[PARAM_VALUE_INDEX], strlen(argv[PARAM_VALUE_INDEX]), &msgLen);
        APPSPAWN_CHECK(receiver->buffer != NULL, break, "Failed to decode msg ");
        APPSPAWN_CHECK(receiver->msgHeader.msgLen == msgLen + sizeof(AppSpawnMsg),
            break, "Msg length invalid %{public}u %{public}u", receiver->msgHeader.msgLen, msgLen);
        receiver->msgRecvLen = receiver->msgHeader.msgLen;
        ret = CheckRecvMsg(&receiver->msgHeader);
        APPSPAWN_CHECK(ret == 0, break, "Invalid msg");

        uint32_t totalCount = receiver->msgHeader.tlvCount + TLV_MAX;
        receiver->tlvOffset = malloc(totalCount * sizeof(uint32_t));
        APPSPAWN_CHECK(receiver->tlvOffset != NULL, break, "Failed to alloc memory for recv message");
        for (uint32_t i = 0; i < totalCount; i++) {
            receiver->tlvOffset[i] = INVALID_OFFSET;
        }
    } while (0);
    if (msgHeader) {
        free(msgHeader);
    }
    if (ret != 0) {
        DeleteAppSpawnMsgReceiver(receiver);
        receiver = NULL;
    }
    return receiver;
}

static void AppSpawnColdRun(AppSpawnContent *content, int argc, char *const argv[])
{
    APPSPAWN_CHECK(argc > MSG_HEADER_INDEX, return, "Invalid arg for cold start %{public}d", argc);
    AppSpawnMgr *appSpawnContent = (AppSpawnMgr *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Invalid appspawn content");

    AppSpawnMsgReceiverCtx *receiver = GetAppSpawnMsgReceiverFromArg(appSpawnContent, argc, argv);
    APPSPAWN_CHECK_ONLY_EXPER(receiver != NULL, return);
    AppSpawningCtx *property = CreateAppSpawningCtx(&g_appSpawnMgr->processMgr);
    if (property == NULL) {
        DeleteAppSpawnMsgReceiver(receiver);
        return;
    }
    property->forkCtx.fd[1] = atoi(argv[FD_VALUE_INDEX]);
    property->client.flags = atoi(argv[FLAGS_VALUE_INDEX]);
    property->client.flags &= ~APP_COLD_START;
    property->receiver = receiver;
    int ret = DecodeRecvMsg(receiver);
    if (ret == 0) {
        ret = CheckMsgReceiver(property, receiver);
    }
    if (ret != 0) {
        APPSPAWN_LOGE("decode message fail, result = %{public}d", ret);
        NotifyResToParent(content, &property->client, ret);
        DeleteAppSpawningCtx(property);
        return;
    }

    ret = AppSpawnHookExecute(HOOK_SPAWN_SECOND, HOOK_STOP_WHEN_ERROR, content, &property->client);
    if (ret != 0) {
        NotifyResToParent(content, &property->client, ret);
        DeleteAppSpawningCtx(property);
        return;
    }
    NotifyResToParent(content, &property->client, 0);

    AppSpawnHookExecute(HOOK_SPAWN_POST, 0, content, &property->client);
    if (content->runChildProcessor != NULL) {
        content->runChildProcessor(content, &property->client);
    }
    APPSPAWN_LOGI("AppSpawnColdRun exit %{public}d.", getpid());
    DeleteAppSpawningCtx(property);
}

static void AppSpawnRun(AppSpawnContent *content, int argc, char *const argv[])
{
    APPSPAWN_LOGI("AppSpawnRun");
    AppSpawnMgr *appSpawnContent = (AppSpawnMgr *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Invalid appspawn content");

    LE_STATUS status = LE_CreateSignalTask(LE_GetDefaultLoop(), &appSpawnContent->sigHandler, ProcessSignal);
    if (status == 0) {
        (void)LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGCHLD);
        (void)LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGTERM);
    }

    LE_RunLoop(LE_GetDefaultLoop());
    APPSPAWN_LOGI("AppSpawnRun exit mode: %{public}d ", content->mode);
}

AppSpawnContent *AppSpawnCreateContent(const char *socketName, char *longProcName, uint32_t nameLen, int mode)
{
    APPSPAWN_CHECK(socketName != NULL && longProcName != NULL, return NULL, "Invalid name");
    APPSPAWN_LOGI("AppSpawnCreateContent %{public}s %{public}u mode %{public}d", socketName, nameLen, mode);

    AppSpawnMgr *appSpawnContent = (AppSpawnMgr *)malloc(sizeof(AppSpawnMgr));
    APPSPAWN_CHECK(appSpawnContent != NULL, return NULL, "Failed to alloc memory for appspawn");
    (void)memset_s(&appSpawnContent->content, sizeof(appSpawnContent->content), 0, sizeof(appSpawnContent->content));
    appSpawnContent->content.longProcName = longProcName;
    appSpawnContent->content.longProcNameLen = nameLen;
    appSpawnContent->content.mode = mode;
    appSpawnContent->content.sandboxNsFlags = 0;
    appSpawnContent->server = NULL;
    appSpawnContent->sigHandler = NULL;
    AppSpawnedProcessMgrInit(&appSpawnContent->processMgr);
    OH_ListInit(&appSpawnContent->extData);

    appSpawnContent->content.notifyResToParent = NotifyResToParent;
    if (IsColdRunMode(appSpawnContent)) {
        appSpawnContent->content.runAppSpawn = AppSpawnColdRun;
    } else {
        appSpawnContent->content.runAppSpawn = AppSpawnRun;
        appSpawnContent->content.coldStartApp = AppSpawnColdStartApp;

        int ret = CreateAppSpawnServer(&appSpawnContent->server, socketName);
        APPSPAWN_CHECK(ret == 0,
            AppSpawnDestroyContent(&appSpawnContent->content); return NULL, "Failed to create server");
    }
    g_appSpawnMgr = appSpawnContent;
    return &g_appSpawnMgr->content;
}

AppSpawnContent *StartSpawnService(uint32_t argvSize, int argc, char *const argv[])
{
    // APPSPAWN_CHECK(argvSize >= APP_LEN_PROC_NAME, return NULL, "Invalid arg for start %{public}u", argvSize);
    const char *socketName = APPSPAWN_SOCKET_NAME;
    const char *serviceName = APPSPAWN_SERVER_NAME;
    AppSpawnModuleType moduleType = MODULE_APPSPAWN;
    RunMode mode = MODE_FOR_APPSPAWN;
    pid_t pid = -1;
    do {
        if (argc <= MODE_VALUE_INDEX) {  // appspawn start
            pid = NWebSpawnLaunch();
        } else if (strcmp(argv[MODE_VALUE_INDEX], "app_cold") == 0) {  // cold start
            mode = MODE_FOR_APP_COLD_RUN;
            break;
        } else if (strcmp(argv[MODE_VALUE_INDEX], "nweb_cold") == 0) {  // cold start
            mode = MODE_FOR_NWEB_COLD_RUN;
            moduleType = MODULE_NWEBSPAWN;
            break;
        } else if (strcmp(argv[MODE_VALUE_INDEX], NWEBSPAWN_SERVER_NAME) == 0) {  // nweb spawn start
            NWebSpawnInit();
            pid = 0;
        } else {
            pid = NWebSpawnLaunch();
        }
        if (pid == 0) {
            socketName = NWEBSPAWN_SOCKET_NAME;
            serviceName = NWEBSPAWN_SERVER_NAME;
            moduleType = MODULE_NWEBSPAWN;
            mode = MODE_FOR_NWEBSPAWN;
        }
        int ret = memset_s(argv[0], argvSize, 0, (size_t)argvSize);
        APPSPAWN_CHECK(ret == EOK, return NULL, "Failed to memset argv[0]");
        ret = strncpy_s(argv[0], argvSize, serviceName, strlen(serviceName));
        APPSPAWN_CHECK(ret == EOK, return NULL, "Failed to copy service name %{public}s", serviceName);
    } while (0);

    // load module appspawn/common
    AppSpawnLoadAutoRunModules(MODULE_COMMON);
    AppSpawnModuleMgrInstall("libappspawn_asan");

    APPSPAWN_CHECK(LE_GetDefaultLoop() != NULL, return NULL, "Invalid default loop");
    AppSpawnContent *content = AppSpawnCreateContent(socketName, argv[0], argvSize, mode);
    APPSPAWN_CHECK(content != NULL, return NULL, "Failed to create content for %{public}s", socketName);

    AppSpawnLoadAutoRunModules(moduleType);  // 按启动的模式加在对应的插件
    int ret = PreloadHookExecute(content);   // 预加载，解析sandbox
    APPSPAWN_CHECK(ret == 0, AppSpawnDestroyContent(content); return NULL,
        "Failed to prepare load %{public}s result: %{public}d", serviceName, ret);
    if (mode == MODE_FOR_APPSPAWN) {
        AddSpawnedProcess(&((AppSpawnMgr *)content)->processMgr, pid, NWEBSPAWN_SERVER_NAME);
        SetParameter("bootevent.appspawn.started", "true");
    }
    return content;
}

static void ProcessRecvMsg(AppSpawnConnection *connection, AppSpawnMsgReceiverCtx *receiver)
{
    AppSpawnMsg *msg = &receiver->msgHeader;
    APPSPAWN_LOGV("Recv message header magic 0x%{public}x type %{public}u id %{public}u len %{public}u %{public}s",
        msg->magic, msg->msgType, msg->msgId, msg->msgLen, msg->processName);
    switch (msg->msgType) {
        case MSG_GET_RENDER_TERMINATION_STATUS: {  // get status
            pid_t pid = 0;
            int ret = 0;
            if (IsNWebSpawnMode(g_appSpawnMgr)) {
                // get render process termination status, only nwebspawn need this logic.
                pid = GetPidFromTerminationMsg(receiver);
                ret = GetProcessTerminationStatus(&g_appSpawnMgr->processMgr, pid);
            }
            SendResponse(connection, msg, ret, pid);
            break;
        }
        case MSG_SPAWN_NATIVE_PROCESS:  // spawn msg
        case MSG_APP_SPAWN: {
            ProcessSpawnReqMsg(connection, receiver);
            receiver = NULL;
            break;
        }
        case MSG_DUMP:
            DumpApSpawn(g_appSpawnMgr);
            SendResponse(connection, msg, 0, 0);
            break;
        default:
            SendResponse(connection, msg, APPSPAWN_INVALID_MSG, 0);
            break;
    }
    DeleteAppSpawnMsgReceiver(receiver);
    connection->receiver = NULL;
}