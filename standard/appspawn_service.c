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

static AppSpawnContentExt *g_appSpawnContent = NULL;

static void WaitChildTimeout(const TimerHandle taskHandle, void *context);
static void ProcessChildResponse(const WatcherHandle taskHandle, int fd, uint32_t *events, const void *context);
static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen);
static void ProcessRecvMsg(AppSpawnConnection *connection, const uint8_t *msgBuffer, uint32_t msgLen);
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
    AppSpawnAppInfo *appInfo = ListEntry(node, AppSpawnAppInfo, node);
    pid_t pid = appInfo->pid;
    APPSPAWN_LOGI("kill app, pid = %{public}d, processName = %{public}s", appInfo->pid, appInfo->name);
    OH_ListRemove(&appInfo->node);
    OH_ListInit(&appInfo->node);
    free(appInfo);
    kill(pid, SIGKILL);
}

static void StopAppSpawn(void)
{
    if (g_appSpawnContent != NULL) {
        OH_ListRemoveAll(&g_appSpawnContent->appMgr.appQueue, AppQueueDestroyProc);
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
    AppSpawnAppInfo *appInfo = GetAppInfo(&g_appSpawnContent->appMgr, pid);
    if (appInfo == NULL) {
        WaitChildDied(pid);
        DumpStatus("unknown", pid, status);
        return;
    }

    appInfo->exitStatus = status;
    APPSPAWN_CHECK_ONLY_LOG(appInfo->uid == uid, "Invalid uid %{public}d %{public}d", appInfo->uid, uid);
    DumpStatus(appInfo->name, pid, status);
    AppChangeHookExecute(HOOK_APP_DIED, &g_appSpawnContent->content, appInfo);

    // if current process of death is nwebspawn, restart appspawn
    if (strcmp(appInfo->name, NWEBSPAWN_SERVER_NAME) == 0) {
        OH_ListRemove(&appInfo->node);
        free(appInfo);
        APPSPAWN_LOGW("Current process of death is nwebspawn, pid = %{public}d, restart appspawn", pid);
        StopAppSpawn();
        return;
    }
    // move app info to died queue in NWEBSPAWN, or delete appinfo
    AppMgrHandleAppDied(&g_appSpawnContent->appMgr, appInfo, IsNWebSpawnMode(g_appSpawnContent));
}

APPSPAWN_STATIC void SignalHandler(const struct signalfd_siginfo *siginfo)
{
    APPSPAWN_LOGI("SignalHandler signum %{public}d", siginfo->ssi_signo);
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

static void OnClose(const TaskHandle taskHandle)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, return, "Invalid connection");
    APPSPAWN_LOGI("OnClose connectionId: %{public}u socket %{public}d",
        connection->connectionId, LE_GetSocketFd(taskHandle));
    if (connection->timer) {
        LE_StopTimer(LE_GetDefaultLoop(), connection->timer);
        connection->timer = NULL;
    }
    if (connection->buffer) {
        free(connection->buffer);
        connection->buffer = NULL;
    }
    AppMgrHandleConnectClose(&g_appSpawnContent->appMgr, connection);
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
    AppSpawnAppInfo *appInfo = GetAppInfo(&g_appSpawnContent->appMgr, msg->result.pid);
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
    APPSPAWN_CHECK(ret == 0,
        LE_FreeBuffer(LE_GetDefaultLoop(), NULL, handle);
        return -1, "Failed to memcpy_s bufferSize");
    buffer->result.result = result;
    buffer->result.pid = pid;
    return LE_Send(LE_GetDefaultLoop(), connection->stream, handle, bufferSize);
}

static void ConnectionTimeOut(const TimerHandle taskHandle, void *context)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)context;
    APPSPAWN_LOGV("ConnectionTimeOut connectionId %{public}u msgRecvLen %{public}u",
        connection->connectionId, connection->msgRecvLen);
    APPSPAWN_LOGE("Long time no msg complete so close connectionId: %{public}u %d ", connection->connectionId, LE_GetSocketFd(taskHandle));
    LE_StopTimer(LE_GetDefaultLoop(), connection->timer);
    connection->timer = NULL;
    LE_CloseStreamTask(LE_GetDefaultLoop(), connection->stream);
}

static inline int StartTimerForCheckMsg(AppSpawnConnection *connection)
{
    if (connection->timer != NULL) {
        return 0;
    }
    int ret = LE_CreateTimer(LE_GetDefaultLoop(), &connection->timer, ConnectionTimeOut, connection);
    if (ret == 0) {
        ret = LE_StartTimer(LE_GetDefaultLoop(), connection->timer, MAX_WAIT_MSG_COMPLETE, 1);
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
    connection->msgRecvLen = 0;
    connection->timer = NULL;
    connection->buffer = NULL;
    (void)memset_s(&connection->msg, sizeof(connection->msg), 0, sizeof(connection->msg));
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

static void ResetClientConnection(AppSpawnConnection *connection)
{
    (void)memset_s(&connection->msg, sizeof(connection->msg), 0, sizeof(connection->msg));
    if (connection->buffer) {
        free(connection->buffer);
        connection->buffer = NULL;
    }
    if (connection->timer) {
        LE_StopTimer(LE_GetDefaultLoop(), connection->timer);
        connection->timer = NULL;
    }
    connection->msgRecvLen = 0;
}

static int HandleRecvBuffer(AppSpawnConnection *connection,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *reminder)
{
    *reminder = 0;
    if (connection->msgRecvLen < sizeof(connection->msg)) {  // recv partial message
        if ((bufferLen + connection->msgRecvLen) >= sizeof(connection->msg)) {
            int ret = memcpy_s(((uint8_t *)&connection->msg) + connection->msgRecvLen,
                sizeof(connection->msg) - connection->msgRecvLen,
                buffer, sizeof(connection->msg) - connection->msgRecvLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");

            APPSPAWN_CHECK_ONLY_EXPER(CheckRecvMsg(&connection->msg) == 0, return -1);
            connection->buffer = malloc(connection->msg.msgLen);
            APPSPAWN_CHECK(connection->buffer != NULL, return -1, "Failed to alloc memory for recv message");

            if (connection->msgRecvLen > 0) { // copy last message to buffer
                ret = memcpy_s(connection->buffer, sizeof(connection->msg), &connection->msg, connection->msgRecvLen);
                APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
            }
        } else {
            int ret = memcpy_s(((uint8_t *)&connection->msg) + connection->msgRecvLen,
                sizeof(connection->msg) - connection->msgRecvLen, buffer, bufferLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
            connection->msgRecvLen += bufferLen;
            return 0;
        }
    }

    uint32_t realCopy = (bufferLen + connection->msgRecvLen) > connection->msg.msgLen ?
        connection->msg.msgLen - connection->msgRecvLen : bufferLen;
    int ret = memcpy_s(connection->buffer + connection->msgRecvLen,
        connection->msg.msgLen - connection->msgRecvLen, buffer, realCopy);
    APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
    connection->msgRecvLen += realCopy;

    if (connection->msgRecvLen == connection->msg.msgLen) {  // recv complete msg
        ProcessRecvMsg(connection, connection->buffer, connection->msgRecvLen);
        connection->buffer = NULL;
        connection->msgRecvLen = 0;
        ResetClientConnection(connection);
        if (realCopy < bufferLen) {
            *reminder = bufferLen - realCopy;
        }
    }
    return 0;
}

static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Failed to get client form socket");
    APPSPAWN_CHECK(buffLen < MAX_MSG_TOTAL_LENGTH, return, "Message too long");

    APPSPAWN_LOGV("OnReceiveRequest msgRecvLen: %{public}u buffer: 0x%{public}x buffLen %{public}d",
        connection->msgRecvLen, *(uint32_t *)(buffer), buffLen);
    uint32_t reminder = 0;
    int ret = HandleRecvBuffer(connection, buffer, buffLen, &reminder);
    if (ret != 0) {
        LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
        return;
    }
    while (reminder > 0) {
        ret = HandleRecvBuffer(connection, buffer + buffLen - reminder, reminder, &reminder);
        if (ret != 0) {
            LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
            return;
        }
    }
    // 有部分数据，启动检测定时器
    if (connection->msgRecvLen > 0) {
        ret = StartTimerForCheckMsg(connection);
        APPSPAWN_CHECK(ret == 0, LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
            return, "Failed to create time for connection");
    }
}

static inline void AddNullForString(char*data, uint32_t maxLen)
{
    data[maxLen - 1] = '\0';
}

static int CheckAppProperty(const AppProperty *property, const uint8_t *buffer, uint32_t msgLen)
{
    // add '\0' to message
    AddNullForString(property->msg->processName, sizeof(property->msg->processName));
    APPSPAWN_CHECK(strlen(property->msg->processName) > 0,
        return APPSPAWN_INVALID_MSG, "Invalid property processName %{public}s", property->msg->processName);
    if (property->tlvOffset[TLV_BUNDLE_INFO] == 0 ||
        property->tlvOffset[TLV_MSG_FLAGS] == 0 ||
        property->tlvOffset[TLV_ACCESS_TOKEN_INFO] == 0 ||
        property->tlvOffset[TLV_DAC_INFO] == 0) {
        APPSPAWN_LOGE("No must tlv: %{public}u %{public}u %{public}u", property->tlvOffset[TLV_BUNDLE_INFO],
            property->tlvOffset[TLV_MSG_FLAGS], property->tlvOffset[TLV_DAC_INFO]);
        return APPSPAWN_INVALID_MSG;
    }
    if (property->tlvOffset[TLV_BUNDLE_INFO] > 0) {
        AppSpawnMsgBundleInfo *bundleInfo = (AppSpawnMsgBundleInfo *)(buffer + property->tlvOffset[TLV_BUNDLE_INFO]);
        if (strstr(bundleInfo->bundleName, "\\") != NULL || strstr(bundleInfo->bundleName, "/") != NULL) {
            APPSPAWN_LOGE("Invalid bundle name %{public}s", bundleInfo->bundleName);
            return APPSPAWN_INVALID_MSG;
        }
    }
    DumpNormalProperty(property, buffer + sizeof(AppSpawnTlv));
    return 0;
}

static int CheckExtTlvInfo(const uint8_t *buffer, uint32_t remainLen, const AppSpawnTlv *tlv)
{
    AppSpawnTlvEx *tlvEx = (AppSpawnTlvEx *)(tlv);
    APPSPAWN_LOGV("Recv type [%{public}s %{public}u] real len: %{public}u",
        tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen);
    if (tlvEx->dataLen > tlvEx->tlvLen - sizeof(AppSpawnTlvEx)) {
        APPSPAWN_LOGE("Invalid tlv [%{public}s %{public}u] real len: %{public}u %{public}u",
            tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen, sizeof(AppSpawnTlvEx));
        return APPSPAWN_INVALID_MSG;
    }
    AddNullForString((char *)(buffer + sizeof(AppSpawnTlvEx)), tlv->tlvLen - sizeof(AppSpawnTlvEx));
    return 0;
}

static int CheckMsgTlv(const uint8_t *buffer, uint32_t remainLen)
{
    AppSpawnTlv *tlv = (AppSpawnTlv *)(buffer);
    APPSPAWN_CHECK(tlv->tlvLen <= remainLen, return APPSPAWN_INVALID_MSG,
        "Invalid tlv [%{public}d %{public}d] ", tlv->tlvType, tlv->tlvLen);
    uint32_t tlvLen = 0;
    switch (tlv->tlvType) {
        case TLV_MSG_FLAGS:
            tlvLen = ((AppSpawnMsgFlags *)(buffer + sizeof(AppSpawnTlv)))->count * sizeof(uint32_t);
            break;
        case TLV_ACCESS_TOKEN_INFO:
            tlvLen = sizeof(AppAccessTokenInfo);
            break;
        case TLV_DAC_INFO:
            tlvLen = sizeof(AppSpawnMsgDacInfo);
            break;
        case TLV_BUNDLE_INFO: {
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= sizeof(AppBundleInfo),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            AppSpawnMsgBundleInfo *bundleInfo = (AppSpawnMsgBundleInfo *)(buffer + sizeof(AppSpawnTlv));
            AddNullForString(bundleInfo->bundleName, tlv->tlvLen - sizeof(AppSpawnTlv) - sizeof(AppSpawnMsgBundleInfo));
            break;
        }
        case TLV_OWNER_INFO: {
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) < sizeof(AppOwnerId),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            AppSpawnMsgOwnerId *info = (AppSpawnMsgOwnerId *)(buffer + sizeof(AppSpawnTlv));
            AddNullForString(info->ownerId, tlv->tlvLen - sizeof(AppSpawnTlv) - sizeof(AppSpawnMsgOwnerId));
            break;
        }
        case TLV_RENDER_CMD: {
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) < sizeof(AppRenderCmd),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            AppSpawnMsgRenderCmd *info = (AppSpawnMsgRenderCmd *)(buffer + sizeof(AppSpawnTlv));
            AddNullForString(info->renderCmd, tlv->tlvLen - sizeof(AppSpawnTlv) - sizeof(AppSpawnMsgRenderCmd));
            break;
        }
        case TLV_DOMAIN_INFO: {
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) < sizeof(AppDomainInfo),
                return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            AppSpawnMsgDomainInfo *info = (AppSpawnMsgDomainInfo *)(buffer + sizeof(AppSpawnTlv));
            AddNullForString(info->apl, tlv->tlvLen - sizeof(AppSpawnTlv) - sizeof(AppSpawnMsgDomainInfo));
            break;
        }
        case TLV_MAX:
            return CheckExtTlvInfo(buffer, remainLen, tlv);
        default:
            break;
    }
    APPSPAWN_CHECK(tlvLen <= tlv->tlvLen,
        return APPSPAWN_INVALID_MSG, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
    return 0;
}

APPSPAWN_STATIC int DecodeRecvMsg(AppProperty *property, const uint8_t *buffer, uint32_t msgLen)
{
    // decode tlv
    int ret = 0;
    uint32_t tlvCount = 0;
    uint32_t currLen = sizeof(AppSpawnMsg);
    while (currLen < msgLen) {
        ret = CheckMsgTlv(buffer + currLen, msgLen - currLen);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        AppSpawnTlv *tlv = (AppSpawnTlv *)(buffer + currLen);
        if (tlv->tlvType < TLV_MAX) {  // normal
            property->tlvOffset[tlv->tlvType] = currLen;
            currLen += tlv->tlvLen;
        } else {
            APPSPAWN_CHECK((tlvCount + 1) < property->tlvCount, break,
                "Invalid tlv number tlv %{public}d tlvCount: %{public}d", tlv->tlvType, tlvCount);
            property->tlvOffset[TLV_MAX + tlvCount] = currLen;
            tlvCount++;
            currLen += tlv->tlvLen;
        }
    }
    APPSPAWN_CHECK_ONLY_EXPER(currLen >= msgLen, return APPSPAWN_INVALID_MSG);
    // save real ext tlv count
    property->tlvCount = tlvCount;
    // 校验
    ret = CheckAppProperty(property, buffer, msgLen);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    return 0;
}

static int CreatePipe(AppProperty *property)
{
    if (pipe(property->fd) == -1) {
        APPSPAWN_LOGE("create pipe fail, errno: %{public}d", errno);
        return errno;
    }
    int option = fcntl(property->fd[0], F_GETFD);
    if (option > 0) {
        (void)fcntl(property->fd[0], F_SETFD, option | O_NONBLOCK);
    }
    return 0;
}

static void ProcessSpawnReqMsg(AppSpawnConnection *connection, const uint8_t *msgBuffer, uint32_t msgLen)
{
    AppSpawnMsg *msg = (AppSpawnMsg *)msgBuffer;
    if (CheckRecvMsg(msg) != 0) {
        SendResponse(connection, (AppSpawnMsg *)msgBuffer, APPSPAWN_INVALID_MSG, 0);
        return;
    }
    AppProperty *property = AppMgrCreateAppProperty(&g_appSpawnContent->appMgr, msg->tlvCount);
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    property->connection = connection; // 由property管理消息
    property->msg = msg;
    connection->buffer = NULL;
    connection->msgRecvLen = 0;
    int ret = DecodeRecvMsg(property, msgBuffer, msgLen);
    if (ret != 0) {
        SendResponse(connection, (AppSpawnMsg *)msgBuffer, ret, 0);
        AppMgrDeleteAppProperty(property);
        return;
    }

    if (CreatePipe(property) != 0) {
        SendResponse(connection, property->msg, APPSPAWN_SYSTEM_ERROR, 0);
        AppMgrDeleteAppProperty(property);
        return;
    }
    APPSPAWN_LOGI("ProcessSpawnReqMsg app: %{public}s reqId: %{public}u clientId: %{public}d",
        GetProcessName(property), property->msg->msgId, property->client.id);
    property->state = APP_STATE_SPAWNING;
    ret = AppSpawnProcessMsg(&g_appSpawnContent->content, &property->client, &property->pid);
    if (ret != 0) {  // wait child process result
        SendResponse(connection, property->msg, ret, 0);
        AppMgrDeleteAppProperty(property);
        return;
    }

    LE_WatchInfo watchInfo = {};
    watchInfo.fd = property->fd[0];
    watchInfo.flags = WATCHER_ONCE;
    watchInfo.events = Event_Read;
    watchInfo.processEvent = ProcessChildResponse;
    LE_STATUS status = LE_StartWatcher(LE_GetDefaultLoop(), &property->watcherHandle, &watchInfo, property);
    if (status == LE_SUCCESS) {
        // start time wait child response
        status = LE_CreateTimer(LE_GetDefaultLoop(), &property->timer, WaitChildTimeout, property);
        status = LE_StartTimer(LE_GetDefaultLoop(), property->timer, WAIT_CHILD_RESPONSE_TIMEOUT, 0);
    }
    if (status != LE_SUCCESS) {
        SendResponse(connection, property->msg, APPSPAWN_SYSTEM_ERROR, 0);
        AppMgrDeleteAppProperty(property);
        return;
    }
}

static pid_t GetPidFromTerminationMsg(const uint8_t *buffer, uint32_t msgLen)
{
    uint32_t currLen = sizeof(AppSpawnMsg);
    while (currLen < msgLen) {
        AppSpawnTlv *tlv = (AppSpawnTlv *)(buffer + currLen);
        APPSPAWN_LOGV("GetPidFromTerminationMsg %{public}d ", tlv->tlvType);
        if (tlv->tlvType == TLV_RENDER_TERMINATION_INFO) {
            return ((AppSpawnResult *)(buffer + currLen + sizeof(AppSpawnTlv)))->pid;
        }
        currLen += tlv->tlvLen;
    }
    return -1;
}

static void WaitChildDied(pid_t pid)
{
    AppProperty *property = GetAppPropertyByPid(&g_appSpawnContent->appMgr, pid);
    if (property != NULL && property->state == APP_STATE_SPAWNING) {
        APPSPAWN_LOGI("Child process %{public}s fail \'child crash \'pid %{public}d appId: %{public}d",
            GetProcessName(property), property->pid, property->client.id);
        SendResponse(property->connection, property->msg, APPSPAWN_CHILD_CRASH, 0);
        AppMgrDeleteAppProperty(property);
    }
}

static void WaitChildTimeout(const TimerHandle taskHandle, void *context)
{
    AppProperty *property = (AppProperty *)context;
    APPSPAWN_LOGI("Child process %{public}s fail \'wait child timeout \'pid %{public}d appId: %{public}d",
        GetProcessName(property), property->pid, property->client.id);
    SendResponse(property->connection, property->msg, APPSPAWN_CLIENT_TIMEOUT, 0);
    AppMgrDeleteAppProperty(property);
}

static void ProcessChildResponse(const WatcherHandle taskHandle, int fd, uint32_t *events, const void *context)
{
    AppProperty *property = (AppProperty *)context;
    property->watcherHandle = NULL; // delete watcher
    LE_RemoveWatcher(LE_GetDefaultLoop(), (WatcherHandle)taskHandle);

    int result = 0;
    (void)read(fd, &result, sizeof(result));
    APPSPAWN_LOGI("Child process %{public}s success pid %{public}d appId: %{public}d result: %{public}d",
        GetProcessName(property), property->pid, property->client.id, result);

    if (result == 0) {
        AppSpawnAppInfo *appInfo = AppMgrAddApp(&g_appSpawnContent->appMgr, property->pid, GetBundleName(property));
        if (appInfo) {
            AppSpawnMsgDacInfo *dacInfo = GetAppProperty(property, TLV_DAC_INFO);
            appInfo->uid = dacInfo != NULL ? dacInfo->uid : 0;
            // 添加max信息
        }
        AppChangeHookExecute(HOOK_APP_ADD, &g_appSpawnContent->content, appInfo);
    }
    SendResponse(property->connection, property->msg, result, property->pid);
    AppMgrDeleteAppProperty(property);
}

static void NotifyResToParent(AppSpawnContent *content, AppSpawnClient *client, int result)
{
    AppProperty *property = (AppProperty *)client;
    int fd = property->fd[1];
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

    MakeDirRec(path, 0711, 0);
    ret = LE_CreateStreamServer(LE_GetDefaultLoop(), server, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create socket for %{public}s errno: %{public}d", path, errno);
    APPSPAWN_LOGI("CreateAppSpawnServer path %{public}s fd %{public}d", path, LE_GetSocketFd(*server));
    return 0;
}

APPSPAWN_STATIC void AppSpawnDestroyContent(AppSpawnContent *content)
{
    if (content == NULL) {
        return;
    }
    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)content;
    if (appSpawnContent->timer != NULL) {
        LE_StopTimer(LE_GetDefaultLoop(), appSpawnContent->timer);
        appSpawnContent->timer = NULL;
    }
    if (appSpawnContent->sigHandler != NULL) {
        LE_CloseSignalTask(LE_GetDefaultLoop(), appSpawnContent->sigHandler);
    }
    // release resource
    AppSpawnAppMgrDestroy(&appSpawnContent->appMgr);
    OH_ListRemoveAll(&appSpawnContent->extData, DataExDestroyProc);
    if (appSpawnContent->server != NULL) {
        LE_CloseStreamTask(LE_GetDefaultLoop(), appSpawnContent->server);
    }
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    free(appSpawnContent);
    g_appSpawnContent = NULL;
}

static int AppSpawnColdStartApp(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    AppProperty *property = (AppProperty *)client;
    APPSPAWN_LOGI("ColdStartApp::processName: %{public}s", GetProcessName(property));

    char buffer[64] = {0};  // 64 buffer for fd
    int len = sprintf_s(buffer, sizeof(buffer), " %d %u ", property->fd[1], property->client.flags);
    APPSPAWN_CHECK(len > 0, return APPSPAWN_SYSTEM_ERROR, "Invalid to format fd");

    char *appSpawnPath = "/system/bin/appspawn";
    if ((client->flags & APP_ASAN_DETECTOR) == APP_ASAN_DETECTOR) {  // asan detector
        appSpawnPath = "/system/asan/bin/appspawn";
    }

    char *param = Base64Encode((uint8_t *)property->msg, property->msg->msgLen);
    APPSPAWN_CHECK(param != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to encode msg");
    char *mode = IsNWebSpawnMode((AppSpawnContentExt *)content) ? "nweb_cold" : "app_cold";
    const char * const formatCmds[] = {appSpawnPath, "-mode", mode, "-param", param, "-fd", buffer, NULL};
    int ret = execv(appSpawnPath, (char **)formatCmds);
    if (ret) {
        APPSPAWN_LOGE("Failed to execv, errno = %{public}d", errno);
    }
    free(param);
    APPSPAWN_LOGV("ColdStartApp::processName: %{public}s end", GetProcessName(property));
    return 0;
}

static void AppSpawnColdRun(AppSpawnContent *content, int argc, char *const argv[])
{
    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Invalid appspawn content");

    // decode msg
    uint32_t msgLen = 0;
    uint8_t *msgBuffer = Base64Decode(argv[PARAM_VALUE_INDEX], strlen(argv[PARAM_VALUE_INDEX]), &msgLen);
    APPSPAWN_CHECK(msgBuffer != NULL, return, "Failed to decode msg ");
    AppSpawnMsg *msg = (AppSpawnMsg *)msgBuffer;
    APPSPAWN_CHECK(msg->msgLen == msgLen, return, "Msg length invalid %{public}u %{public}u", msg->msgLen, msgLen);
    if (CheckRecvMsg(msg) != 0) {
        return;
    }
    AppProperty *property = AppMgrCreateAppProperty(&g_appSpawnContent->appMgr, msg->tlvCount);
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL, return);
    property->fd[1] = atoi(argv[FD_VALUE_INDEX]);
    property->client.flags = atoi(argv[FLAGS_VALUE_INDEX]);
    property->client.flags &= ~APP_COLD_START;
    property->msg = msg;
    int ret = DecodeRecvMsg(property, msgBuffer, msgLen);
    if (ret != 0) {
        APPSPAWN_LOGE("decode message fail, result = %{public}d", ret);
        NotifyResToParent(content, &property->client, ret);
        AppMgrDeleteAppProperty(property);
        return;
    }

    ret = AppSpawnHookExecute(HOOK_SPAWN_SECOND, HOOK_STOP_WHEN_ERROR, content, &property->client);
    if (ret != 0) {
        NotifyResToParent(content, &property->client, ret);
        AppMgrDeleteAppProperty(property);
        return;
    }
    NotifyResToParent(content, &property->client, 0);

    AppSpawnHookExecute(HOOK_SPAWN_POST, 0, content, &property->client);
    if (content->runChildProcessor != NULL) {
        content->runChildProcessor(content, &property->client);
    }
    APPSPAWN_LOGI("AppSpawnColdRun exit %{public}d.", getpid());
    AppMgrDeleteAppProperty(property);
    AppSpawnDestroyContent(content);
    g_appSpawnContent = NULL;
}

static void AppSpawnRun(AppSpawnContent *content, int argc, char *const argv[])
{
    APPSPAWN_LOGI("AppSpawnRun");
    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Invalid appspawn content");

    LE_STATUS status = LE_CreateSignalTask(LE_GetDefaultLoop(), &appSpawnContent->sigHandler, SignalHandler);
    if (status == 0) {
        (void)LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGCHLD);
        (void)LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGTERM);
    }

    LE_RunLoop(LE_GetDefaultLoop());
    APPSPAWN_LOGI("AppSpawnRun exit mode: %{public}d ", content->mode);
    AppSpawnDestroyContent(content);
    g_appSpawnContent = NULL;
}

APPSPAWN_STATIC AppSpawnContent *AppSpawnCreateContent(
    const char *socketName, char *longProcName, uint32_t nameLen, int mode)
{
    APPSPAWN_CHECK(socketName != NULL && longProcName != NULL, return NULL, "Invalid name");
    APPSPAWN_LOGI("AppSpawnCreateContent %{public}s %{public}u mode %{public}d", socketName, nameLen, mode);

    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)malloc(sizeof(AppSpawnContentExt));
    APPSPAWN_CHECK(appSpawnContent != NULL, return NULL, "Failed to alloc memory for appspawn");
    (void)memset_s(&appSpawnContent->content, sizeof(appSpawnContent->content), 0, sizeof(appSpawnContent->content));
    appSpawnContent->content.longProcName = longProcName;
    appSpawnContent->content.longProcNameLen = nameLen;
    appSpawnContent->content.mode = mode;
    appSpawnContent->content.sandboxNsFlags = 0;
    appSpawnContent->timer = NULL;
    appSpawnContent->server = NULL;
    appSpawnContent->sigHandler = NULL;
    AppSpawnAppMgrInit(&appSpawnContent->appMgr);
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
    g_appSpawnContent = appSpawnContent;
    return &g_appSpawnContent->content;
}

AppSpawnContent *StartSpawnService(uint32_t argvSize, int argc, char *const argv[])
{
    APPSPAWN_CHECK(argvSize >= APP_LEN_PROC_NAME, return NULL, "Invalid arg for start %{public}u", argvSize);
    const char *socketName = APPSPAWN_SOCKET_NAME;
    const char *serviceName = APPSPAWN_SERVER_NAME;
    AppSpawnModuleType moduleType = MODULE_APPSPAWN;
    RunMode mode = MODE_FOR_APPSPAWN;
    pid_t pid = -1;
    do {
        if (argc <= MODE_VALUE_INDEX) { // appspawn start
            pid = NWebSpawnLaunch();
        } else if (strcmp(argv[MODE_VALUE_INDEX], "app_cold") == 0) { // cold start
            APPSPAWN_CHECK(argc > FLAGS_VALUE_INDEX, return NULL, "Invalid arg for cold start %{public}d", argc);
            mode = MODE_FOR_APP_COLD_RUN;
            break;
        } else if (strcmp(argv[MODE_VALUE_INDEX], "nweb_cold") == 0) { // cold start
            APPSPAWN_CHECK(argc > FLAGS_VALUE_INDEX, return NULL, "Invalid arg for cold start %{public}d", argc);
            mode = MODE_FOR_NWEB_COLD_RUN;
            moduleType = MODULE_NWEBSPAWN;
            break;
        } else if (strcmp(argv[MODE_VALUE_INDEX], NWEBSPAWN_SERVER_NAME) == 0) { // nweb spawn start
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
#ifdef APPSPAWN_ASAN
    AppSpawnModuleMgrInstall("libappspawn_asan");
#endif
    APPSPAWN_CHECK(LE_GetDefaultLoop() != NULL, return NULL, "Invalid default loop");
    AppSpawnContent *content = AppSpawnCreateContent(socketName, argv[0], argvSize, mode);
    APPSPAWN_CHECK(content != NULL, return NULL, "Failed to create content for %{public}s", socketName);

    AppSpawnLoadAutoRunModules(moduleType);  // 按启动的模式加在对应的插件
    int ret = PreloadHookExecute(content);  // 预加载，解析sandbox
    APPSPAWN_CHECK(ret == 0 && content->runChildProcessor != NULL, AppSpawnDestroyContent(content);
        return NULL, "Failed to init %{public}s result: %{public}d", serviceName, ret);
    if (mode == MODE_FOR_APPSPAWN) {
        if (pid > 0) {
            AppMgrAddApp(&((AppSpawnContentExt *)content)->appMgr, pid, NWEBSPAWN_SERVER_NAME);
        }
        SetParameter("bootevent.appspawn.started", "true");
    }
    return content;
}

static void ProcessRecvMsg(AppSpawnConnection *connection, const uint8_t *msgBuffer, uint32_t msgLen)
{
    AppSpawnMsg *msg = (AppSpawnMsg *)msgBuffer;
    APPSPAWN_LOGV("Recv message header magic 0x%{public}x %{public}u %{public}u %{public}u %{public}u %{public}s",
        msg->magic, msg->msgType, msg->msgId, msg->msgLen, msg->tlvCount, msg->processName);
    switch (msg->msgType) {
        case MSG_GET_RENDER_TERMINATION_STATUS: {  // get status
            pid_t pid = 0;
            int ret = 0;
            if (IsNWebSpawnMode(g_appSpawnContent)) {
                // get render process termination status, only nwebspawn need this logic.
                pid = GetPidFromTerminationMsg(msgBuffer, msgLen);
                ret = GetProcessTerminationStatus(&g_appSpawnContent->appMgr, pid);
            }
            SendResponse(connection, msg, ret, pid);
            break;
        }
        case MSG_SPAWN_NATIVE_PROCESS:  // spawn msg
        case MSG_APP_SPAWN: {
            ProcessSpawnReqMsg(connection, msgBuffer, msgLen);
            msgBuffer = NULL;
            break;
        }
        case MSG_KEEPALIVE:  // no need response
            SendResponse(connection, msg, 0, 0);
            break;
        case MSG_DUMP:
            DumpApSpawn(g_appSpawnContent);
            SendResponse(connection, msg, 0, 0);
            break;
        default:
            SendResponse(connection, msg, APPSPAWN_INVALID_MSG, 0);
            break;
    }
    if (msgBuffer) {
        free((void *)msgBuffer);
    }
}