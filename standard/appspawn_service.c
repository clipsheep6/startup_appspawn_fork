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
#include <sys/ipc.h>
#include <sys/shm.h>
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
static void WaitChildDied(pid_t pid);
static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen);
static void ProcessRecvMsg(AppSpawnConnection *connection, AppSpawnMsgNode *message);

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
    if (appInfo == NULL) { // app孵化过程中异常，kill pid，返回失败
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

static void OnClose(const TaskHandle taskHandle)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, return, "Invalid connection");
    APPSPAWN_LOGI("OnClose connectionId: %{public}u socket %{public}d",
        connection->connectionId, LE_GetSocketFd(taskHandle));
    DeleteAppSpawnMsg(connection->receiverCtx.incompleteMsg);
    connection->receiverCtx.incompleteMsg = NULL;
    ListNode *node = g_appSpawnMgr->processMgr.appSpawnQueue.next;
    // 遍历结束所有这个连接下的孵化进程
    while (node != &g_appSpawnMgr->processMgr.appSpawnQueue) {
        ListNode *next = node->next;
        AppSpawningCtx *property = ListEntry(node, AppSpawningCtx, node);
        if (property->message == NULL || property->message->connection != connection) {
            node = next;
            continue;
        }
        APPSPAWN_LOGI("Kill process, pid: %{public}d app: %{public}s", property->pid, GetProcessName(property));
        if (kill(property->pid, SIGKILL) != 0) {
            APPSPAWN_LOGE("unable to kill process, pid: %{public}d errno: %{public}d", property->pid, errno);
        }
        DeleteAppSpawningCtx(property);
        node = next;
    }
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
    APPSPAWN_LOGV("SendResponse connectionId %{public}u result: 0x%{public}x pid: %{public}d",
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
    DeleteAppSpawnMsg(connection->receiverCtx.incompleteMsg);
    connection->receiverCtx.incompleteMsg = NULL;
    LE_CloseStreamTask(LE_GetDefaultLoop(), connection->stream);
}

static inline int StartTimerForCheckMsg(AppSpawnConnection *connection)
{
    if (connection->receiverCtx.timer != NULL) {
        return 0;
    }
    int ret = LE_CreateTimer(LE_GetDefaultLoop(), &connection->receiverCtx.timer, WaitMsgCompleteTimeOut, connection);
    if (ret == 0) {
        ret = LE_StartTimer(LE_GetDefaultLoop(), connection->receiverCtx.timer, MAX_WAIT_MSG_COMPLETE, 1);
    }
    return ret;
}

static int OnConnection(const LoopHandle loopHandle, const TaskHandle server)
{
    APPSPAWN_CHECK(server != NULL && loopHandle != NULL, return -1, "Error server");
    static uint32_t connectionId = 0;
    TaskHandle stream;
    LE_StreamInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_CONNECT;
    info.baseInfo.close = OnClose;
    info.baseInfo.userDataSize = sizeof(AppSpawnConnection);
    info.disConnectComplete = NULL;
    info.sendMessageComplete = SendMessageComplete;
    info.recvMessage = OnReceiveRequest;
    LE_STATUS ret = LE_AcceptStreamClient(loopHandle, server, &stream, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc stream");

    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(stream);
    APPSPAWN_CHECK(connection != NULL, return -1, "Failed to alloc stream");
    struct ucred cred = {-1, -1, -1};
    socklen_t credSize = sizeof(struct ucred);
    if ((getsockopt(LE_GetSocketFd(stream), SOL_SOCKET, SO_PEERCRED, &cred, &credSize) < 0) ||
        (cred.uid != DecodeUid("foundation") && cred.uid != DecodeUid("root"))) {
        APPSPAWN_LOGE("Invalid uid %{public}d from client", cred.uid);
        LE_CloseStreamTask(LE_GetDefaultLoop(), stream);
        return -1;
    }
    connection->connectionId = ++connectionId;
    connection->stream = stream;
    connection->receiverCtx.incompleteMsg = NULL;
    connection->receiverCtx.timer = NULL;
    connection->receiverCtx.msgRecvLen = 0;
    connection->receiverCtx.nextMsgId = 1;
    APPSPAWN_LOGI("OnConnection connectionId: %{public}u fd %{public}d ",
        connection->connectionId, LE_GetSocketFd(stream));
    return 0;
}

static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    AppSpawnConnection *connection = (AppSpawnConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != NULL, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Failed to get client form socket");
    APPSPAWN_CHECK(buffLen < MAX_MSG_TOTAL_LENGTH, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Message too long %{public}u", buffLen);

    uint32_t reminder = 0;
    uint32_t currLen = 0;
    AppSpawnMsgNode *message = connection->receiverCtx.incompleteMsg; // incomplete msg
    connection->receiverCtx.incompleteMsg = NULL;
    int ret = 0;
    do {
        APPSPAWN_LOGV("ProcessReceiveBuffer buffer: 0x%{public}x buffLen %{public}d",
            *(uint32_t *)(buffer + currLen), buffLen - currLen);

        ret = GetAppSpawnMsgFromBuffer(buffer + currLen, buffLen - currLen,
            &message, &connection->receiverCtx.msgRecvLen, &reminder);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        if (connection->receiverCtx.msgRecvLen != message->msgHeader.msgLen) {  // recv complete msg
            connection->receiverCtx.incompleteMsg = message;
            message = NULL;
            break;
        }
        connection->receiverCtx.msgRecvLen = 0;
        if (connection->receiverCtx.timer) {
            LE_StopTimer(LE_GetDefaultLoop(), connection->receiverCtx.timer);
            connection->receiverCtx.timer = NULL;
        }
        // decode msg
        ret = DecodeAppSpawnMsg(message);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        (void)ProcessRecvMsg(connection, message);
        message = NULL;
        currLen += buffLen - reminder;
    } while (reminder > 0);

    if (message) {
        DeleteAppSpawnMsg(message);
    }
    if (ret != 0) {
        LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return;
    }
    if (connection->receiverCtx.incompleteMsg != NULL) { // 有部分数据，启动检测定时器
        ret = StartTimerForCheckMsg(connection);
        APPSPAWN_CHECK(ret == 0, LE_CloseStreamTask(LE_GetDefaultLoop(), taskHandle);
            return, "Failed to create time for connection");
    }
    return;
}

static int InitForkContext(AppSpawningCtx *property)
{
    if (pipe(property->forkCtx.fd) == -1) {
        APPSPAWN_LOGE("create pipe fail, errno: %{public}d", errno);
        return errno;
    }
    int option = fcntl(property->forkCtx.fd[0], F_GETFD);
    if (option > 0) {
        (void)fcntl(property->forkCtx.fd[0], F_SETFD, option | O_NONBLOCK);
    }

    if (property->client.flags & APP_COLD_START) { // for cold run, use shared memory to exchange message
        const uint32_t memSize = (property->message->msgHeader.msgLen % 1024 + 1) * 1024; // 1024
        property->forkCtx.shmId = shmget(IPC_PRIVATE, memSize, 0600); // 0600 mask
        APPSPAWN_CHECK(property->forkCtx.shmId >= 0, return APPSPAWN_SYSTEM_ERROR,
            "Failed to get shm for %{public}s errno %{public}d", GetProcessName(property), errno);
        property->forkCtx.memSize = memSize;
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

static void ProcessSpawnReqMsg(AppSpawnConnection *connection, AppSpawnMsgNode *message)
{
    int ret = CheckAppSpawnMsg(message);
    if (ret != 0) {
        SendResponse(connection, &message->msgHeader, ret, 0);
        return;
    }

    AppSpawningCtx *property = CreateAppSpawningCtx(&g_appSpawnMgr->processMgr);
    if (property == NULL) {
        SendResponse(connection, &message->msgHeader, APPSPAWN_SYSTEM_ERROR, 0);
        return;
    }

    property->state = APP_STATE_SPAWNING;
    property->message = message;
    message->connection = connection;
    // mount el2 dir
    // getWrapBundleNameValue
    AppSpawnHookExecute(HOOK_SPAWN_PREPARE, 0, &g_appSpawnMgr->content, &property->client);
    if (IsDeveloperModeOn(property)) {
        DumpNormalProperty(property);
    }

    if (InitForkContext(property) != 0) {
        SendResponse(connection, &message->msgHeader, APPSPAWN_SYSTEM_ERROR, 0);
        DeleteAppSpawningCtx(property);
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &property->spawnStart);
    ret = AppSpawnProcessMsg(&g_appSpawnMgr->content, &property->client, &property->pid);
    if (ret != 0) {  // wait child process result
        SendResponse(connection, &message->msgHeader, ret, 0);
        DeleteAppSpawningCtx(property);
        return;
    }
}

static void WaitChildDied(pid_t pid)
{
    AppSpawningCtx *property = GetAppSpawningCtxByPid(&g_appSpawnMgr->processMgr, pid);
    if (property != NULL && property->state == APP_STATE_SPAWNING) {
        APPSPAWN_LOGI("Child process %{public}s fail \'child crash \'pid %{public}d appId: %{public}d",
            GetProcessName(property), property->pid, property->client.id);
        SendResponse(property->message->connection, &property->message->msgHeader, APPSPAWN_CHILD_CRASH, 0);
        DeleteAppSpawningCtx(property);
    }
}

static void WaitChildTimeout(const TimerHandle taskHandle, void *context)
{
    AppSpawningCtx *property = (AppSpawningCtx *)context;
    APPSPAWN_LOGI("Child process %{public}s fail \'wait child timeout \'pid %{public}d appId: %{public}d",
        GetProcessName(property), property->pid, property->client.id);
    if (property->pid > 0) {
        kill(property->pid, SIGABRT);
    }
    SendResponse(property->message->connection, &property->message->msgHeader, APPSPAWN_SPAWN_TIMEOUT, 0);
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
    APPSPAWN_CHECK(property->message != NULL, return, "Invalid message in ctx %{public}d", property->client.id);

    if (result != 0) {
        SendResponse(property->message->connection, &property->message->msgHeader, result, property->pid);
        DeleteAppSpawningCtx(property);
        return;
    }
    // success
    AppSpawnedProcess *appInfo = AddSpawnedProcess(&g_appSpawnMgr->processMgr, property->pid, GetBundleName(property));
    if (appInfo) {
        AppSpawnMsgDacInfo *dacInfo = GetAppProperty(property, TLV_DAC_INFO);
        appInfo->uid = dacInfo != NULL ? dacInfo->uid : 0;
        clock_gettime(CLOCK_MONOTONIC, &appInfo->spawnEnd);
        // 添加max信息
    }
    AppChangeHookExecute(HOOK_APP_ADD, &g_appSpawnMgr->content, appInfo);
    SendResponse(property->message->connection, &property->message->msgHeader, result, property->pid);
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
    APPSPAWN_LOGV("NotifyResToParent client id: %{public}u result: 0x%{public}x", client->id, result);
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
        appSpawnContent->server = NULL;
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

    char buffer[3][32] = {0};  // 3 32 buffer for fd
    char *mode = IsNWebSpawnMode((AppSpawnMgr *)content) ? "nweb_cold" : "app_cold";
    int len = sprintf_s(buffer[0], sizeof(buffer[0]), " %d ", property->forkCtx.fd[1]);
    APPSPAWN_CHECK(len > 0, return APPSPAWN_SYSTEM_ERROR, "Invalid to format fd");
    len = sprintf_s(buffer[1], sizeof(buffer[1]), " %u ", property->client.flags);
    APPSPAWN_CHECK(len > 0, return APPSPAWN_SYSTEM_ERROR, "Invalid to format flags");
    len = sprintf_s(buffer[2], sizeof(buffer[2]), " %d ", property->forkCtx.shmId);
    APPSPAWN_CHECK(len > 0, return APPSPAWN_SYSTEM_ERROR, "Invalid to format shmId ");
    int ret = SendAppSpawnMsgToChild(&property->forkCtx, property->message);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    const char *const formatCmds[] = {
        property->forkCtx.coldRunPath, "-mode", mode, "-param", "null", "-fd", buffer[0], buffer[1], buffer[2], NULL
    };

    ret = execv(property->forkCtx.coldRunPath, (char **)formatCmds);
    if (ret) {
        APPSPAWN_LOGE("Failed to execv, errno: %{public}d", errno);
    }
    APPSPAWN_LOGV("ColdStartApp::processName: %{public}s end", GetProcessName(property));
    return 0;
}

static void AppSpawnColdRun(AppSpawnContent *content, int argc, char *const argv[])
{
    APPSPAWN_CHECK(argc > SHM_ID_INDEX, return, "Invalid arg for cold start %{public}d", argc);
    AppSpawnMgr *appSpawnContent = (AppSpawnMgr *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Invalid appspawn content");

    AppSpawningCtx *property = CreateAppSpawningCtx(&g_appSpawnMgr->processMgr);
    APPSPAWN_CHECK(property != NULL, return, "Create app spawning ctx fail");
    property->forkCtx.fd[1] = atoi(argv[FD_VALUE_INDEX]);
    property->forkCtx.shmId = atoi(argv[SHM_ID_INDEX]);
    property->client.flags = atoi(argv[FLAGS_VALUE_INDEX]);
    property->client.flags &= ~APP_COLD_START;

    AppSpawnMsgNode *message = NULL;
    int ret = APPSPAWN_SYSTEM_ERROR;
    do {
        uint8_t *buffer = (uint8_t *)shmat(property->forkCtx.shmId, NULL, 0);
        APPSPAWN_CHECK(buffer != (uint8_t *)(-1), break, "Failed to attach shm errno %{public}d", errno);

        uint32_t msgRecvLen = 0;
        uint32_t remainLen = 0;
        ret = GetAppSpawnMsgFromBuffer(buffer, ((AppSpawnMsg *)buffer)->msgLen, &message, &msgRecvLen, &remainLen);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ret = DecodeAppSpawnMsg(message);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);
        ret = CheckAppSpawnMsg(message);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        property->message = message;
        message = NULL;
        if (IsDeveloperModeOn(property)) {
            DumpNormalProperty(property);
        }
        ret = AppSpawnHookExecute(HOOK_SPAWN_SET_CHILD_PROPERTY, HOOK_STOP_WHEN_ERROR, content, &property->client);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        NotifyResToParent(content, &property->client, 0);

        (void)AppSpawnHookExecute(HOOK_SPAWN_COMPLETED, 0, content, &property->client);
    } while (0);
    if (ret != 0) {
        NotifyResToParent(content, &property->client, ret);
        DeleteAppSpawningCtx(property);
        DeleteAppSpawnMsg(message);
        return;
    }
    ret = -1;
    if (content->runChildProcessor != NULL) {
        ret = content->runChildProcessor(content, &property->client);
    }
    if (ret != 0) { // clear env
        AppSpawnEnvClear(content, &property->client);
    }
    APPSPAWN_LOGI("AppSpawnColdRun exit %{public}d.", getpid());
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
    AppSpawnDestroyContent(content);
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

static void ProcessRecvMsg(AppSpawnConnection *connection, AppSpawnMsgNode *message)
{
    AppSpawnMsg *msg = &message->msgHeader;
    APPSPAWN_LOGI("Recv message header magic 0x%{public}x type %{public}u id %{public}u len %{public}u %{public}s",
        msg->magic, msg->msgType, msg->msgId, msg->msgLen, msg->processName);
    APPSPAWN_CHECK_ONLY_LOG(connection->receiverCtx.nextMsgId == msg->msgId,
        "Invalid msg id %{public}u %{public}u", connection->receiverCtx.nextMsgId, msg->msgId);
    connection->receiverCtx.nextMsgId++;

    switch (msg->msgType) {
        case MSG_GET_RENDER_TERMINATION_STATUS: {  // get status
            pid_t pid = GetPidFromTerminationMsg(message);
            int ret = APPSPAWN_MSG_INVALID;
            if (IsNWebSpawnMode(g_appSpawnMgr)) {
                // get render process termination status, only nwebspawn need this logic.
                ret = GetProcessTerminationStatus(&g_appSpawnMgr->processMgr, pid);
            }
            SendResponse(connection, msg, ret, pid);
            break;
        }
        case MSG_SPAWN_NATIVE_PROCESS:  // spawn msg
        case MSG_APP_SPAWN: {
            ProcessSpawnReqMsg(connection, message);
            message = NULL;
            break;
        }
        case MSG_DUMP:
            DumpApSpawn(g_appSpawnMgr);
            SendResponse(connection, msg, 0, 0);
            break;
        default:
            SendResponse(connection, msg, APPSPAWN_MSG_INVALID, 0);
            break;
    }
    DeleteAppSpawnMsg(message);
}