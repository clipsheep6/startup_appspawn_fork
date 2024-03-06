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

#include "app_spawn_test_helper.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_client.h"
#include "appspawn_msg.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "loop_event.h"
#include "parameters.h"
#include "securec.h"

#include "app_spawn_stub.h"

namespace OHOS {
typedef struct {
    int32_t bundleIndex;
    char bundleName[APP_LEN_BUNDLE_NAME];  // process name
} AppBundleInfo;

uint32_t AppSpawnTestServer::serverId = 0;
AppSpawnTestServer::~AppSpawnTestServer()
{
    if (localServer_) {
        delete localServer_;
        localServer_ = nullptr;
    }
}

int AppSpawnTestServer::ChildLoopRun(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGV("ChildLoopRun ...");
    while (1) {
        pause();
    }
    return 0;
}

void *AppSpawnTestServer::ServiceThread(void *arg)
{
    pid_t pid = getpid();
    AppSpawnTestServer *server = reinterpret_cast<AppSpawnTestServer *>(arg);
    APPSPAWN_LOGV("serviceCmd_ %{public}s", server->serviceCmd_.c_str());
    CmdArgs *args = ToCmdList(server->serviceCmd_.c_str());
    APPSPAWN_CHECK(args != nullptr, return nullptr, "Failed to alloc args");

    // 测试server时，使用appspawn的server
    if (server->testServer_) {
        server->content_ = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        if (server->content_ == nullptr) {
            free(args);
            return nullptr;
        }
        if (pid == getpid()) {  // 主进程进行处理
            APPSPAWN_LOGV("Service start timer %{public}s ", server->serviceCmd_.c_str());
            LE_AddIdle(LE_GetDefaultLoop(), &server->idle_, ProcessIdle, server, 10000000);  // 10000000 repeat

            RegChildLooper(server->content_, ChildLoopRun);
            AppSpawnMgr *content = reinterpret_cast<AppSpawnMgr *>(server->content_);
            APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return nullptr);
            AppSpawnedProcess *info = GetSpawnedProcessByName(&content->processMgr, NWEBSPAWN_SERVER_NAME);
            if (info != NULL) {
                APPSPAWN_LOGV("Save nwebspawn pid: %{public}d %{public}d", info->pid, server->serverId_);
                server->appPid_.store(info->pid);
            }
        }
        server->content_->runAppSpawn(server->content_, args->argc, args->argv);
        if (pid != getpid()) {  // 子进程退出
            exit(0);
        } else {
            server->content_ = nullptr;
        }
    } else {
        LE_AddIdle(LE_GetDefaultLoop(), &server->idle_, ProcessIdle, server, 10000000);  // 10000000 repeat
        server->localServer_ = new LocalTestServer();
        server->localServer_->Run(APPSPAWN_SOCKET_NAME, server->recvMsgProcess_);
    }
    APPSPAWN_LOGV("Service thread finish %{public}s ", server->serviceCmd_.c_str());
    free(args);
    return nullptr;
}

void AppSpawnTestServer::Start(void)
{
    Start(nullptr);
}

void AppSpawnTestServer::Start(RecvMsgProcess process, uint32_t time)
{
    protectTime_ = time;
    if (threadId_ == 0) {
        clock_gettime(CLOCK_MONOTONIC, &startTime_);
        recvMsgProcess_ = process;
        int ret = pthread_create(&threadId_, nullptr, ServiceThread, static_cast<void *>(this));
        if (ret != 0) {
            return;
        }
    }
}

void AppSpawnTestServer::Stop()
{
    APPSPAWN_LOGV("AppSpawnTestServer::Stop");
    if (threadId_ != 0) {
        stop_ = true;
        pthread_join(threadId_, nullptr);
        threadId_ = 0;
        APPSPAWN_LOGV("Stop");
    }
}

void AppSpawnTestServer::KillNWebSpawnServer()
{
    APPSPAWN_LOGV("Kill nwebspawn %{public}d", serverId_);
    if (appPid_ > 0) {
        kill(appPid_, SIGKILL);
    }
}

void AppSpawnTestServer::StopSpawnService(void)
{
    APPSPAWN_LOGV("StopSpawnService ");
    if (idle_) {
        LE_DelIdle(idle_);
        idle_ = nullptr;
    }
    if (testServer_) {
        struct signalfd_siginfo siginfo = {};
        siginfo.ssi_signo = SIGTERM;
        siginfo.ssi_uid = 0;
        ProcessSignal(&siginfo);
    } else {
        localServer_->Stop();
    }
}

void AppSpawnTestServer::ProcessIdle(const IdleHandle taskHandle, void *context)
{
    AppSpawnTestServer *server = reinterpret_cast<AppSpawnTestServer *>(const_cast<void *>(context));
    if (server->stop_) {
        server->StopSpawnService();
        return;
    }

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t diff = DiffTime(&server->startTime_, &end);
    if (diff >= (server->protectTime_ * 1000)) {  // 1000 ms -> us
        APPSPAWN_LOGV("AppSpawnTestServer::ProcessIdle: %{public}u %{public}llu", server->protectTime_, diff);
        server->StopSpawnService();
        return;
    }
}

int LocalTestServer::OnConnection(const LoopHandle loopHandle, const TaskHandle server)
{
    static uint32_t connectionId = 0;
    TaskHandle stream;
    LE_StreamInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_CONNECT;
    info.baseInfo.close = OnClose;
    info.baseInfo.userDataSize = sizeof(TestConnection);
    info.disConnectComplete = nullptr;
    info.sendMessageComplete = SendMessageComplete;
    info.recvMessage = OnReceiveRequest;

    ServerInfo *serverInfo = (ServerInfo *)LE_GetUserData(server);
    APPSPAWN_CHECK(serverInfo != nullptr, return -1, "Failed to alloc stream");

    LE_STATUS ret = LE_AcceptStreamClient(loopHandle, server, &stream, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc stream");
    TestConnection *connection = (TestConnection *)LE_GetUserData(stream);
    APPSPAWN_CHECK(connection != nullptr, return -1, "Failed to alloc stream");
    connection->connectionId = ++connectionId;
    connection->stream = stream;
    connection->msgRecvLen = 0;
    (void)memset_s(&connection->msg, sizeof(connection->msg), 0, sizeof(connection->msg));
    connection->buffer = nullptr;
    connection->recvMsgProcess = serverInfo->recvMsgProcess;
    APPSPAWN_LOGI("OnConnection connection.id %{public}d fd %{public}d ",
        connection->connectionId, LE_GetSocketFd(stream));
    return 0;
}

void LocalTestServer::SendMessageComplete(const TaskHandle taskHandle, BufferHandle handle)
{
    return;
}

void LocalTestServer::OnClose(const TaskHandle taskHandle)
{
    TestConnection *connection = (TestConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != nullptr, return, "Invalid connection");
    APPSPAWN_LOGI("OnClose connection.id %{public}d socket %{public}d",
        connection->connectionId, LE_GetSocketFd(taskHandle));
}

void LocalTestServer::OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    TestConnection *connection = (TestConnection *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(connection != nullptr, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Failed to get client form socket");

    if (connection->recvMsgProcess) {
        connection->recvMsgProcess(connection, buffer, buffLen);
    }
}

int LocalTestServer::Run(const char *socketName, RecvMsgProcess recvMsg)
{
    char path[128] = {0};  // 128 max path
    int ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s%s", APPSPAWN_SOCKET_DIR, socketName);
    APPSPAWN_CHECK(ret >= 0, return -1, "Failed to snprintf_s %{public}d", ret);
    LE_StreamServerInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_SERVER;
    info.baseInfo.userDataSize = sizeof(ServerInfo);
    info.socketId = -1;
    info.server = path;
    info.baseInfo.close = nullptr;
    info.incommingConnect = OnConnection;

    MakeDirRec(path, 0711, 0);  // 0711 default mask
    ret = LE_CreateStreamServer(LE_GetDefaultLoop(), &serverHandle_, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create socket for %{public}s errno: %{public}d", path, errno);
    APPSPAWN_LOGI("LocalTestServer path %{public}s fd %{public}d", path, LE_GetSocketFd(serverHandle_));

    ServerInfo *serverInfo = (ServerInfo *)LE_GetUserData(serverHandle_);
    APPSPAWN_CHECK(serverInfo != nullptr, return -1, "Failed to alloc stream");
    serverInfo->local = this;
    serverInfo->recvMsgProcess = recvMsg;
    LE_RunLoop(LE_GetDefaultLoop());
    LE_CloseStreamTask(LE_GetDefaultLoop(), serverHandle_);
    LE_StopLoop(LE_GetDefaultLoop());
    LE_CloseLoop(LE_GetDefaultLoop());
    APPSPAWN_LOGI("LocalTestServer exit");
    return 0;
}

void LocalTestServer::Stop()
{
    APPSPAWN_LOGI("Stop LocalTestServer ");
    LE_StopLoop(LE_GetDefaultLoop());
}

int TestConnection::SendResponse(const AppSpawnMsg *msg, int result, pid_t pid)
{
    APPSPAWN_LOGV("SendResponse result: %{public}d pid: %{public}d", result, pid);
    uint32_t bufferSize = sizeof(AppSpawnResponseMsg);
    BufferHandle handle = LE_CreateBuffer(LE_GetDefaultLoop(), bufferSize);
    AppSpawnResponseMsg *buffer = (AppSpawnResponseMsg *)LE_GetBufferInfo(handle, nullptr, &bufferSize);
    int ret = memcpy_s(buffer, bufferSize, msg, sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to memcpy_s bufferSize");
    buffer->result.result = result;
    buffer->result.pid = pid;
    return LE_Send(LE_GetDefaultLoop(), stream, handle, bufferSize);
}

uint32_t AppSpawnTestHelper::GenRandom(void)
{
    uint32_t random = 0;
    int fd = open("/dev/random", O_RDONLY);
    if (fd >= 0) {
        read(fd, &random, sizeof(random));
        close(fd);
    }
    return random;
}

CmdArgs *AppSpawnTestHelper::ToCmdList(const char *cmd)
{
    const uint32_t maxArgc = 10;
    const uint32_t length = sizeof(CmdArgs) + maxArgc * sizeof(char *) + strlen(cmd) + APP_LEN_PROC_NAME + 1 + 2;
    char *buffer = static_cast<char *>(malloc(length));
    CmdArgs *args = reinterpret_cast<CmdArgs *>(buffer);
    APPSPAWN_CHECK(buffer != nullptr, return nullptr, "Failed to alloc args");
    (void)memset_s(args, length, 0, length);
    char *start = buffer + sizeof(CmdArgs) + maxArgc * sizeof(char *);
    char *end = buffer + length;
    uint32_t index = 0;
    char *curr = const_cast<char *>(cmd);
    while (isspace(*curr)) {
        curr++;
    }

    while (index < (maxArgc - 1) && *curr != '\0') {
        if (args->argv[index] == nullptr) {
            args->argv[index] = start;
        }
        *start = *curr;
        if (isspace(*curr)) {
            *start = '\0';
            // 为SetProcessName 预留空间
            start = (index == 0) ? start + APP_LEN_PROC_NAME : start + 1;
            while (isspace(*curr) && *curr != '\0') {
                curr++;
            }
            if (*curr != '\0') {
                index++;
            }
        } else {
            start++;
            curr++;
        }
    }

    index++;
    args->argv[index] = end - 2;  // 2 last
    args->argv[index][0] = '#';
    args->argv[index][1] = '\0';
    args->argc = index + 1;
    return args;
}

AppSpawnReqMsgHandle AppSpawnTestHelper::CreateMsg(AppSpawnClientHandle handle, uint32_t msgType, int base)
{
    AppSpawnReqMsgHandle reqHandle = 0;
    int ret = AppSpawnReqMsgCreate(msgType, processName_.c_str(), &reqHandle);
    APPSPAWN_CHECK(ret == 0, return INVALID_REQ_HANDLE, "Failed to create req %{public}s", processName_.c_str());
    APPSPAWN_CHECK_ONLY_EXPER(msgType == MSG_APP_SPAWN || msgType == MSG_SPAWN_NATIVE_PROCESS, return reqHandle);
    do {
        ret = AppSpawnReqMsgSetBundleInfo(reqHandle, 100, processName_.c_str());  // 100 test index
        APPSPAWN_CHECK(ret == 0, break, "Failed to add bundle info req %{public}s", processName_.c_str());

        AppDacInfo dacInfo = {};
        dacInfo.uid = defaultTestUid_;
        dacInfo.gid = defaultTestGid_;
        dacInfo.gidCount = 2;  // 2 count
        dacInfo.gidTable[0] = defaultTestGidGroup_;
        dacInfo.gidTable[1] = defaultTestGidGroup_ + 1;
        (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
        ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add dac %{public}s", processName_.c_str());

        ret = AppSpawnReqMsgSetAppAccessToken(reqHandle, 12345678);  // 12345678
        APPSPAWN_CHECK(ret == 0, break, "Failed to add access token %{public}s", processName_.c_str());

        if (base) {
            return reqHandle;
        }
        const char *testData = "ssssssssssssss sssssssss ssssssss";
        ret = AppSpawnReqMsgAddExtInfo(reqHandle, "tlv-name-1",
            reinterpret_cast<uint8_t *>(const_cast<char *>(testData)), strlen(testData));
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", processName_.c_str());
        size_t count = permissions_.size();
        for (size_t i = 0; i < count; i++) {
            ret = AppSpawnReqMsgAddPermission(reqHandle, permissions_[i]);
            APPSPAWN_CHECK(ret == 0, break, "Failed to permission %{public}s", permissions_[i]);
        }

        ret = AppSpawnReqMsgSetAppInternetPermissionInfo(reqHandle, 1, 0);
        APPSPAWN_CHECK(ret == 0, break, "Failed to internet info %{public}s", processName_.c_str());

        ret = AppSpawnReqMsgSetAppOwnerId(reqHandle, "ohos.permission.FILE_ACCESS_MANAGER");
        APPSPAWN_CHECK(ret == 0, break, "Failed to ownerid %{public}s", processName_.c_str());
        const char *renderCmd = "/system/bin/sh ls -l ";
        ret = AppSpawnReqMsgAddExtInfo(reqHandle, MSG_EXT_NAME_RENDER_CMD,
            reinterpret_cast<const uint8_t *>(renderCmd), strlen(renderCmd));
        APPSPAWN_CHECK(ret == 0, break, "Failed to render cmd %{public}s", processName_.c_str());
        ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, 1, "system_core");
        APPSPAWN_CHECK(ret == 0, break, "Failed to domain info %{public}s", processName_.c_str());
        return reqHandle;
    } while (0);
    AppSpawnReqMsgFree(reqHandle);
    return INVALID_REQ_HANDLE;
}

AppSpawnMsgNode *AppSpawnTestHelper::CreateAppSpawnMsg(AppSpawnMsg *msg)
{
    AppSpawnMsgNode *msgNode = static_cast<AppSpawnMsgNode *>(calloc(1, sizeof(AppSpawnMsgNode)));
    APPSPAWN_CHECK(msgNode != NULL, return NULL, "Failed to create receiver");
    int ret = memcpy_s(&msgNode->msgHeader, sizeof(msgNode->msgHeader), msg, sizeof(msgNode->msgHeader));
    APPSPAWN_CHECK(ret == 0, free(msgNode);
        return nullptr, "Failed to memcpy msg");
    msgNode->buffer = static_cast<uint8_t *>(malloc(msg->msgLen));
    APPSPAWN_CHECK(msgNode->buffer != NULL, free(msgNode);
        return nullptr, "Failed to memcpy msg");
    uint32_t totalCount = msg->tlvCount + TLV_MAX;
    msgNode->tlvOffset = static_cast<uint32_t *>(malloc(totalCount * sizeof(uint32_t)));
    APPSPAWN_CHECK(msgNode->tlvOffset != NULL, free(msgNode);
        return nullptr, "Failed to alloc memory for recv message");
    for (uint32_t i = 0; i < totalCount; i++) {
        msgNode->tlvOffset[i] = INVALID_OFFSET;
    }
    return msgNode;
}

AppSpawningCtx *AppSpawnTestHelper::GetAppProperty(AppSpawnClientHandle handle, AppSpawnReqMsgHandle reqHandle)
{
    AppSpawnReqMsgNode *reqNode = static_cast<AppSpawnReqMsgNode *>(reqHandle);
    APPSPAWN_CHECK(reqNode != nullptr && reqNode->msg != nullptr, AppSpawnReqMsgFree(reqHandle);
        return nullptr, "Invalid reqNode");

    AppSpawnMsgNode *msgNode = CreateAppSpawnMsg(reqNode->msg);
    APPSPAWN_CHECK(msgNode != nullptr, return nullptr, "Failed to alloc for msg");

    uint32_t bufferSize = reqNode->msg->msgLen;
    uint32_t currIndex = 0;
    uint32_t bufferStart = sizeof(AppSpawnMsg);
    ListNode *node = reqNode->msgBlocks.next;
    while (node != &reqNode->msgBlocks) {
        AppSpawnMsgBlock *block = ListEntry(node, AppSpawnMsgBlock, node);
        int ret = memcpy_s(msgNode->buffer + currIndex, bufferSize - currIndex,
            block->buffer + bufferStart, block->currentIndex - bufferStart);
        if (ret != 0) {
            AppSpawnReqMsgFree(reqHandle);
            DeleteAppSpawnMsg(msgNode);
            return nullptr;
        }
        currIndex += block->currentIndex - bufferStart;
        bufferStart = 0;
        node = node->next;
    }
    APPSPAWN_LOGV("GetAppProperty header magic 0x%{public}x type %{public}u id %{public}u len %{public}u %{public}s",
        msgNode->msgHeader.magic, msgNode->msgHeader.msgType,
        msgNode->msgHeader.msgId, msgNode->msgHeader.msgLen, msgNode->msgHeader.processName);

    // delete reqHandle
    AppSpawnReqMsgFree(reqHandle);
    int ret = DecodeAppSpawnMsg(msgNode);
    APPSPAWN_CHECK(ret == 0, DeleteAppSpawnMsg(msgNode);
        return nullptr, "Decode msg fail");
    AppSpawningCtx *property = CreateAppSpawningCtx(nullptr);
    APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, DeleteAppSpawnMsg(msgNode);
        return nullptr);
    property->message = msgNode;
    return property;
}

void AppSpawnTestHelper::SetDefaultTestData()
{
    processName_ = std::string("com.example.myapplication");
    defaultTestUid_ = 20010029;       // 20010029 test
    defaultTestGid_ = 20010029;       // 20010029 test
    defaultTestGidGroup_ = 20010029;  // 20010029 test
    defaultTestBundleIndex_ = 100;    // 100 test
    SetDumpFlags(OHOS::system::GetBoolParameter("appspawn.open.console", true));
}

int AppSpawnTestHelper::CreateSocket(void)
{
    const uint32_t maxCount = 10;
    uint32_t count = 0;
    int socketId = -1;
    while ((socketId < 0) && (count < maxCount)) {
        usleep(20000);                        // 20000 20ms
        socketId = CreateClientSocket(0, 2);  // 2s
        if (socketId > 0) {
            return socketId;
        }
        count++;
    }
    return socketId;
}

int AppSpawnTestHelper::CreateSendMsg(std::vector<uint8_t> &buffer, uint32_t msgType, uint32_t &msgLen,
    const std::vector<AddTlvFunction> &addTlvFuncs)
{
    if (buffer.size() < sizeof(AppSpawnMsg)) {
        return -1;
    }
    AppSpawnMsg *msg = reinterpret_cast<AppSpawnMsg *>(buffer.data());
    msg->magic = APPSPAWN_MSG_MAGIC;
    msg->msgType = msgType;
    msg->msgLen = sizeof(AppSpawnMsg);
    msg->msgId = 1;
    msg->tlvCount = 0;
    (void)strcpy_s(msg->processName, sizeof(msg->processName), processName_.c_str());
    // add tlv
    uint32_t currLen = sizeof(AppSpawnMsg);
    for (auto addTlvFunc : addTlvFuncs) {
        uint32_t realLen = 0;
        uint32_t tlvCount = 0;
        int ret = addTlvFunc(buffer.data() + currLen, buffer.size() - currLen, realLen, tlvCount);
        APPSPAWN_CHECK(ret == 0 && (currLen + realLen) < buffer.size(),
            return -1, "Failed add tlv to msg %{public}s", processName_.c_str());
        msg->msgLen += realLen;
        currLen += realLen;
        msg->tlvCount += tlvCount;
    }
    msgLen = msg->msgLen;
    APPSPAWN_LOGV("CreateSendMsg msgLen %{public}d", msgLen);
    return 0;
}

static int inline AddOneTlv(uint8_t *buffer, uint32_t bufferLen, const AppSpawnTlv &tlv, const uint8_t *data)
{
    if (tlv.tlvLen > bufferLen) {
        return -1;
    }
    int ret = memcpy_s(buffer, bufferLen, &tlv, sizeof(tlv));
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to memcpy_s bufferSize");
    ret = memcpy_s(buffer + sizeof(tlv), bufferLen - sizeof(tlv), data, tlv.tlvLen - sizeof(tlv));
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to memcpy_s bufferSize");
    return 0;
}

int AppSpawnTestHelper::AddBaseTlv(uint8_t *buffer, uint32_t bufferLen, uint32_t &realLen, uint32_t &tlvCount)
{
    // add app flage
    uint32_t currLen = 0;
    uint32_t flags[2] = {1, 0};
    AppSpawnTlv tlv = {};
    tlv.tlvType = TLV_MSG_FLAGS;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(flags);
    int ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)flags);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    tlv.tlvType = TLV_PERMISSION;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(flags);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)flags);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    AppSpawnMsgAccessToken token = {12345678};  // 12345678
    tlv.tlvType = TLV_ACCESS_TOKEN_INFO;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(token);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)&token);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    // add bundle info
    AppBundleInfo info = {};
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "test-bundleName");
    info.bundleIndex = 100;  // 100 test index
    tlv.tlvType = TLV_BUNDLE_INFO;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(AppBundleInfo);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)&info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    // add dac
    AppDacInfo dacInfo = {};
    dacInfo.uid = 20010029;              // 20010029
    dacInfo.gid = 20010029;              // 20010029
    dacInfo.gidCount = 2;                // 2 count
    dacInfo.gidTable[0] = 20010029;      // 20010029
    dacInfo.gidTable[1] = 20010029 + 1;  // 20010029
    tlv.tlvType = TLV_DAC_INFO;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(dacInfo);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)&dacInfo);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;
    realLen = currLen;
    return 0;
}
}  // namespace OHOS
