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
#include "securec.h"

#include "app_spawn_stub.h"

namespace OHOS {

AppSpawnTestServer::~AppSpawnTestServer()
{
    if (localServer_) {
        delete localServer_;
        localServer_ = nullptr;
    }
}

void AppSpawnTestServer::ChildLoopRun(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGV("ChildLoopRun ...");
    while (1) {
        pause();
    }
}

void *AppSpawnTestServer::ServiceThread(void *arg)
{
    AppSpawnTestServer *server = reinterpret_cast<AppSpawnTestServer *>(arg);
    APPSPAWN_LOGV("serviceCmd_ %{public}s", server->serviceCmd_.c_str());
    CmdArgs *args = ToCmdList(server->serviceCmd_.c_str());
    APPSPAWN_CHECK(args != nullptr, return nullptr, "Failed to alloc args");

    // 测试server时，使用appspawn的server
    pid_t pid = getpid();
    if (server->testServer_) {
        server->content_ = StartSpawnService(APP_LEN_PROC_NAME, args->argc, args->argv);
        if (server->content_ == nullptr) {
            free(args);
            return nullptr;
        }
        if (pid == getpid()) { // 非fork 的 nwebspawn
            APPSPAWN_LOGV("Service start timer %{public}s ", server->serviceCmd_.c_str());
            LE_CreateTimer(LE_GetDefaultLoop(), &server->timer_, WaitChildTimeout, server);
            LE_StartTimer(LE_GetDefaultLoop(), server->timer_, 100, 100000); // 100ms 100000

            RegChildLooper(server->content_, ChildLoopRun);
            AppSpawnContentExt *content = reinterpret_cast<AppSpawnContentExt *>(server->content_);
            APPSPAWN_CHECK_ONLY_EXPER(content != NULL, return nullptr);
            AppSpawnAppInfo *info = GetAppInfoByName(&content->appMgr, NWEBSPAWN_SERVER_NAME);
            if (info != NULL) {
                APPSPAWN_LOGV("Save nwebspawn pid: %{public}d %{public}d", info->pid, server->serverId_);
                server->appPid_.store(info->pid);
            }
        }
        server->content_->runAppSpawn(server->content_, args->argc, args->argv);
    } else {
        LE_CreateTimer(LE_GetDefaultLoop(), &server->timer_, WaitChildTimeout, server);
        LE_StartTimer(LE_GetDefaultLoop(), server->timer_, 100, 100000); // 100ms 100000

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
        int ret = pthread_create(&threadId_, nullptr, ServiceThread, (void *)this);
        if (ret != 0) {
            return;
        }
    }
}

void AppSpawnTestServer::Stop()
{
    if (threadId_ != 0) {
        stop_ = true;
        pthread_join(threadId_, nullptr);
        threadId_ = 0;
        APPSPAWN_LOGV("Stop");
    }
}

void AppSpawnTestServer::KillNWebSpawnServer()
{
    APPSPAWN_LOGV("Kill nwebspawn pid: %{public}d %{public}d", appPid_.load(), serverId_);
    if (appPid_ > 0) {
        kill(appPid_, SIGKILL);
    }
}

void AppSpawnTestServer::StopSpawnService(void)
{
    if (timer_) {
        LE_StopTimer(LE_GetDefaultLoop(), timer_);
        timer_ = nullptr;
    }

    if (testServer_) {
        struct signalfd_siginfo siginfo = {};
        siginfo.ssi_signo = SIGTERM;
        siginfo.ssi_uid = 0;
        SignalHandler(&siginfo);
        content_ = nullptr;
    } else {
        localServer_->Stop();
    }
}

void AppSpawnTestServer::WaitChildTimeout(const TimerHandle taskHandle, void *context)
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

    MakeDirRec(path, 0711, 0); // 0711 default mask
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
    CmdArgs *args = (CmdArgs *)malloc(length);
    APPSPAWN_CHECK(args != nullptr, return nullptr, "Failed to alloc args");
    (void)memset_s(args, length, 0, length);
    char *start = ((char *)args) + sizeof(CmdArgs) + maxArgc * sizeof(char *);
    char *end = ((char *)args) + length;
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
    args->argv[index] = end - 2;
    args->argv[index][0] = '#';
    args->argv[index][1] = '\0';
    args->argc = index + 1;
    return args;
}

AppSpawnReqHandle AppSpawnTestHelper::CreateMsg(AppSpawnClientHandle handle, uint32_t msgType, int base)
{
    AppSpawnReqHandle reqHandle = 0;
    int ret = AppSpawnReqCreate(handle, msgType, processName_, &reqHandle);
    APPSPAWN_CHECK(ret == 0, return INVALID_REQ_HANDLE, "Failed to create req %{public}s", processName_);
    do {
        AppBundleInfo info;
        strcpy_s(info.bundleName, sizeof(info.bundleName), processName_);
        info.bundleIndex = 100;
        ret = AppSpawnReqSetBundleInfo(handle, reqHandle, &info);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add bundle info req %{public}s", processName_);

        AppDacInfo dacInfo = {};
        dacInfo.uid = defaultTestUid_;
        dacInfo.gid = defaultTestGid_;
        dacInfo.gidCount = 2;
        dacInfo.gidTable[0] = defaultTestGidGroup_;
        dacInfo.gidTable[1] = defaultTestGidGroup_ + 1;
        (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), "test-app-name");
        ret = AppSpawnReqSetAppDacInfo(handle, reqHandle, &dacInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add dac %{public}s", processName_);

        AppSpawnMsgAccessToken token = {1234, 12345678}; // 1234, 12345678
        ret = AppSpawnReqSetAppAccessToken(handle, reqHandle, &token);
        APPSPAWN_CHECK(ret == 0, break, "Failed to add access token %{public}s", processName_);

        if (base) {
            return reqHandle;
        }
        const char *testData = "ssssssssssssss sssssssss ssssssss";
        ret = AppSpawnReqAddExtInfo(handle, reqHandle, "tlv-name-1",
            reinterpret_cast<uint8_t *>(const_cast<char *>(testData)), strlen(testData));
        APPSPAWN_CHECK(ret == 0, break, "Failed to ext tlv %{public}s", processName_);

        ret = AppSpawnReqSetPermission(handle, reqHandle, permissions_.data(), permissions_.size());
        APPSPAWN_CHECK(ret == 0, break, "Failed to permission %{public}s", processName_);

        AppInternetPermissionInfo internetInfo = { 1, 0 };
        ret = AppSpawnReqSetAppInternetPermissionInfo(handle, reqHandle, &internetInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to internet info %{public}s", processName_);

        AppOwnerId ownerId = { "ohos.permission.FILE_ACCESS_MANAGER"};
        ret = AppSpawnReqSetAppOwnerId(handle, reqHandle, &ownerId);
        APPSPAWN_CHECK(ret == 0, break, "Failed to ownerid %{public}s", processName_);
        AppRenderCmd renderCmd = { "/system/bin/sh ls -l " };
        ret = AppSpawnReqSetAppRenderCmd(handle, reqHandle, &renderCmd);
        APPSPAWN_CHECK(ret == 0, break, "Failed to render cmd %{public}s", processName_);
        AppDomainInfo domainInfo = { 1, "system_core" };
        ret = AppSpawnReqSetAppDomainInfo(handle, reqHandle, &domainInfo);
        APPSPAWN_CHECK(ret == 0, break, "Failed to domain info %{public}s", processName_);
        return reqHandle;
    } while (0);
    AppSpawnReqDestroy(handle, reqHandle);
    return INVALID_REQ_HANDLE;
}

AppProperty *AppSpawnTestHelper::GetAppProperty(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle)
{
    AppSpawnReqNode *reqNode = GetReqNode(handle, reqHandle, MSG_STATE_COLLECTION);
    APPSPAWN_CHECK(reqNode != nullptr, return nullptr, "Invalid reqNode");
    ListNode *node = reqNode->msgBlocks.next;
    APPSPAWN_CHECK(node != &reqNode->msgBlocks, return nullptr, "No block in reqNode");

    AppSpawnMsgBlock *block = ListEntry(node, AppSpawnMsgBlock, node);
    APPSPAWN_CHECK(block->currentIndex >= sizeof(AppSpawnMsg), return nullptr, "Invalid first block in reqNode");
    AppSpawnMsg *msg = reinterpret_cast<AppSpawnMsg *>(block->buffer);
    uint32_t bufferSize = msg->msgLen;
    uint8_t *buffer = (uint8_t *)malloc(msg->msgLen);
    APPSPAWN_CHECK(buffer != nullptr, return nullptr, "Failed to alloc for msg");

    uint32_t currIndex = 0;
    do {
        block = ListEntry(node, AppSpawnMsgBlock, node);
        if (currIndex + block->currentIndex > bufferSize) {
            free(buffer);
            return nullptr;
        }
        if (memcpy_s(buffer + currIndex, bufferSize - currIndex, block->buffer, block->currentIndex) != EOK) {
            free(buffer);
            return nullptr;
        }
        currIndex += block->currentIndex;
        node = node->next;
    } while (node != &reqNode->msgBlocks);

    AppSpawnAppMgr appMgr;
    int ret = AppSpawnAppMgrInit(&appMgr);
    APPSPAWN_CHECK(ret == 0, return nullptr, "Failed to init mgr req");

    msg = reinterpret_cast<AppSpawnMsg *>(buffer);
    AppProperty *property = AppMgrCreateAppProperty(&appMgr, msg->tlvCount);
    APPSPAWN_CHECK_ONLY_EXPER(property != nullptr, free(buffer); return nullptr);
    OH_ListRemove(&property->node);
    OH_ListInit(&property->node);

    property->msg = msg;
    ret = DecodeRecvMsg(property, buffer, bufferSize);
    APPSPAWN_CHECK(ret == 0, AppMgrDeleteAppProperty(property); return nullptr, "Decode msg fail");
    APPSPAWN_LOGV("GetAppProperty tlvCount: %{public}d", property->tlvCount);
    return property;
}

void AppSpawnTestHelper::SetDefaultTestData()
{
    processName_ = strdup("com.ohos.dlpmanager");
    defaultTestUid_ = 20010029;
    defaultTestGid_ = 20010029;
    defaultTestGidGroup_ = 20010029;
    defaultTestBundleIndex_ = 100;
}

int AppSpawnTestHelper::CreateSocket(void)
{
    const uint32_t maxCount = 10;
    uint32_t count = 0;
    int socketId = -1;
    while ((socketId < 0) && (count < maxCount)) {
        socketId = CreateClientSocket(0, 1);
        if (socketId > 0) {
            return socketId;
        }
        usleep(20000);
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
    (void)strcpy_s(msg->processName, sizeof(msg->processName), processName_);
    // add tlv
    uint32_t currLen = sizeof(AppSpawnMsg);
    for (auto addTlvFunc : addTlvFuncs) {
        uint32_t realLen = 0;
        uint32_t tlvCount = 0;
        int ret = addTlvFunc(buffer.data() + currLen, buffer.size() - currLen, realLen, tlvCount);
        APPSPAWN_CHECK(ret == 0 && (currLen + realLen) < buffer.size(),
            return -1, "Failed add tlv to msg %{public}s", processName_);
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
    (void)memcpy_s(buffer, bufferLen, &tlv, sizeof(tlv));
    (void)memcpy_s(buffer + sizeof(tlv), bufferLen - sizeof(tlv), data, tlv.tlvLen - sizeof(tlv));
    return 0;
}

int AppSpawnTestHelper::AddBaseTlv(uint8_t *buffer, uint32_t bufferLen, uint32_t &realLen, uint32_t &tlvCount)
{
    // add app flage
    uint32_t currLen = 0;
    uint32_t flags[2] = { 1, 0 };
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

    AppSpawnMsgAccessToken token = {1234, 12345678}; // 1234, 12345678
    tlv.tlvType = TLV_ACCESS_TOKEN_INFO;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(token);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)&token);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    // add bundle info
    AppBundleInfo info = {};
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "test-bundleName");
    info.bundleIndex = 100;
    tlv.tlvType = TLV_BUNDLE_INFO;
    tlv.tlvLen = sizeof(AppSpawnTlv) + sizeof(AppBundleInfo);
    ret = AddOneTlv(buffer + currLen, bufferLen - currLen, tlv, (uint8_t *)&info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed add tlv %{public}u", tlv.tlvType);
    currLen += tlv.tlvLen;
    tlvCount++;

    // add dac
    AppDacInfo dacInfo = {};
    dacInfo.uid = 20010029; // 20010029
    dacInfo.gid = 20010029; // 20010029
    dacInfo.gidCount = 2; // 2 count
    dacInfo.gidTable[0] = 20010029; // 20010029
    dacInfo.gidTable[1] = 20010029 + 1; // 20010029
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
