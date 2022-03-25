/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "appspawn_server.h"
#include "init_socket.h"
#include "parameter.h"
#include "securec.h"

static AppSpawnContentExt *g_appSpawnContent = NULL;

static void OnClose(const TaskHandle taskHandle)
{
    AppSpawnClientExt *client = (AppSpawnClientExt *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(client != NULL, return, "Failed to get client");
    APPSPAWN_LOGI("OnClose client.id %d ", client->client.id);
}

static int SendResponse(AppSpawnClientExt *client, const char *buff, size_t buffSize)
{
    APPSPAWN_CHECK(buffSize >= 0 && buff != 0, return -1, "Invalid content buffSize %d", buffSize);
    uint32_t bufferSize = buffSize;
    BufferHandle handle = LE_CreateBuffer(LE_GetDefaultLoop(), bufferSize);
    char *buffer = (char *)LE_GetBufferInfo(handle, NULL, &bufferSize);
    memcpy_s(buffer, bufferSize, buff, buffSize);
    return LE_Send(LE_GetDefaultLoop(), client->stream, handle, buffSize);
}

static void HandleSpecial(AppSpawnClientExt *appProperty)
{
    // special handle bundle name medialibrary and scanner
    const char *specialBundleNames[] = {
        "com.ohos.medialibrary.MediaLibraryDataA",
        "com.ohos.medialibrary.MediaScannerAbilityA"
    };
    for (size_t i = 0; i < sizeof(specialBundleNames) / sizeof(specialBundleNames[0]); i++) {
        if (strcmp(appProperty->property.processName, specialBundleNames[i]) == 0) {
            if (appProperty->property.gidCount < APP_MAX_GIDS) {
                appProperty->property.gidTable[appProperty->property.gidCount] = GID_USER_DATA_RW;
                appProperty->property.gidCount++;
            } else {
                APPSPAWN_LOGE("gidCount out of bounds !");
            }
            break;
        }
    }
}

static int WaitChild(int fd, int pid, const AppSpawnClientExt *appProperty)
{
    int result = 0;
    int count = 0;
    while (count < RETRY_TIME) { // wait child process resutl
        int readLen = read(fd, &result, sizeof(result));
        if (readLen == sizeof(result)) {
            break;
        }
        usleep(DELAY_US);
        count++;
    }
    if (count >= RETRY_TIME) {
        APPSPAWN_LOGI("Time out for child %d %s ", appProperty->property.processName, pid);
        result = 0;
    }
    APPSPAWN_LOGI("child process %s %s pid %d",
        appProperty->property.processName, (result == 0) ? "success" : "fail", pid);
    return result;
}

static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    APPSPAWN_CHECK(buffer != NULL && buffLen >= sizeof(AppParameter), LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid buffer buffLen %u", buffLen);
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(appProperty != NULL, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Failed to alloc client");
    int ret = memcpy_s(&appProperty->property, sizeof(appProperty->property), buffer, buffLen);
    APPSPAWN_CHECK(ret == 0, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid buffer buffLen %u", buffLen);

    APPSPAWN_CHECK(appProperty->property.gidCount <= APP_MAX_GIDS, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid gidCount %u", appProperty->property.gidCount);
    APPSPAWN_CHECK(strlen(appProperty->property.processName) > 0, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid processName %s", appProperty->property.processName);
    APPSPAWN_LOGI("OnReceiveRequest client.id %d appProperty %d processname %s",
        appProperty->client.id, appProperty->property.uid, appProperty->property.processName);
    // special handle bundle name medialibrary and scanner
    HandleSpecial(appProperty);

    // cold start app
    if (appProperty->property.flags & 0x01) {
        char cold[10] = {0};  // 10 cold
        ret = GetParameter("appspawn.cold.boot", "false", cold, sizeof(cold));
        if (ret == 0 && (strcmp(cold, "true") == 0 || strcmp(cold, "1") == 0 || strcmp(cold, "enable") == 0)) {
            appProperty->client.flags |= APP_COLD_START;
        }
    }

    // create pipe for commication from child
    if (pipe(appProperty->fd) == -1) {
        APPSPAWN_LOGE("create pipe fail, errno = %d", errno);
        LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return;
    }
    fcntl(appProperty->fd[0], F_SETFL, O_NONBLOCK);

    int pid = 0;
    int result = AppSpawnProcessMsg(g_appSpawnContent, &appProperty->client, &pid);
    if (result == 0) { // wait child process resutl
        result = WaitChild(appProperty->fd[0], pid, appProperty);
    }
    close(appProperty->fd[0]);
    close(appProperty->fd[1]);
    // send response
    if (result == 0) {
        SendResponse(appProperty, (char *)&pid, sizeof(pid));
    } else {
        SendResponse(appProperty, (char *)&result, sizeof(result));
    }
    // release
    LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
}

static int OnConnection(const LoopHandle loopHandle, const TaskHandle server)
{
    static uint32_t clientId = 0;
    APPSPAWN_LOGI("OnConnection ");
    APPSPAWN_CHECK(server != NULL, return -1, "Error server");

    TaskHandle stream;
    LE_StreamInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_CONNECT;
    info.baseInfo.close = OnClose;
    info.baseInfo.userDataSize = sizeof(AppSpawnClientExt);
    info.disConntectComplete = NULL;
    info.sendMessageComplete = NULL;
    info.recvMessage = OnReceiveRequest;
    LE_STATUS ret = LE_AcceptStreamClient(LE_GetDefaultLoop(), server, &stream, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc stream");
    AppSpawnClientExt *client = (AppSpawnClientExt *)LE_GetUserData(stream);
    APPSPAWN_CHECK(client != NULL, return -1, "Failed to alloc stream");
    client->stream = stream;
    client->client.id = ++clientId;
    APPSPAWN_LOGI("OnConnection client fd %d Id %d", LE_GetSocketFd(stream), client->client.id);
    return 0;
}

static void SignalHandler(const struct signalfd_siginfo *siginfo)
{
    APPSPAWN_LOGI("SignalHandler signum %d", siginfo->ssi_signo);
    switch (siginfo->ssi_signo) {
        case SIGCHLD: {  // delete pid from app map
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                APPSPAWN_LOGI("SignalHandler pid %d", pid);
            }
            break;
        }
        case SIGTERM: {  // appswapn killed, use kill without parameter
            LE_StopLoop(LE_GetDefaultLoop());
            break;
        }
        default:
            APPSPAWN_LOGI("SigHandler, unsupported signal %d.", siginfo->ssi_signo);
            break;
    }
}

static int NotifyResToParent(struct AppSpawnContent_ *content, AppSpawnClient *client, int result)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    APPSPAWN_LOGI("NotifyResToParent %s result %d", appProperty->property.processName, result);
    write(appProperty->fd[1], &result, sizeof(result));
    // close write
    close(appProperty->fd[1]);
    return 0;
}

static void AppSpawnInit(AppSpawnContent *content)
{
    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Failed to alloc memory for appspawn");

    LE_STATUS ret = LE_CreateSignalTask(LE_GetDefaultLoop(), &appSpawnContent->sigHandler, SignalHandler);
    if (ret == 0) {
        ret = LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGCHLD);
        ret = LE_AddSignal(LE_GetDefaultLoop(), appSpawnContent->sigHandler, SIGTERM);
    }

    APPSPAWN_LOGI("AppSpawnInit");
    if (content->loadExtendLib) {
        content->loadExtendLib(content);
    }
    content->notifyResToParent = NotifyResToParent;
    // set private function
    SetContentFunction(content);
}

static void AppSpawnRun(AppSpawnContent *content)
{
    APPSPAWN_LOGI("AppSpawnRun");
    LE_RunLoop(LE_GetDefaultLoop());

    APPSPAWN_LOGI("AppSpawnRun exit ");
    // release resource
    free(content);
    g_appSpawnContent = NULL;
}

AppSpawnContent *AppSpawnCreateContent(const char *socketName, char *longProcName, int64_t longProcNameLen)
{
    APPSPAWN_CHECK(LE_GetDefaultLoop() != NULL, return NULL, "Invalid default loop");
    APPSPAWN_CHECK(socketName != NULL && longProcName != NULL, return NULL, "Invalid name");
    APPSPAWN_LOGI("AppSpawnCreateContent %s", socketName);

    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)malloc(sizeof(AppSpawnContentExt));
    APPSPAWN_CHECK(appSpawnContent != NULL, return NULL, "Failed to alloc memory for appspawn");
    (void)memset_s(&appSpawnContent->content, sizeof(appSpawnContent->content), 0, sizeof(appSpawnContent->content));
    appSpawnContent->content.longProcName = longProcName;
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    int ret = strcpy_s(appSpawnContent->content.socketName, sizeof(appSpawnContent->content.socketName), socketName);
    APPSPAWN_CHECK(ret >= 0, free(appSpawnContent); return NULL, "Failed to strcpy_s %d", ret);

    char path[128] = {0};  // 128 max path
    ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s%s", SOCKET_DIR, socketName);
    APPSPAWN_CHECK(ret >= 0, free(appSpawnContent); return NULL, "Failed to snprintf_s %d", ret);
    //int socketId = GetControlSocket(socketName);
    //APPSPAWN_LOGI("get socket form env %s socketId %d", socketName, socketId);

    LE_StreamServerInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_SERVER;
    //info.socketId = socketId;
    info.server = path;
    info.baseInfo.close = NULL;
    info.incommingConntect = OnConnection;
    ret = LE_CreateStreamServer(LE_GetDefaultLoop(), &appSpawnContent->servcer, &info);
    APPSPAWN_CHECK(ret == 0, free(appSpawnContent); return NULL, "Failed to create socket for %s", path);
    // create socket
    ret = chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    APPSPAWN_CHECK(ret == 0, free(appSpawnContent); return NULL, "Failed to chmod %s, err %d. ", path, errno);
    appSpawnContent->content.runAppSpawn = AppSpawnRun;
    appSpawnContent->content.initAppSpawn = AppSpawnInit;
    APPSPAWN_LOGI("AppSpawnCreateContent path %s fd %d", path, LE_GetSocketFd(appSpawnContent->servcer));
    g_appSpawnContent = appSpawnContent;
    return &g_appSpawnContent->content;
}
