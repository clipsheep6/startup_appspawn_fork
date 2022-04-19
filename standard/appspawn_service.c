/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "init_hashmap.h"
#include "init_socket.h"
#include "parameter.h"
#include "securec.h"

static AppSpawnContentExt *g_appSpawnContent = NULL;

static const int TV_SEC = 60;

static int AppInfoHashNodeCompare(const HashNode *node1, const HashNode *node2)
{
    AppInfo *testNode1 = HASHMAP_ENTRY(node1, AppInfo, node);
    AppInfo *testNode2 = HASHMAP_ENTRY(node2, AppInfo, node);
    return testNode1->pid - testNode2->pid;
}

static int TestHashKeyCompare(const HashNode *node1, const void *key)
{
    AppInfo *testNode1 = HASHMAP_ENTRY(node1, AppInfo, node);
    return testNode1->pid - (pid_t)key;
}

static int AppInfoHashNodeFunction(const HashNode *node)
{
    AppInfo *testNode = HASHMAP_ENTRY(node, AppInfo, node);
    if (testNode == NULL) {
        return -1;
    }
    return testNode->pid % APP_HASH_BUTT;
}

static int AppInfoHashKeyFunction(const void *key)
{
    pid_t code = (pid_t)key;
    return code % APP_HASH_BUTT;
}

static void AppInfoHashNodeFree(const HashNode *node)
{
    AppInfo *testNode = HASHMAP_ENTRY(node, AppInfo, node);
    APPSPAWN_LOGI("AppInfoHashNodeFree %s\n", testNode->name);
    free(testNode);
}

static void AddAppInfo(pid_t pid, const char *processName)
{
    size_t len = strlen(processName) + 1;
    AppInfo *node = (AppInfo *)malloc(sizeof(AppInfo) + len + 1);
    APPSPAWN_CHECK(node != NULL, return, "Failed to malloc for appinfo");

    node->pid = pid;
    int ret = strcpy_s(node->name, len, processName);
    APPSPAWN_CHECK(ret == 0, free(node);
        return, "Failed to strcpy process name");
    HASHMAPInitNode(&node->node);
    ret = HashMapAdd(g_appSpawnContent->appMap, &node->node);
    APPSPAWN_CHECK(ret == 0, free(node);
        return, "Failed to add appinfo to hash");
    APPSPAWN_LOGI("Add %s, pid=%d success", processName, pid);
}

static void RemoveAppInfo(pid_t pid)
{
    HashNode *node = HashMapGet(g_appSpawnContent->appMap, (const void *)&pid);
    APPSPAWN_CHECK(node != NULL, return, "Invalid node %d", pid);
    AppInfo *appInfo = HASHMAP_ENTRY(node, AppInfo, node);
    APPSPAWN_CHECK(appInfo != NULL, return, "Invalid node %d", pid);
    HashMapRemove(g_appSpawnContent->appMap, (const void *)&pid);
    free(appInfo);
}

static void KillProcess(HashNode *node, const void *context)
{
    AppInfo *hashNode = (AppInfo *)node;
    kill(hashNode->pid, SIGKILL);
    APPSPAWN_LOGI("kill app, pid = %d, processName = %s", hashNode->pid, hashNode->name);
}

static void OnClose(const TaskHandle taskHandle)
{
    AppSpawnClientExt *client = (AppSpawnClientExt *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(client != NULL, return, "Failed to get client");
    APPSPAWN_LOGI("OnClose client.id %d ", client->client.id);
}

static void SendMessageComplete(const TaskHandle taskHandle, BufferHandle handle)
{
    AppSpawnClientExt *client = (AppSpawnClientExt *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(client != NULL, return, "Failed to get client");
    APPSPAWN_LOGI("SendMessageComplete client.id %d ", client->client.id);
}

static int SendResponse(AppSpawnClientExt *client, const char *buff, size_t buffSize)
{
    APPSPAWN_CHECK(buffSize >= 0 && buff != 0, return -1, "Invalid content buffSize %d", buffSize);
    uint32_t bufferSize = buffSize;
    BufferHandle handle = LE_CreateBuffer(LE_GetDefaultLoop(), bufferSize);
    char *buffer = (char *)LE_GetBufferInfo(handle, NULL, &bufferSize);
    int ret = memcpy_s(buffer, bufferSize, buff, buffSize);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to memcpy_s bufferSize");
    return LE_Send(LE_GetDefaultLoop(), client->stream, handle, buffSize);
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
                RemoveAppInfo(pid);
            }
            break;
        }
        case SIGTERM: {  // appswapn killed, use kill without parameter
            HashMapTraverse(g_appSpawnContent->appMap, KillProcess, NULL);
            LE_StopLoop(LE_GetDefaultLoop());
            break;
        }
        default:
            APPSPAWN_LOGI("SigHandler, unsupported signal %d.", siginfo->ssi_signo);
            break;
    }
}

static void ProcessTimer(const TimerHandle taskHandle, void *context)
{
    APPSPAWN_LOGI("timeout stop appspawn");
    LE_StopLoop(LE_GetDefaultLoop());
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
    fd_set rd;
    struct timeval tv;
    FD_ZERO(&rd);
    FD_SET(fd, &rd);
    tv.tv_sec = TV_SEC;
    tv.tv_usec = 0;
    int ret = select(fd + 1, &rd, NULL, NULL, &tv);
    if (ret == 0) {  // timeout
        APPSPAWN_LOGI("Time out for child %s %d fd %d", appProperty->property.processName, pid, fd);
        result = 0;
    } else if (ret == -1) {
        APPSPAWN_LOGI("Error for child %s %d", appProperty->property.processName, pid);
        result = 0;
    } else {
        (void)read(fd, &result, sizeof(result));
    }
    return result;
}

static void OnReceiveRequest(const TaskHandle taskHandle, const uint8_t *buffer, uint32_t buffLen)
{
    APPSPAWN_CHECK(buffer != NULL && buffLen >= sizeof(AppParameter), LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid buffer buffLen %u", buffLen);
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)LE_GetUserData(taskHandle);
    APPSPAWN_CHECK(appProperty != NULL, LE_CloseTask(LE_GetDefaultLoop(), taskHandle); return, "alloc client Failed");
    int ret = memcpy_s(&appProperty->property, sizeof(appProperty->property), buffer, buffLen);
    APPSPAWN_CHECK(ret == 0, LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return, "Invalid buffer buffLen %u", buffLen);
    APPSPAWN_CHECK(appProperty->property.gidCount <= APP_MAX_GIDS && strlen(appProperty->property.processName) > 0,
        LE_CloseTask(LE_GetDefaultLoop(), taskHandle); return, "Invalid property %u", appProperty->property.gidCount);
    // special handle bundle name medialibrary and scanner
    HandleSpecial(appProperty);
    if (g_appSpawnContent->timer != NULL) {
        LE_StopTimer(LE_GetDefaultLoop(), g_appSpawnContent->timer);
        g_appSpawnContent->timer = NULL;
    }
    // cold start app
    if (appProperty->property.flags & 0x01) {
        char cold[10] = {0};  // 10 cold
        ret = GetParameter("appspawn.cold.boot", "false", cold, sizeof(cold));
        if (ret > 0 && (strcmp(cold, "true") == 0 || strcmp(cold, "1") == 0 || strcmp(cold, "enable") == 0)) {
            appProperty->client.flags |= APP_COLD_START;
        }
    }

    // create pipe for commication from child
    if (pipe(appProperty->fd) == -1) {
        APPSPAWN_LOGE("create pipe fail, errno = %d", errno);
        LE_CloseTask(LE_GetDefaultLoop(), taskHandle);
        return;
    }
    APPSPAWN_LOGI("OnReceiveRequest client.id %d appProperty %d processname %s buffLen %d flags 0x%x",
        appProperty->client.id, appProperty->property.uid, appProperty->property.processName,
        buffLen, appProperty->property.flags);

    fcntl(appProperty->fd[0], F_SETFL, O_NONBLOCK);
    pid_t pid = 0;
    int result = AppSpawnProcessMsg(g_appSpawnContent, &appProperty->client, &pid);
    if (result == 0) {  // wait child process resutl
        result = WaitChild(appProperty->fd[0], pid, appProperty);
    }
    close(appProperty->fd[0]);
    close(appProperty->fd[1]);
    APPSPAWN_LOGI("child process %s %s pid %d",
        appProperty->property.processName, (result == 0) ? "success" : "fail", pid);
    // send response
    if (result == 0) {
        AddAppInfo(pid, appProperty->property.processName);
        SendResponse(appProperty, (char *)&pid, sizeof(pid));
    } else {
        SendResponse(appProperty, (char *)&result, sizeof(result));
    }
    if (g_appSpawnContent->timer == NULL && ((g_appSpawnContent->flags & FLAGS_ON_DEMAND) == FLAGS_ON_DEMAND)) {
        ret = LE_CreateTimer(LE_GetDefaultLoop(), &g_appSpawnContent->timer, ProcessTimer, NULL);
        APPSPAWN_CHECK(ret == 0, return, "Failed to create time");
        LE_StartTimer(LE_GetDefaultLoop(), g_appSpawnContent->timer, 30000, 1);  // 30000 30s
    }
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
    info.sendMessageComplete = SendMessageComplete;
    info.recvMessage = OnReceiveRequest;
    LE_STATUS ret = LE_AcceptStreamClient(LE_GetDefaultLoop(), server, &stream, &info);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc stream");
    AppSpawnClientExt *client = (AppSpawnClientExt *)LE_GetUserData(stream);
    APPSPAWN_CHECK(client != NULL, return -1, "Failed to alloc stream");
    client->stream = stream;
    client->client.id = ++clientId;
    client->client.flags = 0;
    APPSPAWN_LOGI("OnConnection client fd %d Id %d", LE_GetSocketFd(stream), client->client.id);
    return 0;
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

    APPSPAWN_LOGI("AppSpawnInit");
    if (content->loadExtendLib) {
        content->loadExtendLib(content);
    }
    content->notifyResToParent = NotifyResToParent;
    // set private function
    SetContentFunction(content);
}

void AppSpawnColdRun(AppSpawnContent *content, int argc, char *const argv[])
{
    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)content;
    APPSPAWN_CHECK(appSpawnContent != NULL, return, "Failed to alloc memory for appspawn");

    AppSpawnClientExt *client = (AppSpawnClientExt *)malloc(sizeof(AppSpawnClientExt));
    APPSPAWN_CHECK(client != NULL, return, "Failed to alloc memory for client");
    int ret = GetAppSpawnClientFromArg(argc, argv, client);
    APPSPAWN_CHECK(ret == 0, free(client);
        return, "Failed to get client from arg");
    APPSPAWN_LOGI("Cold running %d processName %s", getpid(), client->property.processName);

    DoStartApp(content, &client->client, content->longProcName, content->longProcNameLen);
    if (content->runChildProcessor) {
        content->runChildProcessor(content, &client->client);
    }
    APPSPAWN_LOGI("App exit %d.", getpid());
    free(client);
    _exit(0x7f);
}

static void AppSpawnRun(AppSpawnContent *content)
{
    APPSPAWN_LOGI("AppSpawnRun");
    LE_STATUS status = LE_CreateSignalTask(LE_GetDefaultLoop(), &g_appSpawnContent->sigHandler, SignalHandler);
    if (status == 0) {
        status = LE_AddSignal(LE_GetDefaultLoop(), g_appSpawnContent->sigHandler, SIGCHLD);
        status = LE_AddSignal(LE_GetDefaultLoop(), g_appSpawnContent->sigHandler, SIGTERM);
    }
    if (status != 0) {
        APPSPAWN_LOGE("Failed to add signal %d", status);
    }

    LE_RunLoop(LE_GetDefaultLoop());
    APPSPAWN_LOGI("AppSpawnRun exit ");
    LE_CloseSignalTask(LE_GetDefaultLoop(), g_appSpawnContent->sigHandler);
    // release resource
    HashMapDestory(g_appSpawnContent->appMap);
    free(content);
    g_appSpawnContent = NULL;
}

AppSpawnContent *AppSpawnCreateContent(const char *socketName, char *longProcName, int64_t longProcNameLen, int cold)
{
    APPSPAWN_CHECK(LE_GetDefaultLoop() != NULL, return NULL, "Invalid default loop");
    APPSPAWN_CHECK(socketName != NULL && longProcName != NULL, return NULL, "Invalid name");
    APPSPAWN_LOGI("AppSpawnCreateContent %s", socketName);

    AppSpawnContentExt *appSpawnContent = (AppSpawnContentExt *)malloc(sizeof(AppSpawnContentExt));
    APPSPAWN_CHECK(appSpawnContent != NULL, return NULL, "Failed to alloc memory for appspawn");
    (void)memset_s(&appSpawnContent->content, sizeof(appSpawnContent->content), 0, sizeof(appSpawnContent->content));
    appSpawnContent->content.longProcName = longProcName;
    appSpawnContent->content.longProcNameLen = longProcNameLen;
    appSpawnContent->timer = NULL;
    appSpawnContent->content.runAppSpawn = AppSpawnRun;
    appSpawnContent->content.initAppSpawn = AppSpawnInit;

    if (cold) {
        g_appSpawnContent = appSpawnContent;
        return &g_appSpawnContent->content;
    }

    // create hash for app
    HashInfo hashInfo = {
        AppInfoHashNodeCompare,
        TestHashKeyCompare,
        AppInfoHashNodeFunction,
        AppInfoHashKeyFunction,
        AppInfoHashNodeFree,
        APP_HASH_BUTT
    };
    int ret = HashMapCreate(&appSpawnContent->appMap, &hashInfo);
    APPSPAWN_CHECK(ret == 0, free(appSpawnContent); return NULL, "Failed to create hash for app");

    char path[128] = {0};  // 128 max path
    ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s%s", SOCKET_DIR, socketName);
    APPSPAWN_CHECK(ret >= 0, free(appSpawnContent); return NULL, "Failed to snprintf_s %d", ret);
    int socketId = GetControlSocket(socketName);
    APPSPAWN_LOGI("get socket form env %s socketId %d", socketName, socketId);
    if (socketId > 0) {
        appSpawnContent->flags = FLAGS_ON_DEMAND;
    }

    LE_StreamServerInfo info = {};
    info.baseInfo.flags = TASK_STREAM | TASK_PIPE | TASK_SERVER;
    info.socketId = socketId;
    info.server = path;
    info.baseInfo.close = NULL;
    info.incommingConntect = OnConnection;
    ret = LE_CreateStreamServer(LE_GetDefaultLoop(), &appSpawnContent->servcer, &info);
    APPSPAWN_CHECK(ret == 0, free(appSpawnContent); return NULL, "Failed to create socket for %s", path);
    // create socket
    ret = chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    APPSPAWN_CHECK(ret == 0, free(appSpawnContent); return NULL, "Failed to chmod %s, err %d. ", path, errno);
    APPSPAWN_LOGI("AppSpawnCreateContent path %s fd %d", path, LE_GetSocketFd(appSpawnContent->servcer));
    g_appSpawnContent = appSpawnContent;
    return &g_appSpawnContent->content;
}
