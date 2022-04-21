/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef OHOS_DEBUG
#include <errno.h>
#include <time.h>
#endif  // OHOS_DEBUG

#include "appspawn_message.h"
#include "appspawn_server.h"
#include "iproxy_server.h"
#include "iunknown.h"
#include "liteipc_adapter.h"
#include "message.h"
#include "ohos_errno.h"
#include "ohos_init.h"
#include "samgr_lite.h"
#include "service.h"

static const int INVALID_PID = -1;
static const int CLIENT_ID = 100;

typedef struct AppSpawnFeatureApi {
    INHERIT_SERVER_IPROXY;
} AppSpawnFeatureApi;

typedef struct AppSpawnService {
    INHERIT_SERVICE;
    INHERIT_IUNKNOWNENTRY(AppSpawnFeatureApi);
    Identity identity;
} AppSpawnService;

static const char *GetName(Service *service)
{
    (void)service;
    APPSPAWN_LOGI("[appspawn] get service name %s.", APPSPAWN_SERVICE_NAME);
    return APPSPAWN_SERVICE_NAME;
}

static BOOL Initialize(Service *service, Identity identity)
{
    if (service == NULL) {
        APPSPAWN_LOGE("[appspawn] initialize, service NULL!");
        return FALSE;
    }

    AppSpawnService *spawnService = (AppSpawnService *)service;
    spawnService->identity = identity;

    APPSPAWN_LOGI("[appspawn] initialize, identity<%d, %d, %p>", \
        identity.serviceId, identity.featureId, identity.queueId);
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    (void)service;
    (void)msg;
    APPSPAWN_LOGE("[appspawn] message handle not support yet!");
    return FALSE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = {LEVEL_HIGH, PRI_BELOW_NORMAL, 0x800, 20, SHARED_TASK};
    return config;
}

static int GetMessageSt(MessageSt *msgSt, IpcIo *req)
{
    if (msgSt == NULL || req == NULL) {
        return EC_FAILURE;
    }
#ifdef __LINUX__
    size_t len = 0;
    char *str = IpcIoPopString(req, &len);
    if (str == NULL || len == 0) {
        APPSPAWN_LOGE("[appspawn] invoke, get data failed.");
        return EC_FAILURE;
    }

    int ret = SplitMessage(str, len, msgSt);  // after split message, str no need to free(linux version)
#else
    BuffPtr *dataPtr = IpcIoPopDataBuff(req);
    if (dataPtr == NULL) {
        APPSPAWN_LOGE("[appspawn] invoke, get data failed.");
        return EC_FAILURE;
    }

    int ret = SplitMessage((char *)dataPtr->buff, dataPtr->buffSz, msgSt);

    // release buffer
    if (FreeBuffer(NULL, dataPtr->buff) != LITEIPC_OK) {
        APPSPAWN_LOGE("[appspawn] invoke, free buffer failed!");
    }
#endif
    return ret;
}

static AppSpawnContentLite *g_appSpawnContentLite = NULL;
AppSpawnContent *AppSpawnCreateContent(const char *socketName, char *longProcName, int64_t longProcNameLen, int cold)
{
    UNUSED(longProcName);
    UNUSED(longProcNameLen);
    APPSPAWN_LOGI("AppSpawnCreateContent %s", socketName);
    AppSpawnContentLite *appSpawnContent = (AppSpawnContentLite *)malloc(sizeof(AppSpawnContentLite));
    APPSPAWN_CHECK(appSpawnContent != NULL, return NULL, "Failed to alloc memory for appspawn");
    appSpawnContent->content.longProcName = NULL;
    appSpawnContent->content.longProcNameLen = NULL;
    g_appSpawnContentLite = appSpawnContent;
    return appSpawnContent;
}

static int Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
#ifdef OHOS_DEBUG
    struct timespec tmStart = {0};
    GetCurTime(&tmStart);
#endif  // OHOS_DEBUG

    (void)iProxy;
    (void)origin;

    if (reply == NULL || funcId != ID_CALL_CREATE_SERVICE || req == NULL) {
        APPSPAWN_LOGE("[appspawn] invoke, funcId %d invalid, reply %d.", funcId, INVALID_PID);
        IpcIoPushInt64(reply, INVALID_PID);
        return EC_BADPTR;
    }

    AppSpawnClientLite *client = (AppSpawnClientLite *)malloc(sizeof(AppSpawnClientLite));
    APPSPAWN_CHECK(client != NULL, return -1, "malloc AppSpawnClientLite Failed");
    client->client.id = CLIENT_ID;
    client->client.flags = 0;
    if (GetMessageSt(&client->message, req) != EC_SUCCESS) {
        APPSPAWN_LOGE("[appspawn] invoke, parse failed! reply %d.", INVALID_PID);
        IpcIoPushInt64(reply, INVALID_PID);
        return EC_FAILURE;
    }

    APPSPAWN_LOGI("[appspawn] invoke, msg<%s,%s,%d,%d %d>", client->message.bundleName, client->message.identityID,
        client->message.uID, client->message.gID, client->message.capsCnt);

    pid_t newPid = 0;
    int ret = AppSpawnProcessMsg(g_appSpawnContentLite, &client->client, &newPid);
    if (ret != 0) {
        newPid = -1;
    }
    FreeMessageSt(&client->message);
    IpcIoPushInt64(reply, newPid);

#ifdef OHOS_DEBUG
    struct timespec tmEnd = {0};
    GetCurTime(&tmEnd);
    // 1s = 1000000000ns
    long timeUsed = (tmEnd.tv_sec - tmStart.tv_sec) * 1000000000L + (tmEnd.tv_nsec - tmStart.tv_nsec);
    APPSPAWN_LOGI("[appspawn] invoke, reply pid %d, timeused %ld ns.", newPid, timeUsed);
#else
    APPSPAWN_LOGI("[appspawn] invoke, reply pid %d.", newPid);
#endif  // OHOS_DEBUG

    return ((newPid > 0) ? EC_SUCCESS : EC_FAILURE);
}

static AppSpawnService g_appSpawnService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
};

void AppSpawnInit(void)
{
    if (SAMGR_GetInstance()->RegisterService((Service *)&g_appSpawnService) != TRUE) {
        APPSPAWN_LOGE("[appspawn] register service failed!");
        return;
    }

    APPSPAWN_LOGI("[appspawn] register service succeed. %p.", &g_appSpawnService);

    if (SAMGR_GetInstance()->RegisterDefaultFeatureApi(APPSPAWN_SERVICE_NAME, \
        GET_IUNKNOWN(g_appSpawnService)) != TRUE) {
        (void)SAMGR_GetInstance()->UnregisterService(APPSPAWN_SERVICE_NAME);
        APPSPAWN_LOGE("[appspawn] register featureapi failed!");
        return;
    }

    APPSPAWN_LOGI("[appspawn] register featureapi succeed.");
}

SYSEX_SERVICE_INIT(AppSpawnInit);
