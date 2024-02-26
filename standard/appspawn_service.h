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

#ifndef APPSPAWN_SERVICE_H
#define APPSPAWN_SERVICE_H

#include <stdbool.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_msg.h"
#include "appspawn_server.h"
#include "appspawn_utils.h"
#include "list.h"
#include "loop_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MODE_ID_INDEX 1
#define MODE_VALUE_INDEX 2
#define PARAM_ID_INDEX 3
#define PARAM_VALUE_INDEX 4
#define FD_ID_INDEX 5
#define FD_VALUE_INDEX 6
#define FLAGS_VALUE_INDEX 7

#define APP_STATE_IDLE 1
#define APP_STATE_SPAWNING 2

#ifdef APPSPAWN_TEST
#define MAX_WAIT_MSG_COMPLETE 500 // 500
#define WAIT_CHILD_RESPONSE_TIMEOUT 500
#else
#define MAX_WAIT_MSG_COMPLETE 5 * 1000 // 5s
#define WAIT_CHILD_RESPONSE_TIMEOUT 5000
#endif

#define APP_HASH_BUTT 32
#define FLAGS_ON_DEMAND 0x1
#define FLAGS_MODE_COLD 0x2
#define FLAGS_SANDBOX_PRIVATE 0x10
#define FLAGS_SANDBOX_APP 0x20

typedef struct AppSpawnContent_ AppSpawnContent;
typedef struct AppSpawnClient_ AppSpawnClient;

typedef struct AppSpawnConnection_ {
    uint32_t connectionId;
    TaskHandle stream;
    uint32_t msgRecvLen;  // 已经接收的长度
    AppSpawnMsg msg;      // 保存不完整的消息，额外保存消息头信息
    TimerHandle timer;    // 测试连接保活
    uint8_t *buffer;
} AppSpawnConnection;

typedef struct {
    struct ListNode node;
    AppSpawnTlvEx *tlv;
} AppPropertyEx;

typedef struct AppProperty_ {
    AppSpawnClient client;
    struct ListNode node;
    int32_t fd[2];  // 2 fd count
    WatcherHandle watcherHandle;
    TimerHandle timer;
    int state;
    pid_t pid;
    AppSpawnConnection *connection;
    AppSpawnMsg *msg;  // 指向消息头，方便数据获取
    uint32_t tlvCount;
    uint32_t tlvOffset[TLV_MAX];  // 记录属性的在msg中的偏移，不完全拷贝
} AppProperty;

typedef struct AppSpawnAppInfo_ {
    struct ListNode node;
    uid_t uid;
    pid_t pid;
    uint32_t max;
    int exitStatus;
    char name[0];
} AppSpawnAppInfo;

typedef struct AppSpawnAppMgr_ {
    struct ListNode appQueue;  // save app pid and name
    uint32_t diedAppCount;
    struct ListNode diedQueue;      // save app pid and name
    struct ListNode appSpawnQueue;  // save app pid and name
} AppSpawnAppMgr;

typedef struct AppSpawnContentExt_ {
    AppSpawnContent content;
    TaskHandle server;
    SignalHandle sigHandler;
    TimerHandle timer;
    struct AppSpawnAppMgr_ appMgr;
    struct ListNode extData;
} AppSpawnContentExt;

int AppSpawnAppMgrInit(AppSpawnAppMgr *mgr);
int AppSpawnAppMgrDestroy(AppSpawnAppMgr *mgr);
AppSpawnAppInfo *AppMgrAddApp(AppSpawnAppMgr *mgr, pid_t pid, const char *processName);
void AppMgrHandleAppDied(AppSpawnAppMgr *mgr, AppSpawnAppInfo *node, int nwebspawn);
AppSpawnAppInfo *GetAppInfo(AppSpawnAppMgr *mgr, pid_t pid);
AppSpawnAppInfo *GetAppInfoByName(AppSpawnAppMgr *mgr, const char *name);
int GetProcessTerminationStatus(AppSpawnAppMgr *mgr, pid_t pid);
void AppMgrHandleConnectClose(AppSpawnAppMgr *mgr, const AppSpawnConnection *connection);

AppProperty *GetAppPropertyByPid(AppSpawnAppMgr *mgr, pid_t pid);
AppProperty *AppMgrCreateAppProperty(AppSpawnAppMgr *mgr, uint32_t tlvCount);
void AppMgrDeleteAppProperty(AppProperty *property);

pid_t NWebSpawnLaunch(void);
void NWebSpawnInit(void);
AppSpawnContent *StartSpawnService(uint32_t argvSize, int argc, char *const argv[]);

// dump
void DumpApSpawn(const AppSpawnContentExt *content);
void DumpNormalProperty(const AppProperty *property, const uint8_t *buffer);

// for stub
bool may_init_gwp_asan(bool forceInit);
#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_SERVICE_H
