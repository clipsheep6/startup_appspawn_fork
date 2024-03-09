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

#include <limits.h>
#include <stdbool.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_hook.h"
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
#define FD_ID_INDEX 3
#define FD_VALUE_INDEX 4
#define FLAGS_VALUE_INDEX 5
#define SHM_ID_INDEX 6
#define PARAM_ID_INDEX 7
#define PARAM_VALUE_INDEX 8

#define MAX_DIED_PROCESS_COUNT 5

#define INVALID_OFFSET 0xffffffff

#define APP_STATE_IDLE 1
#define APP_STATE_SPAWNING 2

#ifdef APPSPAWN_TEST
#define MAX_WAIT_MSG_COMPLETE 500  // 500
#define WAIT_CHILD_RESPONSE_TIMEOUT 500
#else
#define MAX_WAIT_MSG_COMPLETE (5 * 1000)  // 5s
#define WAIT_CHILD_RESPONSE_TIMEOUT 3000  //3s
#endif

#define APP_HASH_BUTT 32
#define FLAGS_ON_DEMAND 0x1
#define FLAGS_MODE_COLD 0x2
#define FLAGS_SANDBOX_PRIVATE 0x10
#define FLAGS_SANDBOX_APP 0x20

typedef struct TagAppSpawnContent AppSpawnContent;
typedef struct TagAppSpawnClient AppSpawnClient;
typedef struct TagAppSpawnConnection AppSpawnConnection;

typedef struct TagAppSpawnMsgNode {
    AppSpawnConnection *connection;
    AppSpawnMsg msgHeader;
    uint32_t tlvCount;
    uint32_t *tlvOffset;  // 记录属性的在msg中的偏移，不完全拷贝试消息完整
    uint8_t *buffer;
} AppSpawnMsgNode;

typedef struct TagAppSpawnMsgReceiverCtx {
    uint32_t nextMsgId;              // 校验消息id
    uint32_t msgRecvLen;             // 已经接收的长度
    TimerHandle timer;               // 测试消息完整
    AppSpawnMsgNode *incompleteMsg;  // 保存不完整的消息，额外保存消息头信息
} AppSpawnMsgReceiverCtx;

typedef struct TagAppSpawnConnection {
    uint32_t connectionId;
    TaskHandle stream;
    AppSpawnMsgReceiverCtx receiverCtx;
} AppSpawnConnection;

typedef struct {
    int32_t fd[2];  // 2 fd count
    WatcherHandle watcherHandle;
    TimerHandle timer;
    int shmId;
    uint32_t memSize;
    char *coldRunPath;
} AppSpawnForkCtx;

typedef struct TagAppSpawningCtx {
    AppSpawnClient client;
    struct ListNode node;
    AppSpawnForkCtx forkCtx;
    AppSpawnMsgNode *message;
    pid_t pid;
    int state;
    struct timespec spawnStart;
} AppSpawningCtx;

typedef struct TagAppSpawnedProcess {
    struct ListNode node;
    uid_t uid;
    pid_t pid;
    uint32_t max;
    int exitStatus;
    struct timespec spawnStart;
    struct timespec spawnEnd;
    char name[0];
} AppSpawnedProcess;

typedef struct {
    struct ListNode appQueue;  // save app pid and name
    uint32_t diedAppCount;
    struct ListNode diedQueue;      // save app pid and name
    struct ListNode appSpawnQueue;  // save app pid and name
} AppSpawnedProcessMgr;

typedef struct TagAppSpawnMgr {
    AppSpawnContent content;
    TaskHandle server;
    SignalHandle sigHandler;
    pid_t servicePid;
    AppSpawnedProcessMgr processMgr;
    struct timespec perLoadStart;
    struct timespec perLoadEnd;
    struct ListNode extData;
} AppSpawnMgr;

typedef struct TagAppSpawnStartArg {
    RunMode mode;
    uint32_t moduleType;
    const char *socketName;
    const char *serviceName;
    uint32_t initArg : 1;
} AppSpawnStartArg;

int AppSpawnedProcessMgrInit(AppSpawnedProcessMgr *mgr);
int AppSpawnedProcessMgrDestroy(AppSpawnedProcessMgr *mgr);
AppSpawnedProcess *AddSpawnedProcess(AppSpawnedProcessMgr *mgr, pid_t pid, const char *processName);
AppSpawnedProcess *GetSpawnedProcess(AppSpawnedProcessMgr *mgr, pid_t pid);
AppSpawnedProcess *GetSpawnedProcessByName(AppSpawnedProcessMgr *mgr, const char *name);
void HandleProcessTerminate(AppSpawnedProcessMgr *mgr, AppSpawnedProcess *node, int nwebspawn);
int GetProcessTerminationStatus(AppSpawnedProcessMgr *mgr, pid_t pid);

AppSpawningCtx *GetAppSpawningCtxByPid(AppSpawnedProcessMgr *mgr, pid_t pid);
AppSpawningCtx *CreateAppSpawningCtx(AppSpawnedProcessMgr *mgr);
void DeleteAppSpawningCtx(AppSpawningCtx *property);

pid_t NWebSpawnLaunch(void);
void NWebSpawnInit(void);
AppSpawnContent *StartSpawnService(const AppSpawnStartArg *arg, uint32_t argvSize, int argc, char *const argv[]);
void AppSpawnDestroyContent(AppSpawnContent *content);

// dump
void DumpApSpawn(const AppSpawnMgr *content, const AppSpawnMsgNode *message);
void DumpNormalProperty(const AppSpawningCtx *property);

pid_t GetPidFromTerminationMsg(AppSpawnMsgNode *message);
void DeleteAppSpawnMsg(AppSpawnMsgNode *msgNode);
int CheckAppSpawnMsg(const AppSpawnMsgNode *message);
int DecodeAppSpawnMsg(AppSpawnMsgNode *message);
int GetAppSpawnMsgFromBuffer(const uint8_t *buffer, uint32_t bufferLen,
    AppSpawnMsgNode **outMsg, uint32_t *msgRecvLen, uint32_t *reminder);
int SendAppSpawnMsgToChild(AppSpawnForkCtx *forkCtx, AppSpawnMsgNode *message);
void *GetAppSpawnMsgInfo(const AppSpawnMsgNode *message, int type);
void *GetAppSpawnMsgExInfo(const AppSpawnMsgNode *message, const char *name, uint32_t *len);
// for stub
bool may_init_gwp_asan(bool forceInit);
#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_SERVICE_H
