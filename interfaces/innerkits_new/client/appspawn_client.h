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

#ifndef APPSPAWN_CLIENT_H
#define APPSPAWN_CLIENT_H

#include <pthread.h>
#ifdef __cplusplus
#include <atomic>
#define ATOMIC_UINT std::atomic_uint
#else
#include <stdatomic.h>
#define ATOMIC_UINT atomic_uint
#endif
#include <stdint.h>
#include <stdlib.h>

#include "appspawn_msg.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef APPSPAWN_ASAN
#define TIMEOUT_DEF 5
#else
#define TIMEOUT_DEF 2
#endif

#define ARRAY_LENGTH(array) (uint32_t)(sizeof(array) / sizeof((array)[0]))
#define SELECT_TIMEOUT 500 * 1000
#define MAX_RETRY_COUNT_MSG_SEND 10
#define GID_FILE_ACCESS 1006  // only used for ExternalFileManager.hap
#define GID_USER_DATA_RW 1008
#define MAX_DATA_IN_TLV 2
#define TEST_REQ_NODE_STATE(reqNode, s)  ((uint32_t)atomic_load(&(reqNode)->state) == (s))

#define APPSPAWN_SOCKET_RETRY 100 // 100ms
#define APPSPAWN_SOCKET_CLOSE  60 * 10 * 1000 // 10m
#define CLIENT_SEND_KEEP  60 * 10 // 60 * 10s
#ifndef APPSPAWN_TEST
#define KEEK_LIVE_TIMEOUT 2 // 2s
#else
#define KEEK_LIVE_TIMEOUT 1 // 2s
#endif

struct AppSpawnReqNode_;
typedef enum ClientType_ {
    CLIENT_FOR_APPSPAWN,
    CLIENT_FOR_NWEBSPAWN,
    CLIENT_NAX
} AppSpawnClientType;

typedef enum {
    MSG_STATE_IDLE,
    MSG_STATE_COLLECTION,
    MSG_STATE_SEND,
    MSG_STATE_WAITING,
    MSG_STATE_FINISH,
    MSG_STATE_TIMEOUT
} AppSpawnMsgState;

typedef struct {
    struct ListNode node;
    uint32_t blockSize;     // block 的大小
    uint32_t currentIndex;  // 当前已经填充的位置
    uint8_t buffer[0];
} AppSpawnMsgBlock;

typedef struct AppSpawnReqMgr_ {
    AppSpawnClientType type;
    uint32_t keepTimeout;
    struct timespec keepStartTm;
    ATOMIC_UINT threadExit;
    pthread_t msgThread;
    struct ListNode msgQueue;
    struct ListNode sendQueue;
    struct ListNode waitingQueue;
    pthread_mutex_t mutex;
    pthread_cond_t notifyMsg;  // 等待回复
    uint32_t msgId;
    struct AppSpawnReqNode_ *keepMsg;
    AppSpawnMsgBlock recvBlock;
} AppSpawnReqMgr;

typedef struct AppSpawnReqNode_ {
    struct ListNode node;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    ATOMIC_UINT state;
    uint32_t retryCount;

    AppSpawnMsgFlags *msgFlags;
    AppSpawnMsgFlags *permissionFlags;
    AppSpawnMsg *msg;
    AppSpawnResult result;
    struct ListNode msgBlocks;  // 保存实际的消息数据
} AppSpawnReqNode;

typedef struct {
    uint8_t *data;
    uint16_t dataLen;
} AppSpawnAppData;

void *ClientProcessMsg(void *args);
AppSpawnReqNode *CreateAppSpawnReq(AppSpawnReqMgr *client, uint32_t msgType, const char *bundleName);
void DeleteAppSpawnReq(AppSpawnReqMgr *client, AppSpawnReqNode *reqNode);
void SafePushReqNode(AppSpawnReqMgr *client, AppSpawnReqNode *reqNode, struct ListNode *queue, uint32_t state);
void SafeRemoveReqNode(AppSpawnReqMgr *client, AppSpawnReqNode *reqNode);

AppSpawnReqNode *FindReqNodeByMsgId(AppSpawnReqMgr *client, uint32_t msgId, const ListNode *queue);
int GetMsgSerialNo(AppSpawnReqMgr *client);
int ClientSendMsg(AppSpawnReqMgr *client, AppSpawnReqNode *reqNode, uint32_t timeout, AppSpawnResult *result);
#ifdef __cplusplus
}
#endif
#endif
