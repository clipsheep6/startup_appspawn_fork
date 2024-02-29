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

#ifndef APPSPAWN_TEST_STUB_H
#define APPSPAWN_TEST_STUB_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define UNUSED(x) (void)(x)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppSpawnContent_ AppSpawnContent;
typedef struct AppSpawnClient_ AppSpawnClient;
typedef struct AppSpawnReqNode_ AppSpawnReqNode;
typedef void * AppSpawnClientHandle;
typedef struct AppSpawnReqMgr_ AppSpawnReqMgr;
typedef struct AppProperty_ AppProperty;
typedef struct AppSpawnMsg_ AppSpawnMsg;
typedef struct AppSpawnSandbox_  AppSpawnSandbox;
typedef struct AppSpawnExtData_ AppSpawnDataEx;
typedef struct SandboxContext_ SandboxContext;
typedef struct AppSpawnAppInfo_ AppSpawnAppInfo;
typedef struct AppSpawnForkArg_ AppSpawnForkArg;

void SetHapDomainSetcontextResult(int result);

void SignalHandler(const struct signalfd_siginfo *siginfo);

int CreateClientSocket(uint32_t type, int block);
void CloseClientSocket(int socketId);

void AddKeepMsgToSendQueue(AppSpawnReqMgr *reqMgr);
AppSpawnReqNode *GetReqNode(AppSpawnClientHandle handle, uint32_t msgId, int state);
int DecodeRecvMsg(AppProperty *property, const uint8_t *buffer, uint32_t msgLen);

void AppSpawnSandboxFree(AppSpawnDataEx *data);
AppSpawnSandbox *CreateAppSpawnSandbox(void);
void AddDefaultVariable(void);

int CloneAppSpawn(void *arg);
void AppSpawnDestroyContent(AppSpawnContent *content);

int WriteToFile(const char *path, int truncated, pid_t pids[], uint32_t count);
int GetCgroupPath(const AppSpawnAppInfo *appInfo, char *buffer, uint32_t buffLen);

void SetDeveloperMode(bool mode);

#define STUB_NEED_CHECK 0x01
typedef int (*ExecvFunc)(const char *pathname, char *const argv[]);
enum {
    STUB_MOUNT,
    STUB_EXECV,
    STUB_MAX,
};

typedef struct {
    uint16_t type;
    uint16_t flags;
    int result;
    void *arg;
} StubNode;
StubNode *GetStubNode(int type);
#ifdef __cplusplus
}
#endif
#endif // APPSPAWN_TEST_STUB_H
