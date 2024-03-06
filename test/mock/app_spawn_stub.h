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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tagAppSpawnContent AppSpawnContent;
typedef struct tagAppSpawnClient AppSpawnClient;
typedef struct tagAppSpawnReqMsgNode AppSpawnReqMsgNode;
typedef void * AppSpawnClientHandle;
typedef struct tagAppSpawnReqMsgMgr AppSpawnReqMsgMgr;
typedef struct tagAppSpawningCtx AppSpawningCtx;
typedef struct tagAppSpawnMsg AppSpawnMsg;
typedef struct tagAppSpawnSandbox  AppSpawnSandbox;
typedef struct tagAppSpawnExtData AppSpawnDataEx;
typedef struct tagSandboxContext SandboxContext;
typedef struct tagAppSpawnedProcess AppSpawnedProcess;
typedef struct tagAppSpawnForkArg AppSpawnForkArg;
typedef struct tagAppSpawnMsgNode AppSpawnMsgNode;

void SetHapDomainSetcontextResult(int result);

void ProcessSignal(const struct signalfd_siginfo *siginfo);

int CreateClientSocket(uint32_t type, int block);
void CloseClientSocket(int socketId);

void AppSpawnSandboxFree(AppSpawnDataEx *data);
AppSpawnSandbox *CreateAppSpawnSandbox(void);
void AddDefaultVariable(void);

int CloneAppSpawn(void *arg);

int WriteToFile(const char *path, int truncated, pid_t pids[], uint32_t count);
int GetCgroupPath(const AppSpawnedProcess *appInfo, char *buffer, uint32_t buffLen);

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
