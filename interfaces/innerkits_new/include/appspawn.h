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

#ifndef APPSPAWN_H
#define APPSPAWN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t AppSpawnReqHandle;
typedef void * AppSpawnClientHandle;

#define INVALID_REQ_HANDLE 0
#define NWEBSPAWN_SERVER_NAME "nwebspawn"
#define APPSPAWN_SERVER_NAME "appspawn"

#define APP_LEN_PROC_NAME 256         // process name length
#define APP_LEN_BUNDLE_NAME 256       // bundle name length
#define APP_LEN_SO_PATH 256             // load so lib
#define APP_MAX_GIDS 64
#define APP_APL_MAX_LEN 32
#define APP_RENDER_CMD_MAX_LEN 1024
#define APP_OWNER_ID_LEN 64
#define APP_USER_NAME 64

/*
flags bit definition
    use TestAppMsgFlagsSet to test
    use AppSpawnReqSetAppFlag to set
*/
typedef enum {
    APP_FLAGS_COLD_BOOT = 0,
    APP_FLAGS_BACKUP_EXTENSION = 1,
    APP_FLAGS_DLP_MANAGER = 2,
    APP_FLAGS_DEBUGGABLE = 3,
    APP_FLAGS_ASANENABLED = 4,
    APP_FLAGS_ACCESS_BUNDLE_DIR = 5,
    APP_FLAGS_NATIVEDEBUG = 6,
    APP_FLAGS_NO_SANDBOX = 7,
    APP_FLAGS_OVERLAY = 8,
    APP_FLAGS_BUNDLE_RESOURCES = 9,
    APP_FLAGS_GWP_ENABLED_FORCE, // APP_GWP_ENABLED_FORCE 0x400
    APP_FLAGS_GWP_ENABLED_NORMAL, // APP_GWP_ENABLED_NORMAL 0x800
#ifndef APPSPAWN_TEST
    MAX_FLAGS_INDEX,
#else
    MAX_FLAGS_INDEX = 63,
#endif
} AppFlagsIndex;

typedef enum {
    MSG_APP_SPAWN = 0,
    MSG_GET_RENDER_TERMINATION_STATUS,
    MSG_SPAWN_NATIVE_PROCESS,
    MSG_KEEPALIVE,
    MSG_DUMP,
    MAX_TYPE_INVALID
} AppSpawnMsgType;

#pragma pack(4)
typedef struct {
    uint32_t uid;                     // the UNIX uid that the child process setuid() to after fork()
    uint32_t gid;                     // the UNIX gid that the child process setgid() to after fork()
    uint32_t gidCount;                // the size of gidTable
    uint32_t gidTable[APP_MAX_GIDS];
    char userName[APP_USER_NAME];
} AppDacInfo, AppSpawnMsgDacInfo;

typedef struct {
    uint32_t accessTokenId; // 这个字段目前没有使用，是否删除
    uint64_t accessTokenIdEx;
} AppAccessTokenInfo, AppSpawnMsgAccessToken;

typedef struct {
    char renderCmd[APP_RENDER_CMD_MAX_LEN]; // 整体申请内存
} AppRenderCmd;

typedef struct {
    char ownerId[APP_OWNER_ID_LEN];  // app identifier id
} AppOwnerId;

typedef struct {
    uint32_t hapFlags;
    char apl[APP_APL_MAX_LEN];
} AppDomainInfo;

typedef struct {
    uint8_t setAllowInternet;
    uint8_t allowInternet; // hap sockect allowed
} AppInternetPermissionInfo;

typedef struct {
    int32_t bundleIndex;
    char bundleName[APP_LEN_BUNDLE_NAME];  // process name
} AppBundleInfo;

typedef struct {
    int result;
    pid_t pid;
} AppSpawnResult;
#pragma pack()

/**
 * @brief init spawn client, eg: nwebspawn、appspawn
 *
 * @param serviceName service name, eg: nwebspawn、appspawn
 * @param handle handle for client
 * @return int
 */
int AppSpawnClientInit(const char *serviceName, AppSpawnClientHandle *handle);
/**
 * @brief destroy client
 *
 * @param handle handle for client
 * @return int
 */
int AppSpawnClientDestroy(AppSpawnClientHandle handle);

/**
 * @brief send client request
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param result result from appspawn service
 * @return int
 */
int AppSpawnClientSendMsg(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, AppSpawnResult *result);

/**
 * @brief create request
 *
 * @param handle handle for client
 * @param msgType msg type AppSpawnMsgType
 * @param processName process name
 * @param reqHandle handle for request
 * @return int
 */
int  AppSpawnReqCreate(AppSpawnClientHandle handle,
    uint32_t msgType, const char *processName, AppSpawnReqHandle *reqHandle);
/**
 * @brief destroy request
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 */
void AppSpawnReqDestroy(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle);

/**
 * @brief set bundle info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info bundle info AppBundleInfo
 * @return int
 */
int AppSpawnReqSetBundleInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppBundleInfo *info);

/**
 * @brief set app flags info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param flagIndex flags index from AppFlagsIndex
 * @return int
 */
int AppSpawnReqSetAppFlag(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, uint32_t flagIndex);

/**
 * @brief set dac info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param dacInfo dac info from AppDacInfo
 * @return int
 */
int AppSpawnReqSetAppDacInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppDacInfo *dacInfo);

/**
 * @brief set domain info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info info from AppDomainInfo
 * @return int
 */
int AppSpawnReqSetAppDomainInfo(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppDomainInfo *info);

/**
 * @brief set internet permission info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info info from AppInternetPermissionInfo
 * @return int
 */
int AppSpawnReqSetAppInternetPermissionInfo(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const AppInternetPermissionInfo *info);

/**
 * @brief set owner info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info info from AppOwnerId
 * @return int
 */
int AppSpawnReqSetAppOwnerId(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppOwnerId *info);

/**
 * @brief set render cmd info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info info from AppRenderCmd
 * @return int
 */
int AppSpawnReqSetAppRenderCmd(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, const AppRenderCmd *info);

/**
 * @brief set access token info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param info info from AppAccessTokenInfo
 * @return int
 */
int AppSpawnReqSetAppAccessToken(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const AppAccessTokenInfo *info);

/**
 * @brief add extend info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param name extend name
 * @param value extend value
 * @param valueLen extend value length
 * @return int
 */
int AppSpawnReqAddExtInfo(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const char *name, const uint8_t *value, uint32_t valueLen);

/**
 * @brief set permission
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param permissions permission name list
 * @param count permission count
 * @return int
 */
int AppSpawnReqSetPermission(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, const char **permissions, uint32_t count);

/**
 * @brief set termination pid for nweb service
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param pid
 * @return int
 */
int AppSpawnReqSetTerminationPid(AppSpawnClientHandle handle, AppSpawnReqHandle reqHandle, uint32_t pid);

int AppSpawnReqSeFlags(AppSpawnClientHandle handle,
    AppSpawnReqHandle reqHandle, uint32_t tlv, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif
