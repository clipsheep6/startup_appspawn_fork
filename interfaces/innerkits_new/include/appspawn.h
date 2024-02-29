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

typedef void *AppSpawnReqMsgHandle;
typedef void *AppSpawnClientHandle;

#define INVALID_REQ_HANDLE NULL
#define NWEBSPAWN_SERVER_NAME "nwebspawn"
#define APPSPAWN_SERVER_NAME "appspawn"

#define APP_LEN_PROC_NAME 256    // process name length
#define APP_LEN_BUNDLE_NAME 256  // bundle name length
#define APP_LEN_SO_PATH 256      // load so lib
#define APP_MAX_GIDS 64
#define APP_APL_MAX_LEN 32
#define APP_RENDER_CMD_MAX_LEN 1024
#define APP_OWNER_ID_LEN 64
#define APP_USER_NAME 64

#define MSG_EXT_NAME_RENDER_CMD "render-cmd"
#define MSG_EXT_NAME_HSP_LIST "HspList"
#define MSG_EXT_NAME_OVERLAY "Overlay"
#define MSG_EXT_NAME_DATA_GROUP "DataGroup"
#define MSG_EXT_NAME_APP_ENV "AppEnv"

/*
flags bit definition
    use TestAppMsgFlagsSet to test
    use AppSpawnReqMsgSetAppFlag to set
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
    APP_FLAGS_GWP_ENABLED_FORCE,   // APP_GWP_ENABLED_FORCE 0x400
    APP_FLAGS_GWP_ENABLED_NORMAL,  // APP_GWP_ENABLED_NORMAL 0x800
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
    uint32_t uid;       // the UNIX uid that the child process setuid() to after fork()
    uint32_t gid;       // the UNIX gid that the child process setgid() to after fork()
    uint32_t gidCount;  // the size of gidTable
    uint32_t gidTable[APP_MAX_GIDS];
    char userName[APP_USER_NAME];
} AppDacInfo;

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
int AppSpawnClientSendMsg(AppSpawnClientHandle handle, AppSpawnReqMsgHandle reqHandle, AppSpawnResult *result);

/**
 * @brief create request
 *
 * @param msgType msg type AppSpawnMsgType
 * @param processName process name
 * @param reqHandle handle for request
 * @return int
 */
int AppSpawnReqMsgCreate(uint32_t msgType, const char *processName, AppSpawnReqMsgHandle *reqHandle);

/**
 * @brief destroy request
 *
 * @param reqHandle handle for request
 */
void AppSpawnReqMsgFree(AppSpawnReqMsgHandle reqHandle);

/**
 * @brief set bundle info
 *
 * @param reqHandle handle for request
 * @param bundleIndex
 * @param bundleName
 * @return int
 */
int AppSpawnReqMsgSetBundleInfo(AppSpawnReqMsgHandle reqHandle, int32_t bundleIndex, const char *bundleName);

/**
 * @brief set app flags info
 *
 * @param reqHandle handle for request
 * @param flagIndex flags index from AppFlagsIndex
 * @return int
 */
int AppSpawnReqMsgSetAppFlag(AppSpawnReqMsgHandle reqHandle, uint32_t flagIndex);

/**
 * @brief set dac info
 *
 * @param reqHandle handle for request
 * @param dacInfo dac info from AppDacInfo
 * @return int
 */
int AppSpawnReqMsgSetAppDacInfo(AppSpawnReqMsgHandle reqHandle, const AppDacInfo *dacInfo);

/**
 * @brief set domain info
 *
 * @param reqHandle handle for request
 * @param hapFlags
 * @param apl
 * @return int
 */
int AppSpawnReqMsgSetAppDomainInfo(AppSpawnReqMsgHandle reqHandle, uint32_t hapFlags, const char *apl);

/**
 * @brief set internet permission info
 *
 * @param reqHandle handle for request
 * @param allowInternet
 * @param setAllowInternet
 * @return int
 */
int AppSpawnReqMsgSetAppInternetPermissionInfo(AppSpawnReqMsgHandle reqHandle, uint8_t allow, uint8_t setAllow);

/**
 * @brief set access token info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param accessTokenId access tokenId
 * @param accessTokenIdEx access tokenId
 * @return int
 */
int AppSpawnReqMsgSetAppAccessToken(AppSpawnReqMsgHandle reqHandle, uint32_t accessTokenId, uint64_t accessTokenIdEx);

/**
 * @brief set owner info
 *
 * @param handle handle for client
 * @param reqHandle handle for request
 * @param ownerId
 * @return int
 */
int AppSpawnReqMsgSetAppOwnerId(AppSpawnReqMsgHandle reqHandle, const char *ownerId);

/**
 * @brief set permission
 *
 * @param reqHandle handle for request
 * @param permission permission name
 * @return int
 */
int AppSpawnReqMsgSetPermission(AppSpawnReqMsgHandle reqHandle, const char *permission);

/**
 * @brief create request
 *
 * @param pid process pid
 * @param reqHandle handle for request
 * @return int
 */
int AppSpawnTerminateMsgCreate(pid_t pid, AppSpawnReqMsgHandle *reqHandle);

/**
 * @brief add extend info
 *
 * @param reqHandle handle for request
 * @param name extend name
 *
 * @param value extend value
 * @param valueLen extend value length
 * @return int
 */
int AppSpawnReqMsgAddExtInfo(AppSpawnReqMsgHandle reqHandle, const char *name, const uint8_t *value, uint32_t valueLen);
int AppSpawnReqMsgAddStringInfo(AppSpawnReqMsgHandle reqHandle, const char *name, const char *value);

int AppSpawnReqMsgSetFlags(AppSpawnReqMsgHandle reqHandle, uint32_t tlv, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif
