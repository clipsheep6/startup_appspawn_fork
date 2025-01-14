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

#ifndef APPSPAWN_MSG_H
#define APPSPAWN_MSG_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__MUSL__)
#ifndef APPSPAWN_TEST
#define  SOCKET_DIR "/dev/unix/socket/"
#else
#define  SOCKET_DIR "/data/appspawn_ut/dev/unix/socket/"
#endif
#else
#define  SOCKET_DIR "/dev/socket/"
#endif


#define NWEBSPAWN_SOCKET_NAME "NWebSpawn"
#define NWEBSPAWN_SERVER_NAME "nwebspawn"
#define APPSPAWN_SOCKET_NAME "AppSpawn"
#define APPSPAWN_SERVER_NAME "appspawn"


enum AppType {
    APP_TYPE_DEFAULT = 0,  // JavaScript app
    APP_TYPE_NATIVE        // Native C++ app
};

typedef enum AppOperateType_ {
    DEFAULT = 0,
    GET_RENDER_TERMINATION_STATUS,
    SPAWN_NATIVE_PROCESS
} AppOperateType;

#define APP_MSG_MAX_SIZE 4096  // appspawn message max size
#define APP_LEN_PROC_NAME 256         // process name length
#define APP_LEN_BUNDLE_NAME 256       // bundle name length
#define APP_LEN_SO_PATH 256             // load so lib
#define APP_MAX_GIDS 64
#define APP_APL_MAX_LEN 32
#define APP_RENDER_CMD_MAX_LEN 2048
#define APP_OWNER_ID_LEN 64

/* AppParameter.flags bit definition */
#define APP_COLD_BOOT 0x01
#define APP_BACKUP_EXTENSION 0x02
#define APP_DLP_MANAGER 0x04
#define APP_DEBUGGABLE 0x08  // debuggable application
#define APP_ASANENABLED 0x10
#define APP_ACCESS_BUNDLE_DIR 0x20
#define APP_NATIVEDEBUG 0X40
#define APP_NO_SANDBOX 0x80  // Do not enter sandbox
#define APP_OVERLAY_FLAG 0x100
#define GET_BUNDLE_RESOURCES_FLAG 0x200
#define APP_GWP_ENABLED_FORCE 0x400
#define APP_GWP_ENABLED_NORMAL 0x800
#define APP_TSANENABLED 0x1000
#define BITLEN32 32
#define FDLEN2 2
#define FD_INIT_VALUE 0

#define APPSPAWN_COLDSTART_KEY "cold-start"
#define NWEBSPAWN_COLDSTART_KEY "nweb-cold-start"

typedef struct ExtraInfo {
    uint32_t totalLength;
    uint32_t savedLength;
    char* data;
} ExtraInfo;

typedef struct AppParameter {
    AppOperateType code;
    uint32_t flags;
    int32_t pid;                     // query render process exited status by render process pid
    uint32_t uid;                     // the UNIX uid that the child process setuid() to after fork()
    uint32_t gid;                     // the UNIX gid that the child process setgid() to after fork()
    uint32_t gidCount;                // the size of gidTable
    uint32_t gidTable[APP_MAX_GIDS];      // a list of UNIX gids that the child process setgroups() to after fork()
    char processName[APP_LEN_PROC_NAME];  // process name
    char bundleName[APP_LEN_BUNDLE_NAME]; // bundle name
    char soPath[APP_LEN_SO_PATH];         // so lib path
    char apl[APP_APL_MAX_LEN];
    char renderCmd[APP_RENDER_CMD_MAX_LEN];
    char ownerId[APP_OWNER_ID_LEN];  // app identifier id
    uint32_t accessTokenId;
    int32_t bundleIndex;
    uint64_t accessTokenIdEx;
    uint32_t hapFlags;
    uint32_t mountPermissionFlags;
#ifndef OHOS_LITE
    uint8_t setAllowInternet;
    uint8_t allowInternet; // hap sockect allowed
    uint8_t reserved1;
    uint8_t reserved2;
#endif
    ExtraInfo extraInfo; // Extera info using by format |type1|...|type1|type2|...|type2|
} AppParameter;

#ifdef __cplusplus
}
#endif

#endif
