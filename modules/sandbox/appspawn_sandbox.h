/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef APPSPAWN_SANDBOX_H
#define APPSPAWN_SANDBOX_H

#include <limits.h>

#include "appspawn.h"
#include "appspawn_utils.h"
#include "appspawn_hook.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_PERMISSION_INDEX -1

#define JSON_FLAGS_INTERNAL "__internal__"
#define SANDBOX_NWEBSPAWN_ROOT_PATH APPSPAWN_BASE_DIR "/mnt/sandbox/com.ohos.render/"
#define SANDBOX_APPSPAWN_ROOT_PATH APPSPAWN_BASE_DIR "/mnt/sandbox/"
#define OHOS_RENDER "__internal__.com.ohos.render"
#define PHYSICAL_APP_INSTALL_PATH "/data/app/el1/bundle/public/"
#define APL_SYSTEM_CORE "system_core"
#define APL_SYSTEM_BASIC "system_basic"

#define PARAMETER_PACKAGE_NAME "<PackageName>"
#define PARAMETER_USER_ID "<currentUserId>"
#define PARAMETER_PACKAGE_INDEX "<PackageName_index>"

#define FILE_MODE 0711
#define MAX_SANDBOX_BUFFER 256
#define FUSE_OPTIONS_MAX_LEN 256
#define DLP_FUSE_FD 1000
#define APP_FLAGS_SECTION 0x80000000
#define BASIC_MOUNT_FLAGS MS_REC | MS_BIND

typedef enum SandboxTag {
    SANDBOX_TAG_MOUNT_PATH = 0,
    SANDBOX_TAG_SYMLINK,
    SANDBOX_TAG_PERMISSION,
    SANDBOX_TAG_PRIVATE,
    SANDBOX_TAG_COMMON_QUEUE,
    SANDBOX_TAG_PRIVATE_QUEUE,
    SANDBOX_TAG_PERMISSION_QUEUE,
    SANDBOX_TAG_INVALID
} SandboxNodeType;

typedef struct {
    struct ListNode node;
    uint32_t type;
} SandboxNode;

typedef struct PathMountNode {
    SandboxNode sandboxNode;
    char *source;  // source 目录，一般是全局的fs 目录
    char *target;  // 沙盒化后的目录
    unsigned long mountFlags; // "sandbox-flags" : [ "bind", "rec" ],
    unsigned long customizedFlags;  // "sandbox-flags-customized": [ "MS_NODEV", "MS_RDONLY" ],
    mode_t destMode;    // "dest-mode": "S_IRUSR | S_IWOTH | S_IRWXU "

    uint32_t flagsPoint : 8; // flags-point" : [{ "flags": "NOT_SUPPORTED",
    uint32_t isFlagsPoint : 1; // flags-point" : [{ "flags": "NOT_SUPPORTED",
    uint32_t dacOverrideSensitive : 1; // "dac-override-sensitive": "true",
    uint32_t mountSharedFlag : 1; // "mount-shared-flag" : "true",
    uint32_t checkErrorFlag : 1;

    char *options;
    char *fsType; // "fs-type": "sharefs"
    char *appAplName;
} PathMountNode;

typedef struct SymbolLinkNode_ {
    SandboxNode sandboxNode;
    char *target;
    char *linkName;
    mode_t destMode;    // "dest-mode": "S_IRUSR | S_IWOTH | S_IRWXU "
    uint32_t checkErrorFlag : 1;
} SymbolLinkNode;

typedef struct SandboxSection_ {
    struct ListNode front;
    uint32_t type;
#ifndef APPSPAWN_CLIENT
    uint32_t sandboxSwitch : 1; // "sandbox-switch": "ON",
    uint32_t sandboxShared : 1; // "sandbox-switch": "ON",
    char *rootFlagsPath[2];     // 2 for DLP_MANAGER/START_FLAGS_BACKUP
    char *rootPath;             // "sandbox-root" : "/mnt/sandbox/<PackageName>",
#endif
} SandboxSection;

#ifndef APPSPAWN_CLIENT
typedef struct PermissionNode_ {
    SandboxNode sandboxNode;
    SandboxSection section;
    int32_t permissionIndex;
    char *name;
    int32_t gidCount;
    gid_t gidTable[0];  // "gids": [1006, 1008],
} SandboxPermissionNode;
#else
typedef struct PermissionNode_ {
    SandboxNode sandboxNode;
    uint32_t permissionIndex;
    char name[0];
} SandboxPermissionNode;
#endif

typedef struct PathIndividualNode {
    SandboxNode sandboxNode;
    SandboxSection section;
    char name[0];
} SandboxPrivateNode;

typedef struct AppSpawnSandbox_ {
    AppSpawnDataEx extData;
    SandboxSection section;
    SandboxSection permissionNodeQueue;
    SandboxSection privateNodeQueue;
    int32_t permissionMaxIndex;
    uint32_t sandboxNsFlags[2]; // "sandbox-ns-flags": [ "pid", "net" ], // for appspawn and newspawn
    // for comm section
    uint32_t topSandboxSwitch : 1; // "top-sandbox-switch": "ON",
    uint32_t appFullMountEnable : 1;
    uint32_t pidNamespaceSupport : 1;
    char *appResourcesPath; // 2 for app-base/app-resources
    char defaultRootPath[0];     // "sandbox-root" : "/mnt/sandbox/<PackageName>",
} AppSpawnSandbox;

typedef struct SandboxContext_{
    uint32_t bufferLen;
    char *buffer[2];
    //uint32_t flags;
    char *realRootPath;
    char *sandboxPackagePath;
    char *defaultRootPath;
    const char *bundleName;
    const char *sandboxSectionName;
    const AppProperty *property;
    uint32_t sandboxSwitch : 1;
    uint32_t sandboxShared : 1;
    uint32_t bundleHasWps : 1;
    uint32_t dlpBundle : 1;
    uint32_t dlpUiExtType : 1;
    uint32_t appFullMountEnable : 1;
    uint32_t permissionCfg : 1;
    uint32_t nwebspawn : 1;
} SandboxContext;

typedef struct {
    struct ListNode node;
    ReplaceVarHandler replaceVar;
    char name[0];
} AppSandboxVarNode;

typedef int (*SetExpandAppSandboxCfgProc)(SandboxContext *context, AppSpawnSandbox *appSandBox, const char *name);
typedef struct {
    struct ListNode node;
    SetExpandAppSandboxCfgProc setConfig;
    char name[0];
} ExpandAppSandboxNode;

int LoadAppSandboxConfig(AppSpawnSandbox *sandBox);
int DumpSandboxNode(ListNode *node, void *data);
void DumpMountFlags(const char *info, unsigned long mountFlags);
void DumpMode(const char *info, mode_t mode);

SandboxPermissionNode *CreateSandboxPermissionNode(const char *name, uint32_t gidCount, uint32_t *gidTable);
int AddPathNode(SandboxNode *node, SandboxSection *queue);
void FreePathNode(SandboxNode *node);

SymbolLinkNode *CreateSymbolLinkNode(void);
PathMountNode *CreatePathMountNode(void);
void SandboxSectionInit(SandboxSection *section, uint32_t type);

// SandboxPrivateNode create and find
SandboxPrivateNode *CreateSandboxPrivateNode(const char *name);
SandboxPrivateNode *GetSandboxPrivateNode(const AppSpawnSandbox *sandBox, const char *name);

int32_t GetPermissionIndexInQueue(SandboxSection *queue, const char *permission);
const SandboxPermissionNode *GetPermissionNodeInQueue(SandboxSection *queue, const char *permission);
const SandboxPermissionNode *GetPermissionNodeInQueueByIndex(SandboxSection *queue, int32_t index);
int32_t PermissionRenumber(SandboxSection *queue);

AppSpawnSandbox *GetAppSpawnSandbox(const AppSpawnContentExt *content);

int PrepareSandbox(AppSpawnContentExt *content, AppProperty *property);
int SetSandboxConfigs(const AppSpawnSandbox *appSandBox, AppProperty *property, int nwebspawn);

void ClearVariable(void);
void AddDefaultVariable(void);
const char *GetSandboxRealVar(const SandboxContext *sandboxContext,
    uint32_t index, const char *source, const char *target, int permission);

typedef struct {
    struct ListNode node;
    ProcessExpandSandboxCfg cfgHandle;
    int prio;
    char name[0];
} AppSandboxExpandAppCfgNode;

int ProcessExpandAppSandboxConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name);
void AddDefaultExpandAppSandboxConfigHandle(void);
void ClearExpandAppSandboxConfigHandle(void);

#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_SANDBOX_H
