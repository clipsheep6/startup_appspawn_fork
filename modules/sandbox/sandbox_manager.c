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

#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>

#include "appspawn_manager.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "modulemgr.h"
#include "securec.h"

static void FreePathMountNode(SandboxMountNode *node)
{
    PathMountNode *sandboxNode = (PathMountNode *)node;
    if (sandboxNode->source) {
        free(sandboxNode->source);
        sandboxNode->source = NULL;
    }
    if (sandboxNode->target) {
        free(sandboxNode->target);
        sandboxNode->target = NULL;
    }
    if (sandboxNode->options) {
        free(sandboxNode->options);
        sandboxNode->options = NULL;
    }
    if (sandboxNode->fsType) {
        free(sandboxNode->fsType);
        sandboxNode->fsType = NULL;
    }
    if (sandboxNode->appAplName) {
        free(sandboxNode->appAplName);
        sandboxNode->appAplName = NULL;
    }
    free(sandboxNode);
}

static void FreeSymbolLinkNode(SandboxMountNode *node)
{
    SymbolLinkNode *sandboxNode = (SymbolLinkNode *)node;
    if (sandboxNode->target) {
        free(sandboxNode->target);
        sandboxNode->target = NULL;
    }
    if (sandboxNode->linkName) {
        free(sandboxNode->linkName);
        sandboxNode->linkName = NULL;
    }
    free(sandboxNode);
}

static void PermissionQueueDestroyProc(ListNode *node)
{
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    FreePathNode(sandboxNode);
}

static void PrivateQueueDestroyProc(ListNode *node)
{
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    FreePathNode(sandboxNode);
}

static void PathNodeDestroyProc(ListNode *node)
{
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    switch (sandboxNode->type) {
        case SANDBOX_TAG_MOUNT_PATH:
            FreePathMountNode(sandboxNode);
            break;
        case SANDBOX_TAG_SYMLINK:
            FreeSymbolLinkNode(sandboxNode);
            break;
        default:
            break;
    }
}

static int PermissionNodeCompareProc(ListNode *node, ListNode *newNode)
{
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
    SandboxPermissionNode *newPermissionNode = (SandboxPermissionNode *)ListEntry(newNode, SandboxMountNode, node);
    return strcmp(permissionNode->name, newPermissionNode->name);
}

static int PrivateNodeCompareProc(ListNode *node, ListNode *newNode)
{
    SandboxPrivateNode *privateNode = (SandboxPrivateNode *)ListEntry(node, SandboxMountNode, node);
    SandboxPrivateNode *newPrivateNode = (SandboxPrivateNode *)ListEntry(newNode, SandboxMountNode, node);
    return strcmp(privateNode->name, newPrivateNode->name);
}

static int SandboxNodeCompareProc(ListNode *node, ListNode *newNode)
{
    SandboxMountNode *sandbox1 = (SandboxMountNode *)ListEntry(node, SandboxMountNode, node);
    SandboxMountNode *sandbox2 = (SandboxMountNode *)ListEntry(newNode, SandboxMountNode, node);
    return sandbox1->type - sandbox2->type;
}

PathMountNode *CreatePathMountNode(void)
{
    PathMountNode *node = (PathMountNode *)malloc(sizeof(PathMountNode));
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to create mount node");
    (void)memset_s(node, sizeof(PathMountNode), 0, sizeof(PathMountNode));
    OH_ListInit(&node->sandboxNode.node);
    node->sandboxNode.type = SANDBOX_TAG_MOUNT_PATH;
    node->source = NULL;
    node->target = NULL;
    node->options = NULL;
    node->fsType = NULL;
    return node;
}

SymbolLinkNode *CreateSymbolLinkNode(void)
{
    SymbolLinkNode *node = (SymbolLinkNode *)malloc(sizeof(SymbolLinkNode));
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to create symbol node");
    (void)memset_s(node, sizeof(SymbolLinkNode), 0, sizeof(SymbolLinkNode));
    OH_ListInit(&node->sandboxNode.node);
    node->sandboxNode.type = SANDBOX_TAG_SYMLINK;
    node->target = NULL;
    node->linkName = NULL;
    return node;
}

static void SandboxSectionFree(SandboxSection *section)
{
    if (section->rootPath) {
        free(section->rootPath);
        section->rootPath = NULL;
    }
    if (section->rootFlagsPath[0]) {
        free(section->rootFlagsPath[0]);
        section->rootFlagsPath[0] = NULL;
    }
    if (section->rootFlagsPath[1]) {
        free(section->rootFlagsPath[1]);
        section->rootFlagsPath[1] = NULL;
    }
    OH_ListRemoveAll(&section->front, PathNodeDestroyProc);
}

SandboxPrivateNode *CreateSandboxPrivateNode(const char *name)
{
    size_t len = strlen(name) + 1;
    SandboxPrivateNode *node = (SandboxPrivateNode *)malloc(sizeof(SandboxPrivateNode) + len);
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to create symbol node");
    (void)memset_s(node, sizeof(SandboxPrivateNode), 0, sizeof(SandboxPrivateNode));
    OH_ListInit(&node->sandboxNode.node);
    node->sandboxNode.type = SANDBOX_TAG_PRIVATE;
    SandboxSectionInit(&node->section, SANDBOX_TAG_PRIVATE_QUEUE);
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node);
        return NULL, "Failed to copy name");
    return node;
}

static int PrivateNodeCompareName(ListNode *node, void *data)
{
    SandboxPrivateNode *tmpNode = (SandboxPrivateNode *)ListEntry(node, SandboxMountNode, node);
    return strcmp(tmpNode->name, (char *)data);
}

SandboxPrivateNode *GetSandboxPrivateNode(const AppSpawnSandboxCfg *sandbox, const char *name)
{
    ListNode *node = OH_ListFind(&sandbox->privateNodeQueue.front, (void *)name, PrivateNodeCompareName);
    if (node == NULL) {
        return NULL;
    }
    return (SandboxPrivateNode *)ListEntry(node, SandboxMountNode, node);
}

void FreePathNode(SandboxMountNode *node)
{
    // delete node
    OH_ListRemove(&node->node);

    switch (node->type) {
        case SANDBOX_TAG_MOUNT_PATH:
            FreePathMountNode(node);
            break;
        case SANDBOX_TAG_SYMLINK:
            FreeSymbolLinkNode(node);
            break;
        case SANDBOX_TAG_PERMISSION: {
            SandboxPermissionNode *sandboxNode = (SandboxPermissionNode *)node;
            SandboxSectionFree(&sandboxNode->section);
            free(node);
            break;
        }
        case SANDBOX_TAG_PRIVATE:{
            SandboxPrivateNode *sandboxNode = (SandboxPrivateNode *)node;
            SandboxSectionFree(&sandboxNode->section);
            free(node);
            break;
        }
        default:
            break;
    }
}

void SandboxSectionInit(SandboxSection *section, uint32_t type)
{
    OH_ListInit(&section->front);
    section->type = type;
    section->sandboxSwitch = 0;
    section->sandboxShared = 0;
    section->rootPath = NULL;
    section->rootFlagsPath[0] = NULL;
    section->rootFlagsPath[1] = NULL;
}

int AddPathNode(SandboxMountNode *node, SandboxSection *queue)
{
    switch (node->type) {
        case SANDBOX_TAG_PERMISSION:
            OH_ListAddWithOrder(&queue->front, &node->node, PermissionNodeCompareProc);
            break;
        case SANDBOX_TAG_PRIVATE:
            OH_ListAddWithOrder(&queue->front, &node->node, PrivateNodeCompareProc);
            break;
        default:
            OH_ListAddWithOrder(&queue->front, &node->node, SandboxNodeCompareProc);
            break;
    }
    return 0;
}

APPSPAWN_STATIC void AppSpawnSandboxFree(AppSpawnExtData *data)
{
    AppSpawnSandboxCfg *sandbox = (AppSpawnSandboxCfg *)data;
    OH_ListRemove(&sandbox->extData.node);
    OH_ListInit(&sandbox->extData.node);

    // delete all queue
    OH_ListRemoveAll(&sandbox->permissionNodeQueue.front, PermissionQueueDestroyProc);
    OH_ListRemoveAll(&sandbox->privateNodeQueue.front, PrivateQueueDestroyProc);
    SandboxSectionFree(&sandbox->section);
    // delete all var
    ClearVariable();
    ClearExpandAppSandboxConfigHandle();

    free(sandbox);
    sandbox = NULL;
}

static int AppSpawnExtDataCompareDataId(ListNode *node, void *data)
{
    AppSpawnExtData *extData = (AppSpawnExtData *)ListEntry(node, AppSpawnExtData, node);
    return extData->dataId - *(uint32_t *)data;
}

AppSpawnSandboxCfg *GetAppSpawnSandbox(const AppSpawnMgr *content)
{
    uint32_t dataId = EXT_DATA_SANDBOX;
    ListNode *node = OH_ListFind(&content->extData, (void *)&dataId, AppSpawnExtDataCompareDataId);
    if (node == NULL) {
        return NULL;
    }
    return (AppSpawnSandboxCfg *)ListEntry(node, AppSpawnSandboxCfg, extData);
}

static void DumpSandboxSection(const char *info, const SandboxSection *section)
{
    APPSPAPWN_DUMP("    ========================================= ");
    APPSPAPWN_DUMP("    Section %{public}s", info);
    APPSPAPWN_DUMP("    sandboxSwitch %{public}s", section->sandboxSwitch ? "true" : "false");
    APPSPAPWN_DUMP("    sandboxShared %{public}s", section->sandboxShared ? "true" : "false");
    APPSPAPWN_DUMP("    rootPath %{public}s", section->rootPath ? section->rootPath : "null");
    APPSPAPWN_DUMP("    flags-point path of DLP_MANAGER %{public}s",
        section->rootFlagsPath[0] ? section->rootFlagsPath[0] : "null");
    APPSPAPWN_DUMP("    flags-point path of START_FLAGS_BACKUP %{public}s",
        section->rootFlagsPath[1] ? section->rootFlagsPath[1] : "null");
}

int DumpSandboxNode(ListNode *node, void *data)
{
    if (data != NULL) {
        (*(uint32_t *)data)++;
    }
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    switch (sandboxNode->type) {
        case SANDBOX_TAG_MOUNT_PATH: {
            PathMountNode *pathNode = (PathMountNode *)sandboxNode;
            APPSPAPWN_DUMP("        ****************************** %{public}u", (data == NULL) ? 0 : *(uint32_t *)data);
            APPSPAPWN_DUMP("        sandbox node source: %{public}s", pathNode->source ? pathNode->source : "null");
            APPSPAPWN_DUMP("        sandbox node target: %{public}s", pathNode->target ? pathNode->target : "null");
            APPSPAPWN_DUMP("        sandbox node options: %{public}s", pathNode->options ? pathNode->options : "null");
            APPSPAPWN_DUMP("        sandbox node fsType: %{public}s", pathNode->fsType ? pathNode->fsType : "null");
            APPSPAPWN_DUMP("        sandbox node apl: %{public}s",
                pathNode->appAplName ? pathNode->appAplName : "null");
            DumpMountFlags("        sandbox node mountFlags: ", pathNode->mountFlags);
            DumpMountFlags("        sandbox node customizedFlags: ", pathNode->customizedFlags);
            DumpMode("        sandbox node destMode: ", pathNode->destMode);
            APPSPAPWN_DUMP("        sandbox node flagsPoint: %{public}s",
                (CHECK_FLAGS_BY_INDEX(pathNode->flagsPoint, APP_FLAGS_BACKUP_EXTENSION)) ? "START_FLAGS_BACKUP" :
                (CHECK_FLAGS_BY_INDEX(pathNode->flagsPoint, APP_FLAGS_DLP_MANAGER)) ? "DLP_MANAGER" : "null");
            APPSPAPWN_DUMP("        sandbox node dacOverrideSensitive: %{public}s",
                pathNode->dacOverrideSensitive ? "true" : "false");
            APPSPAPWN_DUMP("        sandbox node mountSharedFlag: %{public}s",
                pathNode->mountSharedFlag ? "true" : "false");
            APPSPAPWN_DUMP("        sandbox node checkErrorFlag: %{public}s",
                pathNode->checkErrorFlag ? "true" : "false");
            break;
        }
        case SANDBOX_TAG_SYMLINK: {
            SymbolLinkNode *linkNode = (SymbolLinkNode *)sandboxNode;
            APPSPAPWN_DUMP("        ***********************************");
            APPSPAPWN_DUMP("        sandbox node target: %{public}s", linkNode->target ? linkNode->target : "null");
            APPSPAPWN_DUMP("        sandbox node linkName: %{public}s",
                linkNode->linkName ? linkNode->linkName : "null");
            APPSPAPWN_DUMP("        sandbox node destMode: %{public}x", linkNode->destMode);
            APPSPAPWN_DUMP("        sandbox node checkErrorFlag: %{public}s",
                linkNode->checkErrorFlag ? "true" : "false");
            break;
        }
        default:
            break;
    }
    return 0;
}

static int DumpSandboxPrivateNode(ListNode *node, void *data)
{
    (*(uint32_t *)data)++;
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    SandboxPrivateNode *privateNode = (SandboxPrivateNode *)sandboxNode;
    DumpSandboxSection(privateNode->name, &privateNode->section);
    uint32_t count = 0;
    OH_ListTraversal((ListNode *)&privateNode->section.front, (void *)&count, DumpSandboxNode, 0);
    return 0;
}

static int DumpSandboxPermissionNode(ListNode *node, void *data)
{
    (*(uint32_t *)data)++;
    SandboxMountNode *sandboxNode = ListEntry(node, SandboxMountNode, node);
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)sandboxNode;
    DumpSandboxSection(permissionNode->name, &permissionNode->section);
    APPSPAPWN_DUMP("    gidCount: %{public}u", permissionNode->gidCount);
    for (uint32_t index = 0; index < permissionNode->gidCount; index++) {
        APPSPAPWN_DUMP("    gidTable[%{public}u]: %{public}u", index, permissionNode->gidTable[index]);
    }
    APPSPAPWN_DUMP("    permissionIndex: %{public}u", permissionNode->permissionIndex);
    uint32_t count = 0;
    OH_ListTraversal((ListNode *)&permissionNode->section.front, (void *)&count, DumpSandboxNode, 0);
    return 0;
}

static void DumpSandbox(struct TagAppSpawnExtData *data)
{
    uint32_t count = 0;
    AppSpawnSandboxCfg *sandbox = (AppSpawnSandboxCfg *)data;
    APPSPAPWN_DUMP("Sandbox defaultRootPath: %{public}s", sandbox->defaultRootPath);
    APPSPAPWN_DUMP("Sandbox sandboxNsFlags: %{public}x %{public}x",
        sandbox->sandboxNsFlags[0], sandbox->sandboxNsFlags[1]);
    APPSPAPWN_DUMP("Sandbox topSandboxSwitch: %{public}s", sandbox->topSandboxSwitch ? "true" : "false");
    APPSPAPWN_DUMP("Sandbox appFullMountEnable: %{public}s", sandbox->appFullMountEnable ? "true" : "false");
    APPSPAPWN_DUMP("Sandbox pidNamespaceSupport: %{public}s", sandbox->pidNamespaceSupport ? "true" : "false");
    APPSPAPWN_DUMP("Sandbox common info: ");
    DumpSandboxSection("common", &sandbox->section);
    OH_ListTraversal((ListNode *)&sandbox->section.front, (void *)&count, DumpSandboxNode, 0);

    APPSPAPWN_DUMP("Sandbox private info: ");
    DumpSandboxSection("private", &sandbox->privateNodeQueue);
    OH_ListTraversal((ListNode *)&sandbox->privateNodeQueue.front, (void *)&count, DumpSandboxPrivateNode, 0);

    APPSPAPWN_DUMP("Sandbox permission max: %{public}d info: ", sandbox->permissionMaxIndex);
    DumpSandboxSection("permission", &sandbox->permissionNodeQueue);
    OH_ListTraversal((ListNode *)&sandbox->permissionNodeQueue.front, (void *)&count, DumpSandboxPermissionNode, 0);
}

APPSPAWN_STATIC AppSpawnSandboxCfg *CreateAppSpawnSandbox(void)
{
#ifdef APPSPAWN_TEST
    const char *sandBoxRootDir = APPSPAWN_BASE_DIR "/mnt/sandbox/<PackageName>";
#else
    const char *sandBoxRootDir = "/mnt/sandbox/<PackageName>";
#endif
    size_t rootDirLen = strlen(sandBoxRootDir) + 1;
    // create sandbox
    AppSpawnSandboxCfg *sandbox = (AppSpawnSandboxCfg *)malloc(sizeof(AppSpawnSandboxCfg) + rootDirLen);
    APPSPAWN_CHECK(sandbox != NULL, return NULL, "Failed to create sandbox");
    (void)memset_s(sandbox, sizeof(AppSpawnSandboxCfg), 0, sizeof(AppSpawnSandboxCfg));
    // ext data init
    OH_ListInit(&sandbox->extData.node);
    sandbox->extData.dataId = EXT_DATA_SANDBOX;
    sandbox->extData.freeNode = AppSpawnSandboxFree;
    sandbox->extData.dumpNode = DumpSandbox;

    // queue
    SandboxSectionInit(&sandbox->section, SANDBOX_TAG_COMMON_QUEUE);
    SandboxSectionInit(&sandbox->permissionNodeQueue, SANDBOX_TAG_PERMISSION_QUEUE);
    SandboxSectionInit(&sandbox->privateNodeQueue, SANDBOX_TAG_PRIVATE_QUEUE);
    sandbox->topSandboxSwitch = 0;
    sandbox->appFullMountEnable = 0;
    sandbox->topSandboxSwitch = 0;
    sandbox->pidNamespaceSupport = 0;
    sandbox->sandboxNsFlags[0] = 0;
    sandbox->sandboxNsFlags[1] = 0;
    sandbox->permissionMaxIndex = -1;
    int ret = strcpy_s(sandbox->defaultRootPath, rootDirLen, sandBoxRootDir);
    APPSPAWN_CHECK(ret == 0, free(sandbox); return NULL,
        "Failed to create copy root dir %{public}s", sandBoxRootDir);
    return sandbox;
}

static int LoadSandbox(AppSpawnMgr *content)
{
    AppSpawnSandboxCfg *sandbox = GetAppSpawnSandbox(content);
    APPSPAWN_CHECK(sandbox == NULL, return 0, "Sandbox has been load");
    sandbox = CreateAppSpawnSandbox();
    APPSPAWN_CHECK_ONLY_EXPER(sandbox != NULL, return APPSPAWN_SYSTEM_ERROR);
    OH_ListAddTail(&sandbox->extData.node, &content->extData);

    // load app sandbox config
    LoadAppSandboxConfig(sandbox);
    sandbox->permissionMaxIndex = PermissionRenumber(&sandbox->permissionNodeQueue);

    AddDefaultVariable();
    AddDefaultExpandAppSandboxConfigHandle();

    content->content.sandboxNsFlags = 0;
    if (IsNWebSpawnMode(content) || sandbox->pidNamespaceSupport) {
        content->content.sandboxNsFlags =
            IsNWebSpawnMode(content) ? sandbox->sandboxNsFlags[1] : sandbox->sandboxNsFlags[0];
    }
    return 0;
}

int SandboxConfigSet(AppSpawnMgr *content, AppSpawningCtx *property)
{
    AppSpawnSandboxCfg *appSandBox = GetAppSpawnSandbox(content);
    APPSPAWN_CHECK(appSandBox != NULL, return -1, "Failed to get sandbox for %{public}s", GetProcessName(property));
    // CLONE_NEWPID 0x20000000
    // CLONE_NEWNET 0x40000000
    if ((content->content.sandboxNsFlags & CLONE_NEWPID) == CLONE_NEWPID) {
        int ret = getprocpid();
        if (ret < 0) {
            return ret;
        }
    }
    int ret = SetSandboxConfigs(appSandBox, property, IsNWebSpawnMode(content));
    if (ret != 0) {
        return APPSPAWN_SANDBOX_LOAD_FAIL;
    }
    return 0;
}

MODULE_CONSTRUCTOR(void)
{
    APPSPAWN_LOGV("Load sandbox module ...");
    AddPreloadHook(HOOK_PRIO_SANDBOX, LoadSandbox);
    // fork
    AddAppSpawnHook(HOOK_SPAWN_PREPARE, HOOK_PRIO_SANDBOX, PrepareSandbox);
    AddAppSpawnHook(HOOK_SPAWN_SET_CHILD_PROPERTY, HOOK_PRIO_SANDBOX, SandboxConfigSet);
}
