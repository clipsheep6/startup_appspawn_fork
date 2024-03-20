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

#include "appspawn_sandbox.h"

#include <stdbool.h>
#include <stdlib.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_msg.h"
#include "appspawn_permission.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "securec.h"

#define FILE_CROSS_APP_MODE "ohos.permission.FILE_CROSS_APP"

static void CheckAndCreatFile(const char *file)
{
    if (access(file, F_OK) == 0) {
        APPSPAWN_LOGI("file %{public}s already exist", file);
        return;
    }
    MakeDirRec(file, FILE_MODE, 0);
    int fd = open(file, O_CREAT, FILE_MODE);
    if (fd < 0) {
        APPSPAWN_LOGW("failed create %{public}s, err=%{public}d", file, errno);
    } else {
        close(fd);
    }
    return;
}

static inline int TestMountNodeFlagsPoint(const SandboxContext *context, const PathMountNode *sandboxNode)
{
    if (CheckAppMsgFlagsSet(context->property, APP_FLAGS_BACKUP_EXTENSION) &&
        CHECK_FLAGS_BY_INDEX(sandboxNode->flagsPoint, APP_FLAGS_BACKUP_EXTENSION)) {
        return 1;
    }
    if (CheckAppMsgFlagsSet(context->property, APP_FLAGS_DLP_MANAGER) &&
        CHECK_FLAGS_BY_INDEX(sandboxNode->flagsPoint, APP_FLAGS_DLP_MANAGER)) {
        return 1;
    }
    return 0;
}

static bool CheckBundleNameForPrivate(const char *bundleName)
{
    if (strstr(bundleName, JSON_FLAGS_INTERNAL) != NULL) {
        return false;
    }
    return true;
}

static inline const char *GetRootPathForSandbox(const AppSpawnSandboxCfg *sandbox,
    const SandboxSection *section, uint32_t flags)
{
    if (CHECK_FLAGS_BY_INDEX(flags, APP_FLAGS_BACKUP_EXTENSION)) {
        return section->rootFlagsPath[0] == NULL ? NULL : section->rootFlagsPath[0];
    }
    if (CHECK_FLAGS_BY_INDEX(flags, APP_FLAGS_DLP_MANAGER)) {
        return section->rootFlagsPath[1] == NULL ? NULL : section->rootFlagsPath[1];
    }
    return section->rootPath == NULL ? NULL : section->rootPath;
}

static const char *GetPackagePath(const SandboxContext *sandboxContext)
{
    if (sandboxContext->nwebspawn) {
        size_t len = sprintf_s(sandboxContext->buffer[0].buffer, sandboxContext->buffer[0].bufferLen,
            "%s%s", SANDBOX_NWEBSPAWN_ROOT_PATH, sandboxContext->bundleName);
        APPSPAWN_CHECK(len > 0 && (len < sandboxContext->buffer[0].bufferLen),
            return NULL, "Failed to format path app: %{public}s", sandboxContext->bundleName);
    } else {
        AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)GetAppProperty(sandboxContext->property, TLV_DAC_INFO);
        APPSPAWN_CHECK(dacInfo != NULL, return NULL,
            "No dac info in msg %{public}s", GetProcessName(sandboxContext->property));

        size_t len = sprintf_s(sandboxContext->buffer[0].buffer, sandboxContext->buffer[0].bufferLen,
            "%s%u/%s", SANDBOX_APPSPAWN_ROOT_PATH, dacInfo->uid / UID_BASE, sandboxContext->bundleName);
        APPSPAWN_CHECK(len > 0 && (len < sandboxContext->buffer[0].bufferLen),
            return NULL, "Failed to format path app: %{public}s", sandboxContext->bundleName);
    }
    return sandboxContext->buffer[0].buffer;
}

static void DumpSandboxContext(const SandboxContext *context)
{
    APPSPAWN_LOGV("Sandbox context bundle name: %{public}s", context->bundleName);
    APPSPAWN_LOGV("Sandbox context real root path: %{public}s", context->realRootPath);
    APPSPAWN_LOGV("Sandbox context sandbox package path: %{public}s", context->sandboxPackagePath);
    APPSPAWN_LOGV("Sandbox context default root path: %{public}s", context->defaultRootPath);
    APPSPAWN_LOGV("Sandbox context nwebspawn: %{public}d", context->nwebspawn);
    APPSPAWN_LOGV("Sandbox context sandboxSwitch: %{public}d sandboxShared: %{public}d",
        context->sandboxSwitch, context->sandboxShared);
    APPSPAWN_LOGV("Sandbox context bundleHasWps: %{public}d dlpBundle: %{public}d",
        context->bundleHasWps, context->dlpBundle);
    APPSPAWN_LOGV("Sandbox context appFullMountEnable: %{public}d permissionCfg: %{public}d",
        context->appFullMountEnable, context->permissionCfg);
}

static int AppendPermissionGid(const AppSpawnSandboxCfg *sandbox, AppSpawningCtx *property)
{
    // 根据permission列表，获取gid，加入到gidTable
    AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)GetAppProperty(property, TLV_DAC_INFO);
    APPSPAWN_CHECK(dacInfo != NULL, return APPSPAWN_TLV_NONE,
        "No tlv %{public}d in msg %{public}s", TLV_DAC_INFO, GetProcessName(property));

    ListNode *node = sandbox->permissionNodeQueue.front.next;
    while (node != &sandbox->permissionNodeQueue.front) {
        SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
        if (!CheckAppPermissionFlagSet(property, (uint32_t)permissionNode->permissionIndex)) {
            node = node->next;
            continue;
        }
        if (permissionNode->gidCount == 0) {
            node = node->next;
            continue;
        }
        APPSPAWN_LOGV("Append permission gid %{public}s to %{public}s permission: %{public}u message: %{public}u",
            permissionNode->name, GetProcessName(property), permissionNode->gidCount, dacInfo->gidCount);
        size_t copyLen = permissionNode->gidCount;
        if ((permissionNode->gidCount + dacInfo->gidCount) > APP_MAX_GIDS) {
            APPSPAWN_LOGW("More gid for %{public}s msg count %{public}u permission %{public}u",
                GetProcessName(property), dacInfo->gidCount, permissionNode->gidCount);
            copyLen = APP_MAX_GIDS - dacInfo->gidCount;
        }
        int ret = memcpy_s(&dacInfo->gidTable[dacInfo->gidCount], sizeof(gid_t) * copyLen,
            permissionNode->gidTable, sizeof(gid_t) * copyLen);
        if (ret != EOK) {
            APPSPAWN_LOGW("Failed to append permission %{public}s gid to %{public}s",
                permissionNode->name, GetProcessName(property));
        }
        node = node->next;
    }
    return 0;
}

static int32_t DoDlpAppMountStrategy(const SandboxContext *context, const MountArg *args)
{
    // umount fuse path, make sure that sandbox path is not a mount point
    umount2(args->destinationPath, MNT_DETACH);

    int fd = open("/dev/fuse", O_RDWR);
    APPSPAWN_CHECK(fd != -1, return -EINVAL,
        "open /dev/fuse failed, errno: %{public}d sandbox path %{public}s", errno, args->destinationPath);

    AppSpawnMsgDacInfo *info = (AppSpawnMsgDacInfo *)GetAppProperty(context->property, TLV_DAC_INFO);
    APPSPAWN_CHECK(info != NULL, close(fd); return -APPSPAWN_TLV_NONE,
        "No tlv %{public}d in msg %{public}s", TLV_DAC_INFO, GetProcessName(context->property));

    char options[FUSE_OPTIONS_MAX_LEN];
    (void)sprintf_s(options, sizeof(options), "fd=%d,"
        "rootmode=40000,user_id=%d,group_id=%d,allow_other,"
        "context=\"u:object_r:dlp_fuse_file:s0\","
        "fscontext=u:object_r:dlp_fuse_file:s0", fd, info->uid, info->gid);

    // To make sure destinationPath exist
    MakeDirRecursive(args->destinationPath, FILE_MODE);
    MountArg mountArg = { args->originPath, args->destinationPath, args->fsType, args->mountFlags, options, MS_SHARED};
    int ret = SandboxMountPath(&mountArg);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, close(fd);
        return -1);

    /* close DLP_FUSE_FD and dup FD to it */
    close(DLP_FUSE_FD);
    ret = dup2(fd, DLP_FUSE_FD);
    APPSPAWN_CHECK_ONLY_LOG(ret != -1, "dup fuse fd %{public}d failed, errno: %{public}d", fd, errno);
    return 0;
}

static int GetMountArgs(const SandboxContext *context, const PathMountNode *sandboxNode, MountArg *args)
{
    args->fsType = sandboxNode->fsType;
    args->options = sandboxNode->options;
    args->mountFlags = sandboxNode->mountFlags;
    args->mountSharedFlag = (sandboxNode->mountSharedFlag) ? MS_SHARED : MS_SLAVE;

    if (context->permissionCfg) {
        if (!sandboxNode->dacOverrideSensitive || !context->appFullMountEnable) {
            args->fsType = NULL;
            args->options = NULL;
        }
    } else {
        args->options = NULL;
    }
    if (sandboxNode->dacOverrideSensitive && context->appFullMountEnable && sandboxNode->customizedFlags != 0) {
        args->mountFlags = sandboxNode->customizedFlags;
    }
    return 0;
}

static int CheckSandboxMountNode(const SandboxContext *context,
    const SandboxSection *section, const PathMountNode *sandboxNode)
{
    if (sandboxNode->source == NULL || sandboxNode->target == NULL) {
        APPSPAWN_LOGW("Invalid mount config section %{public}s", context->sandboxSectionName);
        return 0;
    }
    if (sandboxNode->mountFlags == 0 && sandboxNode->customizedFlags == 0) {
        APPSPAWN_LOGW("Invalid mount flags section: %{public}s mountFlags: %{public}u customizedFlags: %{public}u",
            context->sandboxSectionName, (uint32_t)sandboxNode->mountFlags, (uint32_t)sandboxNode->customizedFlags);
        return 0;
    }

    // special handle wps and don't use /data/app/xxx/<Package> config
    if (sandboxNode->isFlagsPoint) { // flags-point
        if (!TestMountNodeFlagsPoint(context, sandboxNode)) { // flags pint not match
            return 0;
        }
        if (context->bundleHasWps &&
            (strstr(sandboxNode->source, "/data/app") != NULL) &&
            (strstr(sandboxNode->source, "/base") != NULL || strstr(sandboxNode->source, "/database") != NULL) &&
            (strstr(sandboxNode->source, PARAMETER_PACKAGE_NAME) != NULL)) {
            APPSPAWN_LOGW("Invalid mount source %{public}s section %{public}s",
                sandboxNode->source, context->sandboxSectionName);
            return 0;
        }
    }
    // check apl
    AppSpawnMsgDomainInfo *msgDomainInfo = (AppSpawnMsgDomainInfo *)GetAppProperty(context->property, TLV_DOMAIN_INFO);
    if (msgDomainInfo != NULL && sandboxNode->appAplName != NULL) {
        if (!strcmp(sandboxNode->appAplName, msgDomainInfo->apl)) {
            APPSPAWN_LOGW("Invalid mount app apl %{public}s %{public}s section %{public}s",
                sandboxNode->appAplName, msgDomainInfo->apl, context->sandboxSectionName);
            return 0;
        }
    }
    return 1;
}

static int DoSandboxMountNode(const SandboxContext *context,
    const SandboxSection *section, const PathMountNode *sandboxNode)
{
    if (CheckSandboxMountNode(context, section, sandboxNode) == 0) {
        return 0;
    }

    MountArg args = {};
    GetMountArgs(context, sandboxNode, &args);
    args.originPath = GetSandboxRealVar(context, 0, sandboxNode->source, NULL, 0);
    args.destinationPath = GetSandboxRealVar(
        context, 1, sandboxNode->target, context->realRootPath, context->permissionCfg);
    APPSPAWN_CHECK(args.originPath != NULL && args.destinationPath != NULL,
        return APPSPAWN_ARG_INVALID, "Invalid path %{public}s %{public}s", args.originPath, args.destinationPath);

    struct stat st = {};
    if (stat(args.originPath, &st) == 0 && S_ISREG(st.st_mode)) {
        CheckAndCreatFile(args.destinationPath);
    } else {
        MakeDirRecursive(args.destinationPath, FILE_MODE);
    }

    /* dlp application mount strategy */
    /* dlp is an example, we should change to real bundle name later */
    int ret = -1;
    if (context->dlpBundle && context->dlpUiExtType == 0 && args.fsType != NULL) {
        APPSPAWN_LOGV("DoDlpAppMountStrategy %{public}s => %{public}s", args.originPath, args.destinationPath);
        ret = DoDlpAppMountStrategy(context, &args);
    }
    if (ret < 0) {
        APPSPAWN_LOGV("Bind path %{public}s => %{public}s", args.originPath, args.destinationPath);
        ret = SandboxMountPath(&args);
    }
    if (ret) {
        if (sandboxNode->checkErrorFlag) {
            APPSPAWN_LOGE("Failed to mount config, section: %{public}s result: %{public}d",
                context->sandboxSectionName, ret);
            return ret;
        }
        APPSPAWN_LOGV("Failed to mount config, section: %{public}s result: %{public}d",
            context->sandboxSectionName, ret);
    }
    if (sandboxNode->destMode != 0) {
        chmod(context->realRootPath, sandboxNode->destMode);
    }
    return 0;
}

static int DoSandboxSymbolLinkNode(const SandboxContext *context,
    const SandboxSection *section, const SymbolLinkNode *sandboxNode)
{
    // Check the validity of the symlink configuration
    if (sandboxNode->linkName == NULL || sandboxNode->target == NULL) {
        APPSPAWN_LOGW("Invalid symlink config, section %{public}s", context->sandboxSectionName);
        return 0;
    }

    const char *target = GetSandboxRealVar(context, 0, sandboxNode->target, NULL, 0);
    const char *linkName = GetSandboxRealVar(context, 1, sandboxNode->linkName, context->realRootPath, 0);
    APPSPAWN_LOGV("symlink, from %{public}s to %{public}s", target, linkName);
    int ret = symlink(target, linkName);
    if (ret && errno != EEXIST) {
        if (sandboxNode->checkErrorFlag) {
            APPSPAWN_LOGE("symlink failed, errno: %{public}d link info %{public}s %{public}s",
                errno, sandboxNode->target, sandboxNode->linkName);
            return errno;
        }
        APPSPAWN_LOGV("symlink failed, errno: %{public}d link info %{public}s %{public}s",
            errno, sandboxNode->target, sandboxNode->linkName);
    }
    if (sandboxNode->destMode != 0) {
        chmod(context->realRootPath, sandboxNode->destMode);
    }
    return 0;
}

static int DoSandboxPathConfigs(const SandboxContext *context, const SandboxSection *section, bool symlinkDo)
{
    APPSPAWN_LOGW("DoSandboxPathConfigs section %{public}s", context->sandboxSectionName);
    ListNode *node = section->front.next;
    while (node != &section->front) {
        int ret = 0;
        SandboxMountNode *sandboxNode = (SandboxMountNode *)ListEntry(node, SandboxMountNode, node);
        switch (sandboxNode->type) {
            case SANDBOX_TAG_MOUNT_PATH:
                ret = DoSandboxMountNode(context, section, (PathMountNode *)sandboxNode);
                break;
            case SANDBOX_TAG_SYMLINK:
                if (!symlinkDo) {
                    break;
                }
                ret = DoSandboxSymbolLinkNode(context, section, (SymbolLinkNode *)sandboxNode);
                break;
            default:
                break;
        }
        if (ret != 0) {
            return ret;
        }
        node = node->next;
    }
    return 0;
}

static int BuildRootPath(SandboxContext *context, const char *rootPath, const char *cfgRoot)
{
    if (context->realRootPath) {
        free(context->realRootPath);
        context->realRootPath = NULL;
    }
    if (rootPath) {
        context->realRootPath = strdup(GetSandboxRealVar(context, 0, rootPath, NULL, 0));
    } else {
        context->realRootPath = strdup(context->defaultRootPath);
    }
    APPSPAWN_CHECK(context->realRootPath != NULL,
        return -1, "Failed to create root path app: %{public}s", context->bundleName);
    context->sandboxSectionName = (char *)cfgRoot;
    APPSPAWN_LOGV("BuildRootPath: %{public}s realRootPath: %{public}s section: '%{public}s'",
        rootPath, context->realRootPath, cfgRoot);
    return 0;
}

static int SetSandboxCommConfig(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    // get default root path
    BuildRootPath((SandboxContext *)context, GetRootPathForSandbox(sandbox, &sandbox->section, 0), "app base");
    // if sandbox switch is off, don't do symlink work again
    bool symlinkDo = context->sandboxSwitch && sandbox->topSandboxSwitch;
    APPSPAWN_LOGV("Set root path: %{public}s section: '%{public}s' symlinkDo: %{public}d",
        context->realRootPath, context->sandboxSectionName, symlinkDo);

    int ret = DoSandboxPathConfigs(context, &sandbox->section, symlinkDo);
    APPSPAWN_CHECK(ret == 0, return ret,
        "Set common config fail result: %{public}d, app: %{public}s", ret, context->bundleName);

    ret = ProcessExpandAppSandboxConfig(context, sandbox, "HspList");
    APPSPAWN_CHECK(ret == 0, return ret,
        "Set HspList config fail result: %{public}d, app: %{public}s", ret, context->bundleName);
    ret = ProcessExpandAppSandboxConfig(context, sandbox, "DataGroup");
    APPSPAWN_CHECK(ret == 0, return ret,
        "Set DataGroup config fail result: %{public}d, app: %{public}s", ret, context->bundleName);

    bool mountDestBundlePath = false;
    AppSpawnMsgDomainInfo *msgDomainInfo = (AppSpawnMsgDomainInfo *)GetAppProperty(context->property, TLV_DOMAIN_INFO);
    if (msgDomainInfo != NULL) {
        mountDestBundlePath = (strcmp(msgDomainInfo->apl, APL_SYSTEM_BASIC) == 0) ||
            (strcmp(msgDomainInfo->apl, APL_SYSTEM_CORE) == 0);
    }
    if (mountDestBundlePath || (CheckAppMsgFlagsSet(context->property, APP_FLAGS_ACCESS_BUNDLE_DIR) != 0)) {
        // need permission check for system app here
        const char *destBundlesPath = GetSandboxRealVar(context, 0, "/data/bundles/", context->sandboxPackagePath, 0);
        MakeDirRecursive(destBundlesPath, FILE_MODE);
        MountArg mountArg = { PHYSICAL_APP_INSTALL_PATH, destBundlesPath, NULL, MS_REC | MS_BIND, NULL, MS_SLAVE };
        ret = SandboxMountPath(&mountArg);
        APPSPAWN_CHECK(ret == 0, return ret, "mount library failed %{public}d", ret);
    }
    return 0;
}

static int SetSandboxPrivateConfig(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    if (!CheckBundleNameForPrivate(context->bundleName)) {
        return 0;
    }
    SandboxPrivateNode *sandboxNode = GetSandboxPrivateNode(sandbox, context->bundleName);
    if (sandboxNode != NULL) {
        // get default root path
        int ret = BuildRootPath((SandboxContext *)context,
            GetRootPathForSandbox(sandbox, &sandboxNode->section, 0), sandboxNode->name);
        APPSPAWN_CHECK(ret == 0,
            return -1, "Failed to create root path app: %{public}s", context->bundleName);
        ret = DoSandboxPathConfigs(context, &sandboxNode->section, true);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }
    return 0;
}

static int SetSandboxPermissionConfig(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    ListNode *node = sandbox->permissionNodeQueue.front.next;
    while (node != &sandbox->permissionNodeQueue.front) {
        SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
        if (!CheckAppPermissionFlagSet(context->property, permissionNode->permissionIndex)) {
            node = node->next;
            continue;
        }

        // get default root path
        int ret = BuildRootPath((SandboxContext *)context,
            GetRootPathForSandbox(sandbox, &permissionNode->section, 0), permissionNode->name);
        APPSPAWN_CHECK(ret == 0,
            return -1, "Failed to create root path app: %{public}s", context->bundleName);
        APPSPAWN_LOGV("SetSandboxPermissionConfig permission %{public}s", permissionNode->name);
        ret = DoSandboxPathConfigs(context, &permissionNode->section, false);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        node = node->next;
    }
    return 0;
}

static int SetSandboxRenderConfig(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    SandboxPrivateNode *sandboxNode = GetSandboxPrivateNode(sandbox, OHOS_RENDER);
    if (sandboxNode != NULL) {
        APPSPAWN_LOGV("SetSandboxRenderConfig name: %s", sandboxNode->name);
        // get default root path
        int ret = BuildRootPath((SandboxContext *)context,
            GetRootPathForSandbox(sandbox, &sandboxNode->section, 0), sandboxNode->name);
        APPSPAWN_CHECK(ret == 0,
            return -1, "Failed to create root path app: %{public}s", context->bundleName);

        ret = DoSandboxPathConfigs(context, &sandboxNode->section, true);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }
    return 0;
}

static int SetOverlayAppSandboxConfig(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    if (!CheckAppMsgFlagsSet(context->property, APP_FLAGS_OVERLAY)) {
        return 0;
    }
    int ret = ProcessExpandAppSandboxConfig(context, sandbox, "Overlay");
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    return 0;
}

static int SetBundleResourceSandboxConfig(const SandboxContext *sandboxContext, const AppSpawnSandboxCfg *sandbox)
{
    if (!CheckAppMsgFlagsSet(sandboxContext->property, APP_FLAGS_BUNDLE_RESOURCES)) {
        return 0;
    }
    const char *destPath = GetSandboxRealVar(sandboxContext,
        0, "/data/storage/bundle_resources/", sandboxContext->sandboxPackagePath, 0);
    MakeDirRecursive(destPath, FILE_MODE);
    MountArg mountArg = {
        "/data/service/el1/public/bms/bundle_resources/", destPath, NULL, MS_REC | MS_BIND, NULL, MS_SLAVE
    };
    int ret = SandboxMountPath(&mountArg);
    return ret;
}

static int32_t ChangeCurrentDir(const SandboxContext *context)
{
    int32_t ret = 0;
    ret = chdir(context->sandboxPackagePath);
    APPSPAWN_CHECK(ret == 0, return ret,
        "chdir failed, app: %{public}s, path: %{public}s errno: %{public}d",
        context->bundleName, context->sandboxPackagePath, errno);

    if (context->sandboxShared) {
        ret = chroot(context->sandboxPackagePath);
        APPSPAWN_CHECK(ret == 0, return ret,
            "chroot failed, path: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
        return ret;
    }

    ret = syscall(SYS_pivot_root, context->sandboxPackagePath, context->sandboxPackagePath);
    APPSPAWN_CHECK(ret == 0, return ret,
        "pivot root failed, path: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
    ret = umount2(".", MNT_DETACH);
    APPSPAWN_CHECK(ret == 0, return ret,
        "MNT_DETACH failed,  path: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
    return ret;
}

static int SandboxRootFolderCreate(const SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    printf("topSandboxSwitch %d sandboxSwitch: %d sandboxShared: %d \n",
        sandbox->topSandboxSwitch, context->sandboxSwitch, context->sandboxShared);

    int ret = 0;
    if (sandbox->topSandboxSwitch == 0 || context->sandboxSwitch == 0) {
        ret = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
        APPSPAWN_CHECK(ret == 0, return ret,
            "set propagation slave failed, app: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
        // bind mount "/" to /mnt/sandbox/<packageName> path
        // rootfs: to do more resources bind mount here to get more strict resources constraints
        ret = mount("/", context->sandboxPackagePath, NULL, BASIC_MOUNT_FLAGS, NULL);
        APPSPAWN_CHECK(ret == 0, return ret,
            "mount bind / failed, app: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
    } else if (!context->sandboxShared) {
        ret = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
        APPSPAWN_CHECK(ret == 0, return ret,
            "set propagation slave failed, app: %{public}s errno: %{public}d", context->sandboxPackagePath, errno);
        MountArg arg = {
            context->sandboxPackagePath, context->sandboxPackagePath, NULL, BASIC_MOUNT_FLAGS, NULL, MS_SLAVE
        };
        ret = SandboxMountPath(&arg);
        APPSPAWN_CHECK(ret == 0, return ret,
            "mount path failed, app: %{public}s errno: %{public}d", context->sandboxPackagePath, ret);
    }
    return ret;
}

static int SetSandboxConfig(SandboxContext *context, const AppSpawnSandboxCfg *sandbox)
{
    // make dir
    MakeDirRecursive(context->sandboxPackagePath, FILE_MODE);
    // add pid to a new mnt namespace
    int ret = unshare(CLONE_NEWNS);
    APPSPAWN_CHECK(ret == 0, return ret,
        "unshare failed, app: %{public}s errno: %{public}d", context->bundleName, errno);

    DumpSandboxContext(context);
    // set root
    ret = SandboxRootFolderCreate(context, sandbox);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    if (!context->nwebspawn) {
        ret = SetSandboxCommConfig(context, sandbox);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

        ret = SetSandboxPrivateConfig(context, sandbox);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

        context->permissionCfg = 1;
        ret = SetSandboxPermissionConfig(context, sandbox);
        context->permissionCfg = 0;
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    } else {
        ret = SetSandboxRenderConfig(context, sandbox);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }

    ret = SetOverlayAppSandboxConfig(context, sandbox);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetBundleResourceSandboxConfig(context, sandbox);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = ChangeCurrentDir(context);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    APPSPAWN_LOGV("Change root dir success");
    return ret;
}

static int SetDefaultSandboxContext(
    const AppSpawningCtx *property, const AppSpawnSandboxCfg *sandbox, SandboxContext *context)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, TLV_MSG_FLAGS);
    APPSPAWN_CHECK(msgFlags != NULL, return APPSPAWN_TLV_NONE,
        "No msg flags in msg %{public}s", GetProcessName(property));

    context->bundleName = GetBundleName(property);
    context->bundleHasWps = strstr(context->bundleName, "wps") != NULL;
    context->dlpBundle = strstr(context->bundleName, "com.ohos.dlpmanager") != NULL;
    context->appFullMountEnable = sandbox->appFullMountEnable;
    context->dlpUiExtType = strstr(GetProcessName(property), "sys/commonUI") != NULL;
    context->permissionCfg = 0;

    context->buffer[0].buffer = NULL;
    context->buffer[1].buffer = NULL;
    context->buffer[0].current = 0;
    context->buffer[1].current = 0;
    context->buffer[0].bufferLen = MAX_SANDBOX_BUFFER;
    context->buffer[1].bufferLen = MAX_SANDBOX_BUFFER;
    char *buffer = (char *)malloc(MAX_SANDBOX_BUFFER + MAX_SANDBOX_BUFFER);
    APPSPAWN_CHECK(buffer != NULL,
        return -1, "Failed to alloc buffer for context app: %{public}s", context->bundleName);
    context->buffer[0].buffer = buffer;
    context->buffer[1].buffer = buffer + MAX_SANDBOX_BUFFER;

    context->sandboxSwitch = 1;
    SandboxPrivateNode *privateNode = GetSandboxPrivateNode(sandbox, context->bundleName);
    if (privateNode != NULL) {
        context->sandboxSwitch = privateNode->section.sandboxSwitch;
        context->sandboxShared = privateNode->section.sandboxShared;
    }
    context->property = property;
    if (context->sandboxPackagePath == NULL) {
        context->sandboxPackagePath = strdup(GetPackagePath(context));
        APPSPAWN_CHECK(context->sandboxPackagePath != NULL,
            return -1, "Failed to dup sandbox package path app: %{public}s", context->bundleName);
    }
    const char *sandBoxRootDir = "/mnt/sandbox/<currentUserId>/<PackageName>";
    if (context->defaultRootPath == NULL) {
        context->defaultRootPath = strdup(GetSandboxRealVar(context, 0, sandBoxRootDir, NULL, 0));
        APPSPAWN_CHECK(context->defaultRootPath != NULL,
            return -1, "Failed to dup sandbox default root path app: %{public}s", context->bundleName);
    }
    return 0;
}

static void FreeSandboxContext(SandboxContext *context)
{
    if (context->buffer[0].buffer) {
        free(context->buffer[0].buffer);
        context->buffer[0].buffer = NULL;
        context->buffer[1].buffer = NULL;
    }
    if (context->sandboxPackagePath) {
        free(context->sandboxPackagePath);
        context->sandboxPackagePath = NULL;
    }
    if (context->defaultRootPath) {
        free(context->defaultRootPath);
        context->defaultRootPath = NULL;
    }
    if (context->realRootPath) {
        free(context->realRootPath);
        context->realRootPath = NULL;
    }
}

int PrepareSandbox(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Prepare sandbox config %{public}s", GetProcessName(property));
    AppSpawnSandboxCfg *sandbox = GetAppSpawnSandbox(content);
    APPSPAWN_CHECK(sandbox != NULL, return -1, "Failed to get sandbox for %{public}s", GetProcessName(property));

    // 添加FILE_CROSS_APP_MODE 权限到app
    if (sandbox->appFullMountEnable) {
        int index = GetPermissionIndexInQueue(&sandbox->permissionNodeQueue, FILE_CROSS_APP_MODE);
        if (index > 0) {
            SetAppPermissionFlags(property, index);
        }
    }
    return AppendPermissionGid(sandbox, property);
}

int SetSandboxConfigs(const AppSpawnSandboxCfg *sandbox, AppSpawningCtx *property, int nwebspawn)
{
    APPSPAWN_LOGV("Set sandbox config %{public}s", GetProcessName(property));
    APPSPAWN_CHECK(sandbox != NULL, return -1, "Failed to get sandbox for %{public}s", GetProcessName(property));
    SandboxContext context = {};
    context.nwebspawn = nwebspawn;
    SetDefaultSandboxContext(property, sandbox, &context);
    int ret = SetSandboxConfig(&context, sandbox);
    FreeSandboxContext(&context);

    // for module test do not create sandbox
    if (strncmp(GetBundleName(property), MODULE_TEST_BUNDLE_NAME, strlen(MODULE_TEST_BUNDLE_NAME)) == 0) {
        return 0;
    }
    return ret;
}
