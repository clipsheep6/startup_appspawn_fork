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
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/types.h>

#include "appspawn_msg.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "cJSON.h"
#include "json_utils.h"
#include "parameter.h"
#include "securec.h"

static const char *APP_BASE = "app-base";
static const char *APP_RESOURCE = "app-resources";
static const char *COMM_PREFIX = "common";
static const char *MOUNT_PREFIX = "mount-paths";
static const char *PRIVATE_PREFIX = "individual";
static const char *PERMISSION_PREFIX = "permission";
static const char *SANDBOX_SHARED = "sandbox-shared";
static const char *SANDBOX_SWITCH = "sandbox-switch";
static const char *SYMLINK_PREFIX = "symbol-links";
static const char *SANDBOX_ROOT = "sandbox-root";
static const char *SANDBOX_NS_FLAGS = "sandbox-ns-flags";

typedef struct {
    const char *name;
    unsigned long flags;
} SandboxFlagInfo;

static const SandboxFlagInfo MOUNT_FLAGS_MAP[] = {
    {"rec", MS_REC}, {"MS_REC", MS_REC},
    {"bind", MS_BIND}, {"MS_BIND", MS_BIND}, {"move", MS_MOVE}, {"MS_MOVE", MS_MOVE},
    {"slave", MS_SLAVE}, {"MS_SLAVE", MS_SLAVE}, {"rdonly", MS_RDONLY}, {"MS_RDONLY", MS_RDONLY},
    {"shared", MS_SHARED}, {"MS_SHARED", MS_SHARED}, {"unbindable", MS_UNBINDABLE},
    {"MS_UNBINDABLE", MS_UNBINDABLE}, {"remount", MS_REMOUNT}, {"MS_REMOUNT", MS_REMOUNT},
    {"nosuid", MS_NOSUID}, {"MS_NOSUID", MS_NOSUID}, {"nodev", MS_NODEV}, {"MS_NODEV", MS_NODEV},
    {"noexec", MS_NOEXEC}, {"MS_NOEXEC", MS_NOEXEC}, {"noatime", MS_NOATIME}, {"MS_NOATIME", MS_NOATIME},
    {"lazytime", MS_LAZYTIME}, {"MS_LAZYTIME", MS_LAZYTIME}
};

static const SandboxFlagInfo PATH_MODE_MAP[] = {
    {"S_IRUSR", S_IRUSR}, {"S_IWUSR", S_IWUSR}, {"S_IXUSR", S_IXUSR},
    {"S_IRGRP", S_IRGRP}, {"S_IWGRP", S_IWGRP}, {"S_IXGRP", S_IXGRP},
    {"S_IROTH", S_IROTH}, {"S_IWOTH", S_IWOTH}, {"S_IXOTH", S_IXOTH},
    {"S_IRWXU", S_IRWXU}, {"S_IRWXG", S_IRWXG}, {"S_IRWXO", S_IRWXO}
};

static const SandboxFlagInfo NAMESPACE_FLAGS_MAP[] = {
    {"pid", CLONE_NEWPID}, {"net", CLONE_NEWNET}
};

static const SandboxFlagInfo FLAGE_POINT_MAP[] = {
    {"0", 0},
    {"START_FLAGS_BACKUP", (unsigned long)APP_FLAGS_BACKUP_EXTENSION},
    {"DLP_MANAGER", (unsigned long)APP_FLAGS_DLP_MANAGER}
};

static inline bool GetBoolParameter(const char *param, bool value)
{
    char tmp[32] = {0};  // 32 max
    int ret = GetParameter(param, "", tmp, sizeof(tmp));
    APPSPAWN_LOGV("GetBoolParameter key %{public}s ret %{public}d result: %{public}s", param, ret, tmp);
    return (ret > 0 && (strcmp(tmp, "true") == 0 || strcmp(tmp, "on") == 0 || strcmp(tmp, "1") == 0));
}

static bool AppSandboxPidNsIsSupport(void)
{
    return GetBoolParameter("const.sandbox.pidns.support", true);
}

static bool CheckAppFullMountEnable(void)
{
    return GetBoolParameter("const.filemanager.full_mount.enable", false);
}

static inline const SandboxFlagInfo *GetSandboxFlagInfo(const char *key,
    const SandboxFlagInfo *flagsInfos, uint32_t count)
{
    APPSPAWN_CHECK_ONLY_EXPER(key != NULL && flagsInfos != NULL, return NULL);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(flagsInfos[i].name, key) == 0) {
            return &flagsInfos[i];
        }
    }
    return NULL;
}

static void DumpSandboxFlags(char *buffer, uint32_t bufferSize, unsigned long flags,
    const SandboxFlagInfo *flagsInfos, uint32_t count)
{
    bool first = true;
    size_t currLen = 0;
    int len = 0;
    unsigned long tmp = flags;
    for (uint32_t i = 0; i < count; i++) {
        if ((flagsInfos[i].flags & tmp) == 0) {
            continue;
        }
        tmp &= ~(flagsInfos[i].flags);
        if (!first) {
            len = sprintf_s(buffer + currLen, bufferSize - currLen, " %s ", "|");
            APPSPAWN_CHECK_ONLY_EXPER(len > 0, return);
            currLen += len;
        }
        first = false;
        len = sprintf_s(buffer + currLen, bufferSize - currLen, "%s", flagsInfos[i].name);
        APPSPAWN_CHECK_ONLY_EXPER(len > 0, return);
        currLen += len;
    }
}

static unsigned long GetMountFlagsFromConfig(const cJSON *config, const char *key, unsigned long def)
{
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(config, key);
    if (obj == NULL || !cJSON_IsArray(obj)) {
        return def;
    }
    unsigned long mountFlags = 0;
    int count = cJSON_GetArraySize(obj);
    for (int i = 0; i < count; i++) {
        char *value = cJSON_GetStringValue(cJSON_GetArrayItem(obj, i));
        const SandboxFlagInfo *info = GetSandboxFlagInfo(value, MOUNT_FLAGS_MAP, ARRAY_LENGTH(MOUNT_FLAGS_MAP));
        if (info != NULL) {
            mountFlags |= info->flags;
        }
    }
    return mountFlags;
}

static uint32_t GetSandboxNsFlags(const cJSON *appConfig)
{
    uint32_t nsFlags = 0;
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(appConfig, SANDBOX_NS_FLAGS);
    if (obj == NULL || !cJSON_IsArray(obj)) {
        return nsFlags;
    }
    int count = cJSON_GetArraySize(obj);
    for (int i = 0; i < count; i++) {
        char *value = cJSON_GetStringValue(cJSON_GetArrayItem(obj, i));
        const SandboxFlagInfo *info = GetSandboxFlagInfo(value, NAMESPACE_FLAGS_MAP, ARRAY_LENGTH(NAMESPACE_FLAGS_MAP));
        if (info != NULL) {
            nsFlags |= info->flags;
        }
    }
    return nsFlags;
}

static int HandleModeString(const char *str, void *context)
{
    mode_t *mode = (mode_t *)context;
    const SandboxFlagInfo *info = GetSandboxFlagInfo(str, PATH_MODE_MAP, ARRAY_LENGTH(PATH_MODE_MAP));
    if (info != NULL) {
        *mode |= info->flags;
    }
    return 0;
}

static mode_t GetChmodFromJson(const cJSON *config)
{
    mode_t mode = 0;
    char *modeStrs = GetStringFromJsonObj(config, "dest-mode");
    if (modeStrs == NULL) {
        return mode;
    }
    (void)StringSplit(modeStrs, "|", (void *)&mode, HandleModeString);
    return mode;
}

static uint32_t GetFlagsFromJson(const cJSON *config)
{
    char *flagStr = GetStringFromJsonObj(config, "flags");
    const SandboxFlagInfo *info = GetSandboxFlagInfo(flagStr, FLAGE_POINT_MAP, ARRAY_LENGTH(FLAGE_POINT_MAP));
    if (info != NULL) {
        return 1 << info->flags;
    }
    return 0;
}

static inline cJSON *GetFirstJson(const cJSON *config)
{
    if (config == NULL || !cJSON_IsArray(config)) {
        return NULL;
    }
    return cJSON_GetArrayItem(config, 0);
}

static PathMountNode *DecodeMountPathConfig(const cJSON *config)
{
    char *srcPath = GetStringFromJsonObj(config, "src-path");
    char *dstPath = GetStringFromJsonObj(config, "sandbox-path");
    if (srcPath == NULL || dstPath == NULL) {
        return NULL;
    }

    PathMountNode *sandboxNode = CreatePathMountNode();
    APPSPAWN_CHECK_ONLY_EXPER(sandboxNode != NULL, return NULL);
    sandboxNode->source = strdup(srcPath);
    sandboxNode->target = strdup(dstPath);

    sandboxNode->mountFlags = GetMountFlagsFromConfig(config, "sandbox-flags", 0);
    sandboxNode->customizedFlags = GetMountFlagsFromConfig(config, "sandbox-flags-customized", 0);
    sandboxNode->destMode = GetChmodFromJson(config);
    sandboxNode->mountSharedFlag = GetBoolValueFromJsonObj(config, "mount-shared-flag", false);
    sandboxNode->checkErrorFlag = GetBoolValueFromJsonObj(config, "check-action-status", false);
    sandboxNode->dacOverrideSensitive = GetBoolValueFromJsonObj(config, "dac-override-sensitive", false);
    const char *value = GetStringFromJsonObj(config, "options");
    if (value != NULL) {
        sandboxNode->options = strdup(value);
    }
    value = GetStringFromJsonObj(config, "fs-type");
    if (value != NULL) {
        sandboxNode->fsType = strdup(value);
    }
    value = GetStringFromJsonObj(config, "app-apl-name");
    if (value != NULL) {
        sandboxNode->appAplName = strdup(value);
    }
    return sandboxNode;
}

static int DecodeMountPathsConfig(AppSpawnSandbox *sandbox,
    const cJSON *mountConfigs, uint32_t flagsPoint, SandboxSection *section)
{
    APPSPAWN_CHECK_ONLY_EXPER(mountConfigs != NULL && cJSON_IsArray(mountConfigs), return -1);
    uint32_t mountPointSize = cJSON_GetArraySize(mountConfigs);
    for (uint32_t i = 0; i < mountPointSize; i++) {
        cJSON *mntJson = cJSON_GetArrayItem(mountConfigs, i);
        PathMountNode *sandboxNode = DecodeMountPathConfig(mntJson);
        APPSPAWN_CHECK_ONLY_EXPER(sandboxNode != NULL, continue);
        sandboxNode->flagsPoint = flagsPoint;
        sandboxNode->isFlagsPoint = (flagsPoint & APP_FLAGS_SECTION) == APP_FLAGS_SECTION;
        AddPathNode(&sandboxNode->sandboxNode, section);
    }
    return 0;
}

static int DecodeSymbolLinksConfig(AppSpawnSandbox *sandbox,
    const cJSON *symbolLinkConfigs, uint32_t flagsPoint, SandboxSection *section)
{
    APPSPAWN_CHECK_ONLY_EXPER(symbolLinkConfigs != NULL && cJSON_IsArray(symbolLinkConfigs), return -1);
    uint32_t symlinkPointSize = cJSON_GetArraySize(symbolLinkConfigs);
    for (uint32_t i = 0; i < symlinkPointSize; i++) {
        cJSON *symConfig = cJSON_GetArrayItem(symbolLinkConfigs, i);
        const char *target = GetStringFromJsonObj(symConfig, "target-name");
        const char *linkName = GetStringFromJsonObj(symConfig, "link-name");
        if (target == NULL || linkName == NULL) {
            continue;
        }

        SymbolLinkNode *node = CreateSymbolLinkNode();
        APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);
        node->destMode = GetChmodFromJson(symConfig);
        node->checkErrorFlag = GetBoolValueFromJsonObj(symConfig, "check-action-status", false);
        node->target = strdup(target);
        node->linkName = strdup(linkName);
        AddPathNode(&node->sandboxNode, section);
    }
    return 0;
}

static void SandboxSectionSetRootPath(AppSpawnSandbox *sandbox,
    SandboxSection *section, const cJSON *configs, uint32_t flags)
{
    // only compare with defaultRootPath
    const char *sandboxRoot = GetStringFromJsonObj(configs, SANDBOX_ROOT);
    if (sandboxRoot != NULL && strcmp(sandboxRoot, sandbox->defaultRootPath) == 0) {
        sandboxRoot = NULL;
    }
    char **rootPath = NULL;
    if (CHECK_FLAGS_BY_INDEX(flags, APP_FLAGS_BACKUP_EXTENSION)) {
        rootPath = &section->rootFlagsPath[0];
    } else if (CHECK_FLAGS_BY_INDEX(flags, APP_FLAGS_DLP_MANAGER)) {
        rootPath = &section->rootFlagsPath[1];
    } else {
        rootPath = &section->rootPath;
    }
    if (*rootPath != NULL) {
        APPSPAWN_LOGW("Root path has been set %{public}s new %{public}s ", *rootPath, sandboxRoot);
        free(*rootPath);
        *rootPath = NULL;
    }

    *rootPath = sandboxRoot == NULL ? NULL : strdup(sandboxRoot);
    APPSPAWN_LOGV("SandboxSectionSetRootPath %{public}s ", *rootPath);
    return;
}

static int ParseBaseConfig(AppSpawnSandbox *sandbox,
    const cJSON *configs, SandboxSection *section, const char *configName)
{
    int ret = 0;
    cJSON *pathConfigs = cJSON_GetObjectItemCaseSensitive(configs, MOUNT_PREFIX);
    if (pathConfigs != NULL) {  // mount-paths
        ret = DecodeMountPathsConfig(sandbox, pathConfigs, 0, section);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);
    }
    pathConfigs = cJSON_GetObjectItemCaseSensitive(configs, SYMLINK_PREFIX);
    if (pathConfigs != NULL) {  // symbol-links
        ret = DecodeSymbolLinksConfig(sandbox, pathConfigs, 0, section);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }
    // flags-point
    cJSON *flagsConfigs = cJSON_GetObjectItemCaseSensitive(configs, "flags-point");
    APPSPAWN_CHECK_ONLY_EXPER(flagsConfigs != NULL, return 0);
    APPSPAWN_CHECK(cJSON_IsArray(flagsConfigs), return -1, "Invalid flags point json");

    uint32_t flagsSize = cJSON_GetArraySize(flagsConfigs);
    for (uint32_t i = 0; i < flagsSize; i++) {
        cJSON *flagsConfig = cJSON_GetArrayItem(flagsConfigs, i);
        uint32_t flagsPoint = GetFlagsFromJson(flagsConfig);
        flagsPoint |= APP_FLAGS_SECTION;
        SandboxSectionSetRootPath(sandbox, section, flagsConfig, flagsPoint);

        pathConfigs = cJSON_GetObjectItemCaseSensitive(flagsConfig, MOUNT_PREFIX);
        if (pathConfigs != NULL) {  // mount-paths
            ret = DecodeMountPathsConfig(sandbox, pathConfigs, flagsPoint, section);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);
        }
        pathConfigs = cJSON_GetObjectItemCaseSensitive(flagsConfig, SYMLINK_PREFIX);
        if (pathConfigs != NULL) {  // symbol-links
            ret = DecodeSymbolLinksConfig(sandbox, pathConfigs, flagsPoint, section);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        }
    }
    return 0;
}

static int ParseCommConfig(AppSpawnSandbox *sandbox, const cJSON *commonConfig)
{
    int ret = 0;
    // "top-sandbox-switch": "ON", default sandbox switch is on
    if (sandbox->topSandboxSwitch == 0) {
        sandbox->topSandboxSwitch = GetBoolValueFromJsonObj(commonConfig, "top-sandbox-switch", true);
    }

    // app-base
    cJSON *appBaseConfig = GetFirstJson(cJSON_GetObjectItemCaseSensitive(commonConfig, APP_BASE));
    if (appBaseConfig != NULL) {
        sandbox->sandboxNsFlags[0] = GetSandboxNsFlags(appBaseConfig);
        APPSPAWN_LOGV("Load app base sandboxNsFlags '%{public}x' ", sandbox->sandboxNsFlags[0]);
        SandboxSectionSetRootPath(sandbox, &sandbox->section, appBaseConfig, 0);
        ret = ParseBaseConfig(sandbox, appBaseConfig, &sandbox->section, APP_BASE);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }
    // app-resources
    cJSON *appResourceConfig = GetFirstJson(cJSON_GetObjectItemCaseSensitive(commonConfig, APP_RESOURCE));
    if (appResourceConfig != NULL) {
        SandboxSectionSetRootPath(sandbox, &sandbox->section, appResourceConfig, 0);
        ret = ParseBaseConfig(sandbox, appResourceConfig, &sandbox->section, APP_RESOURCE);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    }
    return ret;
}

static int ParsePrivateConfig(AppSpawnSandbox *sandbox, const cJSON *privateConfigs)
{
    int ret = 0;
    cJSON *config = NULL;
    cJSON_ArrayForEach(config, privateConfigs) {
        const char *name = config->string;
        APPSPAWN_LOGV("ParsePrivateConfig %{public}s", name);
        cJSON *json = GetFirstJson(config);
        APPSPAWN_CHECK(json != NULL, return -1, "No config for private %{public}s", name);

        SandboxPrivateNode *node = CreateSandboxPrivateNode(name);
        APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);

        if (strcmp(OHOS_RENDER, name) == 0) {  // nweb namespace flags
            sandbox->sandboxNsFlags[1] = GetSandboxNsFlags(json);
        }
        // "sandbox-switch": "ON", default sandbox switch is on
        node->section.sandboxSwitch = GetBoolValueFromJsonObj(json, SANDBOX_SWITCH, true);
        // "sandbox-shared"
        node->section.sandboxShared = GetBoolValueFromJsonObj(json, SANDBOX_SHARED, false);
        SandboxSectionSetRootPath(sandbox, &node->section, json, 0);

        ret = ParseBaseConfig(sandbox, json, &node->section, name);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        // success, insert section
        AddPathNode(&node->sandboxNode, &sandbox->privateNodeQueue);
    }
    return 0;
}

static int ParsePermissionConfig(AppSpawnSandbox *sandbox, const cJSON *permissionConfigs)
{
    uint32_t gidTable[APP_MAX_GIDS] = {};
    int ret = 0;
    cJSON *config = NULL;
    cJSON_ArrayForEach(config, permissionConfigs) {
        const char *name = config->string;
        APPSPAWN_LOGV("ParsePermissionConfig %{public}s", name);
        cJSON *json = GetFirstJson(config);
        APPSPAWN_CHECK(json != NULL, return -1, "No config for private %{public}s", name);

        uint32_t gidCount = GetUint32ArrayFromJson(json, "gids", gidTable, APP_MAX_GIDS);

        SandboxPermissionNode *node = CreateSandboxPermissionNode(name, gidCount, gidTable);
        APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);

        // "sandbox-switch": "ON",
        node->section.sandboxSwitch = GetBoolValueFromJsonObj(json, SANDBOX_SWITCH, false);
        // "sandbox-shared"
        node->section.sandboxShared = GetBoolValueFromJsonObj(json, SANDBOX_SHARED, false);
        SandboxSectionSetRootPath(sandbox, &node->section, json, 0);

        ret = ParseBaseConfig(sandbox, json, &node->section, name);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        // success, insert section
        AddPathNode(&node->sandboxNode, &sandbox->permissionNodeQueue);
    }
    return 0;
}

APPSPAWN_STATIC int ParseAppSandboxConfig(const cJSON *appSandboxConfig, AppSpawnSandbox *sandbox)
{
    int ret = 0;
    cJSON *json = GetFirstJson(cJSON_GetObjectItemCaseSensitive(appSandboxConfig, COMM_PREFIX));
    if (json != NULL) {
        ret = ParseCommConfig(sandbox, json);
        APPSPAWN_CHECK(ret == 0, return ret, "Load common config fail result: %{public}d ", ret);
    }
    json = GetFirstJson(cJSON_GetObjectItemCaseSensitive(appSandboxConfig, PRIVATE_PREFIX));
    if (json != NULL) {
        ret = ParsePrivateConfig(sandbox, json);
        APPSPAWN_CHECK(ret == 0, return ret, "Load private config fail result: %{public}d ", ret);
    }
    json = GetFirstJson(cJSON_GetObjectItemCaseSensitive(appSandboxConfig, PERMISSION_PREFIX));
    if (json != NULL) {
        ret = ParsePermissionConfig(sandbox, json);
        APPSPAWN_CHECK(ret == 0, return ret, "Load permission config fail result: %{public}d ", ret);
    }
    return ret;
}

int LoadAppSandboxConfig(AppSpawnSandbox *sandbox)
{
    int ret = ParseSandboxConfig("etc/sandbox", "/appdata-sandbox.json", ParseAppSandboxConfig, sandbox);
    if (ret == APPSPAWN_SANDBOX_NONE) {
        APPSPAWN_LOGW("No sandbox config");
        ret = 0;
    }
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    sandbox->pidNamespaceSupport = AppSandboxPidNsIsSupport();
    sandbox->appFullMountEnable = CheckAppFullMountEnable();
    APPSPAWN_LOGI("Sandbox pidNamespaceSupport: %{public}d appFullMountEnable: %{public}d",
        sandbox->pidNamespaceSupport, sandbox->appFullMountEnable);
    return 0;
}

void DumpMountFlags(const char *info, unsigned long mountFlags)
{
    char buffer[128] = {0};  // 64 to show flags
    DumpSandboxFlags(buffer, sizeof(buffer), mountFlags, MOUNT_FLAGS_MAP, ARRAY_LENGTH(MOUNT_FLAGS_MAP));
    APPSPAPWN_DUMP("%{public}s[0x%{public}x] %{public}s", info, (uint32_t)(mountFlags), buffer);
}

void DumpMode(const char *info, mode_t mode)
{
    char buffer[64] = {0};  // 64 to show flags
    DumpSandboxFlags(buffer, sizeof(buffer), mode, PATH_MODE_MAP, ARRAY_LENGTH(PATH_MODE_MAP));
    APPSPAPWN_DUMP("%{public}s[0x%{public}x] %{public}s", info, (uint32_t)(mode), buffer);
}
