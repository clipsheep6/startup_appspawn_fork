/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sandbox.h"

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include "beget_ext.h"
#include "init_utils.h"
#include "cJSON.h"
#include "sandbox_namespace.h"
#include "securec.h"

#define SANDBOX_ROOT_TAG "sandbox-root"
#define SANDBOX_MOUNT_PATH_TAG "mount-bind-paths"
#define SANDBOX_MOUNT_FILE_TAG "mount-bind-files"
#define SANDBOX_SOURCE "src-path"
#define SANDBOX_TARGET "sandbox-path"
#define SANDBOX_FLAGS "sandbox-flags"
#define SANDBOX_SYMLINK_TAG "symbol-links"
#define SANDBOX_SYMLINK_TARGET "target-name"
#define SANDBOX_SYMLINK_NAME "link-name"

#ifndef SUPPORT_64BIT
#define SANDBOX_SYSTEM_CONFIG_FILE "/system/etc/sandbox/system-sandbox.json"
#define SANDBOX_CHIPSET_CONFIG_FILE "/system/etc/sandbox/chipset-sandbox.json"
#else
#define SANDBOX_SYSTEM_CONFIG_FILE "/system/etc/sandbox/system-sandbox64.json"
#define SANDBOX_CHIPSET_CONFIG_FILE "/system/etc/sandbox/chipset-sandbox64.json"
#endif

#define SANDBOX_MOUNT_FLAGS_MS_BIND "bind"
#define SANDBOX_MOUNT_FLAGS_MS_PRIVATE "private"
#define SANDBOX_MOUNT_FLAGS_MS_REC "rec"
#define SANDBOX_MOUNT_FLAGS_MS_MOVE "move"

typedef enum SandboxTag {
    SANDBOX_TAG_MOUNT_PATH = 0,
    SANDBOX_TAG_MOUNT_FILE,
    SANDBOX_TAG_SYMLINK
} SandboxTag;

struct SandboxMountFlags {
    const char *flag;
    unsigned long value;
};

static const struct SandboxMountFlags g_flags[] = {
    {
        .flag = "bind",
        .value = MS_BIND,
    },
    {
        .flag = "private",
        .value = MS_PRIVATE,
    },
    {
        .flag = "rec",
        .value = MS_REC,
    },
    {
        .flag = "move",
        .value = MS_MOVE,
    }
};

static sandbox_t g_systemSandbox;
static sandbox_t g_chipsetSandbox;

struct SandboxMap {
    const char *name;
    sandbox_t *sandbox;
    const char *configfile;
};

static const struct SandboxMap g_map[] = {
    {
        .name = "system",
        .sandbox = &g_systemSandbox,
        .configfile = SANDBOX_SYSTEM_CONFIG_FILE,
    },
    {
        .name = "chipset",
        .sandbox = &g_chipsetSandbox,
        .configfile = SANDBOX_CHIPSET_CONFIG_FILE,
    }
};

static unsigned long GetSandboxMountFlags(cJSON *item)
{
    BEGET_ERROR_CHECK(item != NULL, return 0, "Invalid parameter.");
    char *str = cJSON_GetStringValue(item);
    if (str == NULL) {
        return 0;
    }
    for (size_t i = 0; i < ARRAY_LENGTH(g_flags); i++) {
        if (strcmp(str, g_flags[i].flag) == 0) {
            return g_flags[i].value;
        }
    }
    return 0;
}

typedef int (*AddInfoToSandboxCallback)(sandbox_t *sandbox, cJSON *item, const char *type);

static int AddMountInfoToSandbox(sandbox_t *sandbox, cJSON *item, const char *type)
{
    if (sandbox == NULL || item == NULL || type == NULL) {
        return -1;
    }
    char *srcPath = cJSON_GetStringValue(cJSON_GetObjectItem(item, SANDBOX_SOURCE));
    BEGET_ERROR_CHECK(srcPath != NULL, return 0, "Get src-path is null");
    char *dstPath = cJSON_GetStringValue(cJSON_GetObjectItem(item, SANDBOX_TARGET));
    BEGET_ERROR_CHECK(dstPath != NULL, return 0, "Get sandbox-path is null");
    cJSON *obj = cJSON_GetObjectItem(item, SANDBOX_FLAGS);
    BEGET_ERROR_CHECK(obj != NULL, return 0, "Get sandbox-flags is null");
    int ret = cJSON_IsArray(obj);
    BEGET_ERROR_CHECK(ret, return 0, "Sandbox-flags is not array");
    int count = cJSON_GetArraySize(obj);
    BEGET_ERROR_CHECK(count > 0, return 0, "Get sandbox-flags array size is zero");
    mountlist_t *tmpMount = (mountlist_t *)calloc(1, sizeof(mountlist_t));
    BEGET_ERROR_CHECK(tmpMount != NULL, return -1, "Failed calloc err=%d", errno);
    tmpMount->info = (mount_t *)calloc(1, sizeof(mount_t));
    BEGET_ERROR_CHECK(tmpMount->info != NULL, free(tmpMount); return -1, "Failed calloc err=%d", errno);
    tmpMount->info->source = strdup(srcPath);
    tmpMount->info->target = strdup(dstPath);
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(obj, i);
        tmpMount->info->flags |= GetSandboxMountFlags(item);
    }
    if (strcmp(type, SANDBOX_MOUNT_PATH_TAG) == 0) {
        if (sandbox->pathMounts == NULL) {
            sandbox->pathMounts = tmpMount;
            tmpMount->next = NULL;
        } else {
            tmpMount->next = sandbox->pathMounts->next;
            sandbox->pathMounts->next = tmpMount;
        }
    } else if (strcmp(type, SANDBOX_MOUNT_FILE_TAG) == 0) {
        if (sandbox->fileMounts == NULL) {
            sandbox->fileMounts = tmpMount;
            tmpMount->next = NULL;
        } else {
            tmpMount->next = sandbox->fileMounts->next;
            sandbox->fileMounts->next = tmpMount;
        }
    }
    return 0;
}

static int AddSymbolLinksToSandbox(sandbox_t *sandbox, cJSON *item, const char *type)
{
    if (sandbox == NULL || item == NULL || type == NULL) {
        return -1;
    }
    if (strcmp(type, SANDBOX_SYMLINK_TAG) != 0) {
        BEGET_LOGE("Type is not sandbox symbolLink.");
        return -1;
    }
    char *target = cJSON_GetStringValue(cJSON_GetObjectItem(item, SANDBOX_SYMLINK_TARGET));
    BEGET_ERROR_CHECK(target != NULL, return 0, "Get target-name is null");
    char *name = cJSON_GetStringValue(cJSON_GetObjectItem(item, SANDBOX_SYMLINK_NAME));
    BEGET_ERROR_CHECK(name != NULL, return 0, "Get link-name is null");
    linklist_t *tmpLink = (linklist_t *)calloc(1, sizeof(linklist_t));
    BEGET_ERROR_CHECK(tmpLink != NULL, return -1, "Failed calloc err=%d", errno);
    tmpLink->info = (linker_t *)calloc(1, sizeof(linker_t));
    BEGET_ERROR_CHECK(tmpLink->info != NULL, free(tmpLink); return -1, "Failed calloc err=%d", errno);
    tmpLink->info->target = strdup(target);
    tmpLink->info->linkName = strdup(name);
    if (sandbox->links == NULL) {
        sandbox->links = tmpLink;
        tmpLink->next = NULL;
    } else {
        tmpLink->next = sandbox->links->next;
        sandbox->links->next = tmpLink;
    }
    return 0;
}

static int GetSandboxInfo(sandbox_t *sandbox, cJSON *root, const char *itemName)
{
    if (sandbox == NULL || root == NULL || itemName == NULL) {
        BEGET_LOGE("Get sandbox mount info with invalid argument");
        return -1;
    }
    cJSON *obj = cJSON_GetObjectItem(root, itemName);
    if (obj == NULL) {
        BEGET_LOGE("Cannot find item \' %s \' in sandbox config", itemName);
        return 0;
    }
    if (!cJSON_IsArray(obj)) {
        BEGET_LOGE("%s with invalid type, should be array", itemName);
        return 0;
    }

    int counts = cJSON_GetArraySize(obj);
    if (counts <= 0) {
        BEGET_LOGE("Item %s array size is zero.", itemName);
        return 0;
    }
    AddInfoToSandboxCallback func = NULL;
    if (strcmp(itemName, SANDBOX_MOUNT_PATH_TAG) == 0) {
        func = AddMountInfoToSandbox;
    } else if (strcmp(itemName, SANDBOX_MOUNT_FILE_TAG) == 0) {
        func = AddMountInfoToSandbox;
    } else if (strcmp(itemName, SANDBOX_SYMLINK_TAG) == 0) {
        func = AddSymbolLinksToSandbox;
    } else {
        BEGET_LOGE("%s item name is not support.", itemName);
        return -1;
    }
    for (int i = 0; i < counts; i++) {
        cJSON *item = cJSON_GetArrayItem(obj, i);
        BEGET_ERROR_CHECK(item != NULL, return -1, "Failed get json array item %d", i);
        if (func(sandbox, item, itemName) < 0) {
            BEGET_LOGE("Failed add info to sandbox.");
            return -1;
        }
    }
    return 0;
}

static int ParseSandboxConfig(sandbox_t *sandbox, const char *sandboxConfig)
{
    if (sandbox == NULL || sandboxConfig == NULL) {
        BEGET_LOGE("Parse sandbox config with invalid argument");
        return -1;
    }
    char *contents = ReadFileToBuf(sandboxConfig);
    if (contents == NULL) {
        return -1;
    }
    cJSON *root = cJSON_Parse(contents);
    if (root == NULL) {
        BEGET_LOGE("Parse sandbox config \' %s \' failed", sandboxConfig);
        return -1;
    }
    cJSON *sandboxRoot = cJSON_GetObjectItem(root, SANDBOX_ROOT_TAG);
    if (sandboxRoot == NULL) {
        BEGET_LOGE("Cannot find item \' %s \' in sandbox config", SANDBOX_ROOT_TAG);
        cJSON_Delete(root);
        return -1;
    }
    char *rootdir = cJSON_GetStringValue(sandboxRoot);
    if (rootdir != NULL) {
        sandbox->rootPath = strdup(rootdir);
        if (sandbox->rootPath == NULL) {
            BEGET_LOGE("Get sandbox root path out of memory");
            cJSON_Delete(root);
            return -1;
        }
    }
    BEGET_LOGI("config file %s", sandboxConfig);
    if (GetSandboxInfo(sandbox, root, SANDBOX_MOUNT_PATH_TAG) < 0) {
        BEGET_LOGE("config file %s, SANDBOX_MOUNT_PATH_TAG error", sandboxConfig);
        cJSON_Delete(root);
        return -1;
    }
    if (GetSandboxInfo(sandbox, root, SANDBOX_MOUNT_FILE_TAG) < 0) {
        BEGET_LOGE("config file %s, SANDBOX_MOUNT_FILE_TAG error", sandboxConfig);
        cJSON_Delete(root);
        return -1;
    }
    if (GetSandboxInfo(sandbox, root, SANDBOX_SYMLINK_TAG) < 0) {
        BEGET_LOGE("config file %s, SANDBOX_SYMLINK_TAG error", sandboxConfig);
        cJSON_Delete(root);
        return -1;
    }
    cJSON_Delete(root);
    return 0;
}

static const struct SandboxMap *GetSandboxMapByName(const char *name)
{
    if (name == NULL) {
        BEGET_LOGE("Sandbox map name is NULL.");
        return NULL;
    }
    int len = ARRAY_LENGTH(g_map);
    for (int i = 0; i < len; i++) {
        if (strcmp(g_map[i].name, name) == 0) {
            return &g_map[i];
        }
    }
    return NULL;
}

static void InitSandbox(sandbox_t *sandbox, const char *sandboxConfig, const char *name)
{
    if (sandbox == NULL || sandboxConfig == NULL || name == NULL) {
        BEGET_LOGE("Init sandbox with invalid arguments");
        return;
    }
    if (sandbox->isCreated) {
        BEGET_LOGE("Sandbox %s has created.", name);
        return;
    }
    if (UnshareNamespace(CLONE_NEWNS) < 0) {
        return;
    }
    sandbox->ns = GetNamespaceFd("/proc/self/ns/mnt");
    if (sandbox->ns < 0) {
        BEGET_LOGE("Get sandbox namespace fd is failed");
        return;
    }

    if (strcpy_s(sandbox->name, MAX_BUFFER_LEN - 1, name) != 0) {
        BEGET_LOGE("Failed to copy sandbox name");
        return;
    }

    // parse json config
    if (ParseSandboxConfig(sandbox, sandboxConfig) < 0) {
        return;
    }
}

static int CheckAndMakeDir(const char *dir, mode_t mode)
{
    if (access(dir, F_OK) == 0) {
        BEGET_LOGW("Mount point \' %s \' already exist", dir);
        return 0;
    } else {
        if (errno == ENOENT) {
            if (MakeDirRecursive(dir, mode) != 0) {
                BEGET_LOGE("Failed MakeDirRecursive %s, err=%d", dir, errno);
                return -1;
            }
        } else {
            BEGET_LOGW("Failed to access mount point \' %s \', err = %d", dir, errno);
            return -1;
        }
    }
    return 0;
}

static int BindMount(const char *source, const char *target, unsigned long flags, SandboxTag tag)
{
    if (source == NULL || target == NULL) {
        BEGET_LOGE("Mount with invalid arguments");
        errno = EINVAL;
        return -1;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (tag == SANDBOX_TAG_MOUNT_PATH) {
        if (CheckAndMakeDir(target, mode) != 0) {
            BEGET_LOGE("Failed make %s dir.", target);
            return -1;
        }
    } else if (tag == SANDBOX_TAG_MOUNT_FILE) {
        if (CheckAndCreatFile(target, mode) != 0) {
            BEGET_LOGE("Failed make %s file.", target);
            return -1;
        }
    } else {
        BEGET_LOGE("Tag is error.");
        return -1;
    }

    if ((flags & MS_BIND) == 0) {
        BEGET_LOGW("Not configure bind, must configure bind flag.");
        flags |= MS_BIND;
    }

    if ((flags & MS_REC) == 0) {
        BEGET_LOGW("Not configure rec, must configure rec flag.");
        flags |= MS_REC;
    }

    // do mount
    if (mount(source, target, NULL, flags, NULL) != 0) {
        BEGET_LOGE("Failed to bind mount \' %s \' to \' %s \', err = %d", source, target, errno);
        if (errno != ENOTDIR) {  // mount errno is 'Not a directory' can ignore
            return -1;
        }
    }

    return 0;
}

static bool IsValidSandbox(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        BEGET_LOGE("preparing sandbox with invalid argument");
        return false;
    }

    if (sandbox->rootPath == NULL) {
        return false;
    }

    return true;
}

static int MountSandboxInfo(const mountlist_t *mounts, const char *rootPath, SandboxTag tag)
{
    if (mounts == NULL) {
        return 0;
    }
    if (mounts->info == NULL) {
        return 0;
    }
    while (mounts != NULL) {
        mount_t *mount = mounts->info;
        char *source = mount->source;
        char target[PATH_MAX] = {};
        if (snprintf_s(target, PATH_MAX, PATH_MAX - 1, "%s%s", rootPath, mount->target) < 0) {
            BEGET_LOGE("Failed snprintf_s err=%d", errno);
            return -1;
        }
        int rc = BindMount(source, target, mount->flags, tag);
        BEGET_ERROR_CHECK(rc == 0, return -1, "Failed bind mount %s to %s.", source, target);
        mounts = mounts->next;
    }
    return 0;
}

static int LinkSandboxInfo(const linklist_t *links, const char *rootPath)
{
    if (links == NULL) {
        return 0;
    }
    if (links->info == NULL) {
        return 0;
    }
    while (links != NULL) {
        linker_t *link = links->info;
        char linkName[PATH_MAX] = {0};
        if (snprintf_s(linkName, PATH_MAX, PATH_MAX - 1, "%s%s", rootPath, link->linkName) < 0) {
            BEGET_LOGE("Failed snprintf_s err=%d", errno);
            return -1;
        }
        int rc = symlink(link->target, linkName);
        if (rc != 0) {
            if (errno == EEXIST) {
                BEGET_LOGE("symbol link name \' %s \' already exist", linkName);
            } else {
                BEGET_LOGE("Failed to link \' %s \' to \' %s \', err = %d", link->target, linkName, errno);
                return -1;
            }
        }
        links = links->next;
    }
    return 0;
}

int PrepareSandbox(const char *name)
{
    BEGET_ERROR_CHECK(name != NULL, return -1, "Prepare sandbox name is NULL.");
    BEGET_ERROR_CHECK(getuid() == 0, return -1, "Current process uid is not root, exit.");
    const struct SandboxMap *map = GetSandboxMapByName(name);
    BEGET_ERROR_CHECK(map != NULL, return -1, "Cannot get sandbox map by name %s.", name);
    sandbox_t *sandbox = map->sandbox;
    BEGET_CHECK(IsValidSandbox(sandbox) == true, return -1);
    BEGET_INFO_CHECK(sandbox->isCreated == false, return 0, "Sandbox %s already created", sandbox->name);
    BEGET_CHECK(sandbox->rootPath != NULL, return -1);
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    BEGET_ERROR_CHECK(CheckAndMakeDir(sandbox->rootPath, mode) == 0, return -1, "Failed root %s.", sandbox->rootPath);
    int rc = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
    BEGET_ERROR_CHECK(rc == 0, return -1, "Failed set mount slave err = %d", errno);
    rc = BindMount(sandbox->rootPath, sandbox->rootPath, MS_BIND | MS_REC, SANDBOX_TAG_MOUNT_PATH);
    BEGET_ERROR_CHECK(rc == 0, return -1, "Failed to mount rootpath bind err = %d", errno);

    // 1) walk through all mounts and do bind mount
    rc = MountSandboxInfo(sandbox->pathMounts, sandbox->rootPath, SANDBOX_TAG_MOUNT_PATH);
    if (rc < 0) {
        return -1;
    }

    rc = MountSandboxInfo(sandbox->fileMounts, sandbox->rootPath, SANDBOX_TAG_MOUNT_FILE);
    if (rc < 0) {
        return -1;
    }

    // 2) walk through all links and do symbol link
    rc = LinkSandboxInfo(sandbox->links, sandbox->rootPath);
    if (rc < 0) {
        return -1;
    }

    BEGET_ERROR_CHECK(chdir(sandbox->rootPath) == 0, return -1, "Change to %s, err = %d", sandbox->rootPath, errno);
    BEGET_ERROR_CHECK(syscall(SYS_pivot_root, sandbox->rootPath, sandbox->rootPath) == 0, return -1,
        "Failed system call pivot root, err=%d", errno);
    BEGET_ERROR_CHECK(umount2(".", MNT_DETACH) == 0, return -1, "Failed umount2 MNT_DETACH, err=%d", errno);
    sandbox->isCreated = true;
    return 0;
}

static void FreeLink(linker_t *link)
{
    if (link == NULL) {
        return;
    }

    if (link->linkName != NULL) {
        free(link->linkName);
        link->linkName = NULL;
    }

    if (link->target != NULL) {
        free(link->target);
        link->target = NULL;
    }
}

static void FreeLinks(linklist_t *links)
{
    if (links == NULL) {
        return;
    }

    linklist_t *tmp = links;
    while (tmp != NULL) {
        linklist_t *next = tmp ->next;
        FreeLink(tmp->info);
        free(tmp);
        tmp = next;
    }
}

static void FreeMount(mount_t *mount)
{
    if (mount == NULL) {
        return;
    }

    if (mount->source != NULL) {
        free(mount->source);
        mount->source = NULL;
    }

    if (mount->target != NULL) {
        free(mount->target);
        mount->target = NULL;
    }
}

static void FreeMounts(mountlist_t *mounts)
{
    if (mounts == NULL) {
        return;
    }

    mountlist_t *tmp = mounts;
    while (tmp != NULL) {
        mountlist_t *next = tmp ->next;
        FreeMount(tmp->info);
        free(tmp);
        tmp = next;
    }
}

bool InitSandboxWithName(const char *name)
{
    bool isFound = false;
    if (name == NULL) {
        BEGET_LOGE("Init sandbox name is NULL.");
        return isFound;
    }
    const struct SandboxMap *map = GetSandboxMapByName(name);
    if (map != NULL) {
        InitSandbox(map->sandbox, map->configfile, name);
        isFound = true;
    }

    if (!isFound) {
        BEGET_LOGE("Cannot find sandbox with name %s.", name);
    }
    return isFound;
}

void DestroySandbox(const char *name)
{
    if (name == NULL) {
        BEGET_LOGE("Destroy sandbox name is NULL.");
        return;
    }
    const struct SandboxMap *map = GetSandboxMapByName(name);
    if (map == NULL) {
        BEGET_LOGE("Cannot get sandbox map by name %s.", name);
        return;
    }
    sandbox_t *sandbox = map->sandbox;

    if (sandbox == NULL) {
        return;
    }

    if (sandbox->rootPath != NULL) {
        free(sandbox->rootPath);
        sandbox->rootPath = NULL;
    }
    FreeLinks(sandbox->links);
    FreeMounts(sandbox->fileMounts);
    FreeMounts(sandbox->pathMounts);
    if (sandbox->ns > 0) {
        (void)close(sandbox->ns);
    }
    sandbox->isCreated = false;
    return;
}

int EnterSandbox(const char *name)
{
    if (name == NULL) {
        BEGET_LOGE("Sandbox name is NULL.");
        return -1;
    }
    const struct SandboxMap *map = GetSandboxMapByName(name);
    if (map == NULL) {
        BEGET_LOGE("Cannot get sandbox map by name %s.", name);
        return -1;
    }
    sandbox_t *sandbox = map->sandbox;

    if (sandbox == NULL) {
        return -1;
    }
    if (sandbox->isCreated == false) {
        BEGET_LOGE("Sandbox %s has not been created.", name);
        return -1;
    }
    if (sandbox->ns > 0) {
        if (SetNamespace(sandbox->ns, CLONE_NEWNS) < 0) {
            BEGET_LOGE("Cannot enter mount namespace for sandbox \' %s \', err=%d.", name, errno);
            return -1;
        }
    } else {
        BEGET_LOGE("Sandbox \' %s \' namespace fd is invalid.", name);
        return -1;
    }
    return 0;
}

void DumpSandboxByName(const char *name)
{
    if (name == NULL) {
        BEGET_LOGE("Init sandbox name is NULL.");
        return;
    }
    const struct SandboxMap *map = GetSandboxMapByName(name);
    if (map == NULL) {
        return;
    }
    BEGET_LOGI("Sandbox Map name: %s.", map->name);
    BEGET_LOGI("Sandbox Map config file: %s.", map->configfile);
    BEGET_LOGI("Sandbox name: %s.", map->sandbox->name);
    BEGET_LOGI("Sandbox rootPath: %s.", map->sandbox->rootPath);
    BEGET_LOGI("Sandbox mounts info:");
    mountlist_t *mounts = map->sandbox->pathMounts;
    while (mounts != NULL) {
        mount_t *mount = mounts->info;
        BEGET_LOGI("Sandbox path mounts list source: %s", mount->source);
        BEGET_LOGI("Sandbox path mounts list target: %s", mount->target);
        mounts = mounts->next;
    }
    mounts = map->sandbox->fileMounts;
    while (mounts != NULL) {
        mount_t *mount = mounts->info;
        BEGET_LOGI("Sandbox file mounts list source: %s", mount->source);
        BEGET_LOGI("Sandbox file mounts list target: %s", mount->target);
        mounts = mounts->next;
    }
    BEGET_LOGI("Sandbox links info:");
    linklist_t *links = map->sandbox->links;
    while (links != NULL) {
        linker_t *link = links->info;
        BEGET_LOGI("Sandbox links list source: %s", link->target);
        BEGET_LOGI("Sandbox links list target: %s", link->linkName);
        links = links->next;
    }
    return;
}
