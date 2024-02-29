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
#include "appspawn_mount_permission.h"

#include <fstream>
#include <sstream>
#include <vector>

#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "sandbox_utils.h"

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int32_t g_maxPermissionIndex = -1;
static SandboxSection g_permissionQueue;

static int PermissionNodeCompareProc(ListNode *node, ListNode *newNode)
{
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxNode, node);
    SandboxPermissionNode *newPermissionNode = (SandboxPermissionNode *)ListEntry(newNode, SandboxNode, node);
    return strcmp(permissionNode->name, newPermissionNode->name);
}

static int DecodePermissionConfig(const nlohmann::json &permissionConfigs)
{
    for (auto it = permissionConfigs.begin(); it != permissionConfigs.end(); it++) {
        SandboxPermissionNode *node = CreateSandboxPermissionNode(it.key().c_str(), 0, NULL);
        APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);
        // success, insert queue
        OH_ListAddWithOrder(&g_permissionQueue.front, &node->sandboxNode.node, PermissionNodeCompareProc);
    }
    return 0;
}

static int LoadPermissionConfig(void)
{
    std::vector<nlohmann::json> jsonConfigs;
    int ret = OHOS::AppSpawn::SandboxUtils::GetSandboxConfigs(jsonConfigs);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    for (auto config : jsonConfigs) {
        if (config.find("permission") == config.end()) {
            continue;
        }
        ret = DecodePermissionConfig(config["permission"][0]);
        if (ret != 0) {
            APPSPAWN_LOGE("Failed to load permission err: %{public}d for config", ret);
        }
    }
    g_maxPermissionIndex = PermissionRenumber(&g_permissionQueue);
    return 0;
}

int32_t GetPermissionIndex(const char *permission)
{
    return GetPermissionIndexInQueue(&g_permissionQueue, permission);
}

int32_t GetMaxPermissionIndex(void)
{
    return g_maxPermissionIndex;
}

const SandboxPermissionNode *GetPermissionNode(const char *permission)
{
    return GetPermissionNodeInQueue(&g_permissionQueue, permission);
}

const SandboxPermissionNode *GetPermissionNodeByIndex(int32_t index)
{
    if (g_maxPermissionIndex <= index) {
        return nullptr;
    }
    return GetPermissionNodeInQueueByIndex(&g_permissionQueue, index);
}

static void LoadPermission(void)
{
    pthread_mutex_lock(&g_mutex);
    if (g_maxPermissionIndex == -1) {
        OH_ListInit(&g_permissionQueue.front);
        g_permissionQueue.type = SANDBOX_TAG_PERMISSION_QUEUE;
        LoadPermissionConfig();
    }
    pthread_mutex_unlock(&g_mutex);
}

static void DeletePermissions(void)
{
    pthread_mutex_lock(&g_mutex);
    OH_ListRemoveAll(&g_permissionQueue.front, NULL);
    g_maxPermissionIndex = -1;
    pthread_mutex_unlock(&g_mutex);
}

__attribute__((constructor)) static void LoadPermissionModule(void)
{
    LoadPermission();
}

__attribute__((destructor)) static void DeletePermissionModule(void)
{
    DeletePermissions();
}