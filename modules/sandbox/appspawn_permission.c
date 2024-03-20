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
#include "appspawn_permission.h"
#ifdef APPSPAWN_CLIENT
#include "appspawn_mount_permission.h"
#else
#include "appspawn_sandbox.h"
#endif
#include "appspawn_utils.h"
#include "appspawn_msg.h"
#include "securec.h"

static int PermissionNodeCompareIndex(ListNode *node, void *data)
{
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
    return permissionNode->permissionIndex - *(int32_t *)data;
}

static int PermissionNodeCompareName(ListNode *node, void *data)
{
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
    return strcmp(permissionNode->name, (char *)data);
}

static int PermissionNodeCompareProc(ListNode *node, ListNode *newNode)
{
    SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
    SandboxPermissionNode *newPermissionNode = (SandboxPermissionNode *)ListEntry(newNode, SandboxMountNode, node);
    return strcmp(permissionNode->name, newPermissionNode->name);
}

#ifndef APPSPAWN_CLIENT
SandboxPermissionNode *CreateSandboxPermissionNode(const char *name, uint32_t gidCount, uint32_t *gidTable)
{
    size_t len = APPSPAWN_ALIGN(strlen(name) + 1);
    SandboxPermissionNode *node = (SandboxPermissionNode *)calloc(1,
        len + sizeof(uint32_t) * gidCount + sizeof(SandboxPermissionNode));
    APPSPAWN_CHECK(node != NULL, return NULL, "Failed to create symbol node");
    OH_ListInit(&node->sandboxNode.node);
    node->sandboxNode.type = SANDBOX_TAG_PERMISSION;
    node->permissionIndex = 0;

    SandboxSectionInit(&node->section, SANDBOX_TAG_PERMISSION_QUEUE);
    node->name = (char *)(((uint8_t *)node) + sizeof(SandboxPermissionNode) + sizeof(uint32_t) * gidCount);
    node->gidCount = gidCount;
    if (gidCount && gidTable != NULL) {
        (void)memcpy_s(node->gidTable, sizeof(uint32_t) * gidCount, gidTable, sizeof(uint32_t) * gidCount);
    }
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node);
        return NULL, "Failed to copy name");
    return node;
}
#endif

int AddSandboxPermissionNode(const char *name, SandboxQueue *queue)
{
    size_t len = APPSPAWN_ALIGN(strlen(name) + 1) + sizeof(SandboxPermissionNode);
    SandboxPermissionNode *node = (SandboxPermissionNode *)calloc(1, len);
    APPSPAWN_CHECK(node != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to create permission node");
    OH_ListInit(&node->sandboxNode.node);
    node->permissionIndex = 0;
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node);
        return APPSPAWN_SYSTEM_ERROR, "Failed to copy name");
    OH_ListAddWithOrder(&queue->front, &node->sandboxNode.node, PermissionNodeCompareProc);
    return 0;
}

int32_t PermissionRenumber(SandboxQueue *queue)
{
    ListNode *node = queue->front.next;
    int index = -1;
    while (node != &queue->front) {
        SandboxPermissionNode *permissionNode = (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
        permissionNode->permissionIndex = ++index;
        APPSPAWN_LOGV("Permission index %{public}d name %{public}s",
            permissionNode->permissionIndex, permissionNode->name);
        node = node->next;
    }
    return index + 1;
}

const SandboxPermissionNode *GetPermissionNodeInQueue(SandboxQueue *queue, const char *permission)
{
    if (queue == NULL || permission == NULL) {
        return NULL;
    }
    ListNode *node = OH_ListFind(&queue->front, (void *)permission, PermissionNodeCompareName);
    return (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
}

const SandboxPermissionNode *GetPermissionNodeInQueueByIndex(SandboxQueue *queue, int32_t index)
{
    if (queue == NULL) {
        return NULL;
    }
    ListNode *node = OH_ListFind(&queue->front, (void *)&index, PermissionNodeCompareIndex);
    return (SandboxPermissionNode *)ListEntry(node, SandboxMountNode, node);
}

int32_t GetPermissionIndexInQueue(SandboxQueue *queue, const char *permission)
{
    const SandboxPermissionNode *permissionNode = GetPermissionNodeInQueue(queue, permission);
    return permissionNode == NULL ? INVALID_PERMISSION_INDEX : permissionNode->permissionIndex;
}