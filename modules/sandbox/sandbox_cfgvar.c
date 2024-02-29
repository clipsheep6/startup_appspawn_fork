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

#include "appspawn_service.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "parameter.h"
#include "modulemgr.h"
#include "securec.h"

struct ListNode g_sandboxVarList = { &g_sandboxVarList, &g_sandboxVarList };

static int VarPackageNameIndexReplace(const SandboxContext *sandboxContext,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *realLen, int permission)
{
    AppSpawnMsgBundleInfo *bundleInfo = (
        AppSpawnMsgBundleInfo *)GetAppProperty(sandboxContext->property, TLV_BUNDLE_INFO);
    APPSPAWN_CHECK(bundleInfo != NULL, return APPSPAWN_NO_TLV,
        "No tlv %{public}d in msg %{public}s", TLV_BUNDLE_INFO, GetProcessName(sandboxContext->property));
    int len = 0;
    if (bundleInfo->bundleIndex > 0) {
        len = sprintf_s((char *)buffer, bufferLen, "%s_%d", bundleInfo->bundleName, bundleInfo->bundleIndex);
    } else {
        len = sprintf_s((char *)buffer, bufferLen, "%s", bundleInfo->bundleName);
    }
    APPSPAWN_CHECK(len > 0 && ((uint32_t)len < bufferLen),
        return -1, "Failed to format path app: %{public}s", sandboxContext->bundleName);
    *realLen = (uint32_t)len;
    return 0;
}

static int VarPackageNameReplace(const SandboxContext *sandboxContext,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *realLen, int permission)
{
    int len = sprintf_s((char *)buffer, bufferLen, "%s", sandboxContext->bundleName);
    APPSPAWN_CHECK(len > 0 && ((uint32_t)len < bufferLen),
        return -1, "Failed to format path app: %{public}s", sandboxContext->bundleName);
    *realLen = (uint32_t)len;
    return 0;
}

static int VarCurrentUseIdReplace(const SandboxContext *sandboxContext,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *realLen, int permission)
{
    AppSpawnMsgDacInfo *info = (AppSpawnMsgDacInfo *)GetAppProperty(sandboxContext->property, TLV_DAC_INFO);
    APPSPAWN_CHECK(info != NULL, return APPSPAWN_NO_TLV,
        "No tlv %{public}d in msg %{public}s", TLV_DAC_INFO, GetProcessName(sandboxContext->property));
    int len = 0;
    if (!permission) {
        len = sprintf_s((char *)buffer, bufferLen, "%u", info->uid / UID_BASE);
    } else if (sandboxContext->appFullMountEnable && strlen(info->userName) > 0) {
        len = sprintf_s((char *)buffer, bufferLen, "%s", info->userName);
    } else {
        len = sprintf_s((char *)buffer, bufferLen, "%s", "currentUser");
    }
    APPSPAWN_CHECK(len > 0 && ((uint32_t)len < bufferLen),
        return -1, "Failed to format path app: %{public}s", sandboxContext->bundleName);
    *realLen += (uint32_t)len;
    return 0;
}

static int VariableNodeCompareName(ListNode *node, void *data)
{
    AppSandboxVarNode *varNode = (AppSandboxVarNode *)ListEntry(node, AppSandboxVarNode, node);
    return strncmp((char *)data, varNode->name, strlen(varNode->name));
}

static AppSandboxVarNode *GetAppSandboxVarNode(const char *name)
{
    ListNode *node = OH_ListFind(&g_sandboxVarList, (void *)name, VariableNodeCompareName);
    if (node == NULL) {
        return NULL;
    }
    return (AppSandboxVarNode *)ListEntry(node, AppSandboxVarNode, node);
}

int AddVariableReplaceHandler(const char *name, ReplaceVarHandler ReplaceVarHandler)
{
    if (GetAppSandboxVarNode(name) != NULL) {
        return APPSPAWN_NODE_EXIST;
    }

    size_t len = APPSPAWN_ALIGN(strlen(name) + 1);
    AppSandboxVarNode *node = (AppSandboxVarNode *)malloc(sizeof(AppSandboxVarNode) + len);
    APPSPAWN_CHECK(node != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to create sandbox");
    // ext data init
    OH_ListInit(&node->node);
    node->replaceVar = ReplaceVarHandler;
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node);
        return -1, "Failed to copy name %{public}s", name);
    OH_ListAddTail(&g_sandboxVarList, &node->node);
    return 0;
}

const char *GetSandboxRealVar(const SandboxContext *sandboxContext,
    uint32_t index, const char *source, const char *prefix, int permission)
{
    if (index >= 2) { // max buffer count
        return NULL;
    }
    uint32_t destIndex = 0;
    int ret = 0;
    if (prefix != NULL) { // copy prefix data
        destIndex = strlen(prefix);
        if (destIndex >= sandboxContext->bufferLen) {
            return NULL;
        }
        ret = memcpy_s(sandboxContext->buffer[index], sandboxContext->bufferLen, prefix, destIndex);
        APPSPAWN_CHECK(ret == EOK,
            return NULL, "Failed to copy prefix data %{public}s app: %{public}s", prefix, sandboxContext->bundleName);
    }
    AppSandboxVarNode *node = NULL;
    size_t sourceLen = strlen(source);
    for (size_t i = 0; i < sourceLen; i++) {
        if (destIndex >= sandboxContext->bufferLen) {
            return NULL;
        }
        if (*(source + i) == '<') {
            node = GetAppSandboxVarNode(source + i);
            if (node != NULL) {
                i += strlen(node->name) - 1;
                uint32_t realLen = 0;
                ret = node->replaceVar(sandboxContext,
                    (uint8_t *)(sandboxContext->buffer[index] + destIndex),
                    sandboxContext->bufferLen - destIndex, &realLen, permission);
                APPSPAWN_CHECK(ret == 0, return NULL, "Failed to fill real data");
                destIndex += realLen;
                continue;
            }
        }
        *(sandboxContext->buffer[index] + destIndex) = *(source + i);
        destIndex++;
    }
    sandboxContext->buffer[index][destIndex] = '\0';
    return sandboxContext->buffer[index];
}

void AddDefaultVariable(void)
{
    AddVariableReplaceHandler(PARAMETER_PACKAGE_NAME, VarPackageNameReplace);
    AddVariableReplaceHandler(PARAMETER_USER_ID, VarCurrentUseIdReplace);
    AddVariableReplaceHandler(PARAMETER_PACKAGE_INDEX, VarPackageNameIndexReplace);
}

void ClearVariable(void)
{
    OH_ListRemoveAll(&g_sandboxVarList, NULL);
}
