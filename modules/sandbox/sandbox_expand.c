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

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_msg.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "json_utils.h"
#include "securec.h"

#define SANDBOX_GROUP_PATH "/data/storage/el2/group/"
#define SANDBOX_INSTALL_PATH "/data/storage/el2/group/"
#define SANDBOX_OVERLAY_PATH "/data/storage/overlay/"

typedef struct TagSandboxExpandContext {
    const SandboxContext *sandboxContext;
    VarExtraData extraData;
    int (*checkInputData)(struct TagSandboxExpandContext *context, const char *data);
    int (*checkInputRepeat)(struct TagSandboxExpandContext *context, const char *data);
    uint32_t inputDataLen;
    char *inputData;
} SandboxExpandContext;

static void GetMountArgs(const SandboxExpandContext *context, uint32_t category, MountArg *args)
{
    const MountArgTemplate *tmp = GetMountArgTemplate(category);
    if (tmp == 0) {
        args->mountFlags = MS_REC | MS_BIND;
        args->mountSharedFlag = MS_SLAVE;
        return;
    }
    args->fsType = tmp->fsType;
    args->options = tmp->options;
    args->mountFlags = tmp->mountFlags;
    args->mountSharedFlag = MS_SLAVE;
    return;
}

static int MountPathNode(SandboxExpandContext *context,
    const PathMountNode *sandboxNode, const cJSON *config, uint32_t category)
{
    MountArg args = {};
    GetMountArgs(context, category == MOUNT_TMP_MAX ? sandboxNode->category : category, &args);

    int ret = 0;
    int count = cJSON_GetArraySize(config);
    VarExtraData *extraData = &context->extraData;
    for (int i = 0; i < count; i++) {
        extraData->data.json = cJSON_GetArrayItem(config, i);
        args.originPath = GetSandboxRealVar(context->sandboxContext,
            BUFFER_FOR_SOURCE, sandboxNode->source, NULL, extraData);
        args.destinationPath = GetSandboxRealVar(context->sandboxContext,
            BUFFER_FOR_TARGET, sandboxNode->target, context->sandboxContext->rootPath, extraData);
        if (args.originPath == NULL || args.destinationPath == NULL) {
            APPSPAWN_LOGE("Faild to get real path");
            continue;
        }
        if (context->checkInputRepeat && context->checkInputRepeat(context, args.originPath)) {
            continue;
        }

        CreateSandboxDir(args.destinationPath , FILE_MODE);
        ret = SandboxMountPath(&args);
        APPSPAWN_CHECK(ret == 0, return ret, "mount hsp failed %{public}d", ret);
    }
    return ret;
}

static int SetExpandSandboxConfig(const SandboxExpandContext *context,
    const AppSpawnSandboxCfg *appSandBox, const char *name, uint32_t category)
{
    uint32_t size = 0;
    char *extInfo = (char *)(GetAppSpawnMsgExtInfo(context->sandboxContext->message, name, &size));
    if (size == 0 || extInfo == NULL) {
        return 0;
    }

    SandboxSection *section = GetSandboxSection(&appSandBox->nameGroupsQueue, name);
    APPSPAWN_CHECK(section != NULL, return -1, "Can not find cfg for %{public}s", name);
    PathMountNode *pathNode = (PathMountNode *)GetFirstSandboxMountNode(section);
    APPSPAWN_CHECK(pathNode != NULL, return -1, "Can not get path mount node for %{public}s", name);
    APPSPAWN_LOGV("SetExpandSandboxConfig config: %{public}s value: %{public}s", name, extInfo);
    cJSON *root = cJSON_Parse(extInfo);
    APPSPAWN_CHECK(root != NULL, return -1, "Invalid ext info %{public}s for %{public}s", extInfo, name);
    int ret = MountPathNode((SandboxExpandContext *)context, pathNode, root, category);
    cJSON_Delete(root);
    return ret;
}

static int ReplaceVariableByJson(const SandboxContext *context,
    const char *varName, SandboxBuffer *sandboxBuffer, uint32_t *varLen, const VarExtraData *extraData)
{
    APPSPAWN_CHECK_ONLY_EXPER(context != NULL && extraData != NULL, return -1);
    APPSPAWN_CHECK_ONLY_EXPER(varName != NULL && sandboxBuffer != NULL && varLen != NULL, return -1);
    char *value = GetStringFromJsonObj(extraData->data.json, varName);
    APPSPAWN_CHECK(value != NULL, return -1, "Can not value for %{public}s", varName);
    APPSPAWN_LOGV("ReplaceVariableByByJson varName: %{public}s value: %{public}s", varName, value);

    int len = sprintf_s((char *)sandboxBuffer->buffer + sandboxBuffer->current,
        sandboxBuffer->bufferLen - sandboxBuffer->current - 1, "%s", value);
    APPSPAWN_CHECK(len > 0, return -1, "Failed to releace value for var %{public}s", varName);
    *varLen = (uint32_t)len;
    return 0;
}
/**
 [{
    "bundle-name" : "",
    "module-name" : "",
    "version" : ""
 }]
 */
static int ProcessHSPListConfig(const SandboxContext *context, const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    SandboxExpandContext expendContext = {};
    expendContext.extraData.varReplaceWithName = ReplaceVariableByJson;
    expendContext.sandboxContext = context;
    return SetExpandSandboxConfig(&expendContext, appSandBox, name, MOUNT_TMP_MAX);
}

/**
 [{
    "data-group-id" : "",
    "data-gid" : "",
    "data-dir" : "",
    "data-uuid" : ""
 }]
 */
static int ProcessDataGroupConfig(const SandboxContext *context, const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    SandboxExpandContext expendContext = {};
    expendContext.extraData.varReplaceWithName = ReplaceVariableByJson;
    expendContext.sandboxContext = context;
    uint32_t category = MOUNT_TMP_MAX;
    if (CheckAppSpawnMsgFlag(context->message, TLV_MSG_FLAGS, APP_FLAGS_ISOLATED_SANDBOX)) {
        category = MOUNT_TMP_RDONLY;
    }
    return SetExpandSandboxConfig(&expendContext, appSandBox, name, category);
}

/**
 [{
    "overlay-path" : ""
 }]
 */
static int ReplaceVariableForOverlayPath(const SandboxContext *context,
    const char *varName, SandboxBuffer *sandboxBuffer, uint32_t *varLen, const VarExtraData *extraData)
{
    APPSPAWN_CHECK_ONLY_EXPER(context != NULL && extraData != NULL, return -1);
    APPSPAWN_CHECK_ONLY_EXPER(varName != NULL && sandboxBuffer != NULL && varLen != NULL, return -1);

    char *value = GetStringFromJsonObj(extraData->data.json, "overlay-path");
    APPSPAWN_CHECK(value != NULL, return -1, "Can not value for %{public}s", varName);
    APPSPAWN_LOGV("ReplaceVariableForOverlayPath varName: %{public}s value: %{public}s", varName, value);
    char *tmp = GetLastStr(value, "/");
    if (tmp == NULL) {
        APPSPAWN_LOGE("Invalid hap path %{public}s", value);
        return -1;
    }

    int len = 0;
    if (strcmp("hap-path", varName) == 0) {
        len = strncpy_s((char *)sandboxBuffer->buffer + sandboxBuffer->current,
        sandboxBuffer->bufferLen - sandboxBuffer->current - 1, value, tmp - value);
        APPSPAWN_CHECK(len == 0, return -1, "Failed to releace value for var %{public}s", varName);
        len = tmp - value;
    } else if (strcmp("hap-name", varName) == 0) {
        len = sprintf_s((char *)sandboxBuffer->buffer + sandboxBuffer->current,
            sandboxBuffer->bufferLen - sandboxBuffer->current - 1, "%s", tmp + 1);
    }
    APPSPAWN_CHECK(len > 0, return -1, "Failed to releace value for var %{public}s", varName);
    *varLen = (uint32_t)len;
    return 0;
}

static int CheckOverlayRepeat(struct TagSandboxExpandContext *context, const char *data)
{
    if (strstr(context->inputData, data) != NULL) {
        APPSPAWN_LOGV("%{public}s have mounted before, no need to mount twice.", data);
        return 1;
    }
    int ret = strcat_s(context->inputData, context->inputDataLen, "|");
    APPSPAWN_CHECK(ret == 0, return 0, "Fail to add src path to set %{public}s", "|");
    ret = strcat_s(context->inputData, context->inputDataLen, data);
    APPSPAWN_CHECK(ret == 0, return 0, "Fail to add src path to set %{public}s", data);
    return 0;
}

static int ProcessOverlayAppConfig(const SandboxContext *context,
    const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)(GetAppSpawnMsgExtInfo(context->message, name, &size));
    if (size == 0 || extInfo == NULL) {
        return 0;
    }

    SandboxExpandContext expendContext = {};
    expendContext.extraData.varReplaceWithName = ReplaceVariableForOverlayPath;
    expendContext.sandboxContext = context;
    expendContext.checkInputRepeat = CheckOverlayRepeat;
    expendContext.inputDataLen = size;
    expendContext.inputData = (char *)calloc(1, expendContext.inputDataLen + 1);
    APPSPAWN_CHECK(expendContext.inputData != NULL, return -1, "Failed to create inputData");
    int ret = SetExpandSandboxConfig(&expendContext, appSandBox, name, MOUNT_TMP_MAX);
    free(expendContext.inputData);
    return ret;
}

struct ListNode g_sandboxExpandCfgList = {&g_sandboxExpandCfgList, &g_sandboxExpandCfgList};
static int AppSandboxExpandAppCfgCompareName(ListNode *node, void *data)
{
    AppSandboxExpandAppCfgNode *varNode = ListEntry(node, AppSandboxExpandAppCfgNode, node);
    return strncmp((char *)data, varNode->name, strlen(varNode->name));
}

static int AppSandboxExpandAppCfgComparePrio(ListNode *node1, ListNode *node2)
{
    AppSandboxExpandAppCfgNode *varNode1 = ListEntry(node1, AppSandboxExpandAppCfgNode, node);
    AppSandboxExpandAppCfgNode *varNode2 = ListEntry(node2, AppSandboxExpandAppCfgNode, node);
    return varNode1->prio - varNode2->prio;
}

static const AppSandboxExpandAppCfgNode *GetAppSandboxExpandAppCfg(const char *name)
{
    ListNode *node = OH_ListFind(&g_sandboxExpandCfgList, (void *)name, AppSandboxExpandAppCfgCompareName);
    if (node == NULL) {
        return NULL;
    }
    return ListEntry(node, AppSandboxExpandAppCfgNode, node);
}

int RegisterExpandSandboxCfgHandler(const char *name, int prio, ProcessExpandSandboxCfg handleExpandCfg)
{
    APPSPAWN_CHECK_ONLY_EXPER(name != NULL && handleExpandCfg != NULL, return APPSPAWN_ARG_INVALID);
    if (GetAppSandboxExpandAppCfg(name) != NULL) {
        return APPSPAWN_NODE_EXIST;
    }

    size_t len = APPSPAWN_ALIGN(strlen(name) + 1);
    AppSandboxExpandAppCfgNode *node = (AppSandboxExpandAppCfgNode *)(malloc(sizeof(AppSandboxExpandAppCfgNode) + len));
    APPSPAWN_CHECK(node != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to create sandbox");
    // ext data init
    OH_ListInit(&node->node);
    node->cfgHandle = handleExpandCfg;
    node->prio = prio;
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node);
        return -1, "Failed to copy name %{public}s", name);
    OH_ListAddWithOrder(&g_sandboxExpandCfgList, &node->node, AppSandboxExpandAppCfgComparePrio);
    return 0;
}

int ProcessExpandAppSandboxConfig(const SandboxContext *context, const AppSpawnSandboxCfg *appSandBox, const char *name)
{
    APPSPAWN_CHECK_ONLY_EXPER(context != NULL && appSandBox != NULL, return APPSPAWN_ARG_INVALID);
    APPSPAWN_CHECK_ONLY_EXPER(name != NULL, return APPSPAWN_ARG_INVALID);
    APPSPAWN_LOGV("ProcessExpandAppSandboxConfig %{public}s.", name);
    const AppSandboxExpandAppCfgNode *node = GetAppSandboxExpandAppCfg(name);
    if (node != NULL && node->cfgHandle != NULL) {
        return node->cfgHandle(context, appSandBox, name);
    }
    return 0;
}

void AddDefaultExpandAppSandboxConfigHandle(void)
{
    RegisterExpandSandboxCfgHandler("HspList", 0, ProcessHSPListConfig);
    RegisterExpandSandboxCfgHandler("DataGroup", 1, ProcessDataGroupConfig);
    RegisterExpandSandboxCfgHandler("Overlay", 2, ProcessOverlayAppConfig);  // 2 priority
}

void ClearExpandAppSandboxConfigHandle(void)
{
    OH_ListRemoveAll(&g_sandboxExpandCfgList, NULL);
}
