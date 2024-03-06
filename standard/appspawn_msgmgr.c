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

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#include "appspawn.h"
#include "appspawn_msg.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "securec.h"

static inline void *GetAppSpawnMsgInfo(const AppSpawnMsgNode *message, int type)
{
    APPSPAWN_CHECK(type < TLV_MAX, return NULL, "Invalid tlv type %{public}u", type);
    APPSPAWN_CHECK(message != NULL && message->buffer != NULL,
        return NULL, "Invalid message for type %{public}u", type);
    APPSPAWN_CHECK_ONLY_EXPER(message->tlvOffset[type] != INVALID_OFFSET, return NULL);
    return (void *)(message->buffer + message->tlvOffset[type] + sizeof(AppSpawnTlv));
}

static AppSpawnMsgNode *CreateAppSpawnMsg(void)
{
    AppSpawnMsgNode *message = (AppSpawnMsgNode *)calloc(1, sizeof(AppSpawnMsgNode));
    APPSPAWN_CHECK(message != NULL, return NULL, "Failed to create message");
    message->buffer = NULL;
    message->tlvOffset = NULL;
    (void)memset_s(&message->msgHeader, sizeof(message->msgHeader), 0, sizeof(message->msgHeader));
    return message;
}

void DeleteAppSpawnMsg(AppSpawnMsgNode *msgNode)
{
    if (msgNode == NULL) {
        return;
    }
    if (msgNode->buffer) {
        free(msgNode->buffer);
        msgNode->buffer = NULL;
    }
    if (msgNode->tlvOffset) {
        free(msgNode->tlvOffset);
        msgNode->tlvOffset = NULL;
    }
    free(msgNode);
}

static inline int CheckRecvMsg(const AppSpawnMsg *msg)
{
    APPSPAWN_CHECK(msg != NULL, return -1, "Invalid msg");
    APPSPAWN_CHECK(msg->magic == APPSPAWN_MSG_MAGIC, return -1, "Invalid magic 0x%{public}x", msg->magic);
    APPSPAWN_CHECK(msg->msgLen < MAX_MSG_TOTAL_LENGTH, return -1, "Message too long %{public}u", msg->msgLen);
    APPSPAWN_CHECK(msg->msgLen >= sizeof(AppSpawnMsg), return -1, "Message too long %{public}u", msg->msgLen);
    APPSPAWN_CHECK(msg->tlvCount < MAX_TLV_COUNT, return -1, "Message too long %{public}u", msg->tlvCount);
    APPSPAWN_CHECK(msg->tlvCount < (msg->msgLen / sizeof(AppSpawnTlv)),
        return -1, "Message too long %{public}u", msg->tlvCount);
    return 0;
}

static int AppSpawnMsgRebuild(AppSpawnMsgNode *message, const AppSpawnMsg *msg)
{
    APPSPAWN_CHECK_ONLY_EXPER(CheckRecvMsg(&message->msgHeader) == 0, return APPSPAWN_MSG_INVALID);
    if (msg->msgLen == sizeof(message->msgHeader)) {  // only has msg header
        return 0;
    }
    if (message->buffer == NULL) {
        message->buffer = calloc(1, msg->msgLen - sizeof(message->msgHeader));
        APPSPAWN_CHECK(message->buffer != NULL, return -1, "Failed to alloc memory for recv message");
    }
    if (message->tlvOffset == NULL) {
        uint32_t totalCount = msg->tlvCount + TLV_MAX;
        message->tlvOffset = malloc(totalCount * sizeof(uint32_t));
        APPSPAWN_CHECK(message->tlvOffset != NULL, return -1, "Failed to alloc memory for recv message");
        for (uint32_t i = 0; i < totalCount; i++) {
            message->tlvOffset[i] = INVALID_OFFSET;
        }
    }
    return 0;
}

int CheckAppSpawnMsg(const AppSpawnMsgNode *message)
{
    APPSPAWN_CHECK(strlen(message->msgHeader.processName) > 0,
        return APPSPAWN_MSG_INVALID, "Invalid property processName %{public}s", message->msgHeader.processName);
    APPSPAWN_CHECK(message->tlvOffset != NULL,
        return APPSPAWN_MSG_INVALID, "Invalid property tlv offset for %{public}s", message->msgHeader.processName);
    APPSPAWN_CHECK(message->buffer != NULL,
        return APPSPAWN_MSG_INVALID, "Invalid property buffer for %{public}s", message->msgHeader.processName);

    if (message->tlvOffset[TLV_BUNDLE_INFO] == INVALID_OFFSET ||
        message->tlvOffset[TLV_MSG_FLAGS] == INVALID_OFFSET ||
        message->tlvOffset[TLV_ACCESS_TOKEN_INFO] == INVALID_OFFSET ||
        message->tlvOffset[TLV_DAC_INFO] == INVALID_OFFSET) {
        APPSPAWN_LOGE("No must tlv: %{public}u %{public}u %{public}u", message->tlvOffset[TLV_BUNDLE_INFO],
            message->tlvOffset[TLV_MSG_FLAGS], message->tlvOffset[TLV_DAC_INFO]);
        return APPSPAWN_MSG_INVALID;
    }
    AppSpawnMsgBundleInfo *bundleInfo = (AppSpawnMsgBundleInfo *)GetAppSpawnMsgInfo(message, TLV_BUNDLE_INFO);
    if (bundleInfo != NULL) {
        if (strstr(bundleInfo->bundleName, "\\") != NULL || strstr(bundleInfo->bundleName, "/") != NULL) {
            APPSPAWN_LOGE("Invalid bundle name %{public}s", bundleInfo->bundleName);
            return APPSPAWN_MSG_INVALID;
        }
    }
    return 0;
}

static int CheckExtTlvInfo(const AppSpawnTlv *tlv, uint32_t remainLen)
{
    AppSpawnTlvEx *tlvEx = (AppSpawnTlvEx *)(tlv);
    APPSPAWN_LOGV("Recv type [%{public}s %{public}u] real len: %{public}u",
        tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen);
    if (tlvEx->dataLen > tlvEx->tlvLen - sizeof(AppSpawnTlvEx)) {
        APPSPAWN_LOGE("Invalid tlv [%{public}s %{public}u] real len: %{public}u %{public}u",
            tlvEx->tlvName, tlvEx->tlvLen, tlvEx->dataLen, sizeof(AppSpawnTlvEx));
        return APPSPAWN_MSG_INVALID;
    }
    return 0;
}

static int CheckMsgTlv(const AppSpawnTlv *tlv, uint32_t remainLen)
{
    uint32_t tlvLen = 0;
    switch (tlv->tlvType) {
        case TLV_MSG_FLAGS:
            tlvLen = ((AppSpawnMsgFlags *)(tlv + 1))->count * sizeof(uint32_t);
            break;
        case TLV_ACCESS_TOKEN_INFO:
            tlvLen = sizeof(AppSpawnMsgAccessToken);
            break;
        case TLV_DAC_INFO:
            tlvLen = sizeof(AppSpawnMsgDacInfo);
            break;
        case TLV_BUNDLE_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= (sizeof(AppSpawnMsgBundleInfo) + APP_LEN_BUNDLE_NAME),
                return APPSPAWN_MSG_INVALID, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_OWNER_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= APP_OWNER_ID_LEN,
                return APPSPAWN_MSG_INVALID, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_DOMAIN_INFO:
            APPSPAWN_CHECK((tlv->tlvLen - sizeof(AppSpawnTlv)) <= (APP_APL_MAX_LEN + sizeof(AppSpawnMsgDomainInfo)),
                return APPSPAWN_MSG_INVALID, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
            break;
        case TLV_MAX:
            return CheckExtTlvInfo(tlv, remainLen);
        default:
            break;
    }
    APPSPAWN_CHECK(tlvLen <= tlv->tlvLen,
        return APPSPAWN_MSG_INVALID, "Invalid property tlv %{public}d %{public}d ", tlv->tlvType, tlv->tlvLen);
    return 0;
}

int DecodeAppSpawnMsg(AppSpawnMsgNode *message)
{
    int ret = 0;
    uint32_t tlvCount = 0;
    uint32_t bufferLen = message->msgHeader.msgLen - sizeof(AppSpawnMsg);
    uint32_t currLen = 0;
    while (currLen < bufferLen) {
        AppSpawnTlv *tlv = (AppSpawnTlv *)(message->buffer + currLen);
        APPSPAWN_CHECK(tlv->tlvLen <= (bufferLen - currLen), break,
            "Invalid tlv [%{public}d %{public}d] curr: %{public}u",
            tlv->tlvType, tlv->tlvLen, currLen + sizeof(AppSpawnMsg));

        APPSPAWN_LOGV("DecodeAppSpawnMsg tlv %{public}u %{public}u start: %{public}u ",
            tlv->tlvType, tlv->tlvLen, currLen + sizeof(AppSpawnMsg)); // show in msg offset
        ret = CheckMsgTlv(tlv, bufferLen - currLen);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        if (tlv->tlvType < TLV_MAX) {  // normal
            message->tlvOffset[tlv->tlvType] = currLen;
            currLen += tlv->tlvLen;
        } else {
            APPSPAWN_CHECK((tlvCount + 1) < message->msgHeader.tlvCount, break,
                "Invalid tlv number tlv %{public}d tlvCount: %{public}d", tlv->tlvType, tlvCount);
            message->tlvOffset[TLV_MAX + tlvCount] = currLen;
            tlvCount++;
            currLen += tlv->tlvLen;
        }
    }
    APPSPAWN_CHECK_ONLY_EXPER(currLen >= bufferLen, return APPSPAWN_MSG_INVALID);
    // save real ext tlv count
    message->tlvCount = tlvCount;
    return 0;
}

int GetAppSpawnMsgFromBuffer(const uint8_t *buffer, uint32_t bufferLen,
    AppSpawnMsgNode **outMsg, uint32_t *msgRecvLen, uint32_t *reminder)
{
    *reminder = 0;
    AppSpawnMsgNode *message = *outMsg;
    if (message == NULL) {
        message = CreateAppSpawnMsg();
        APPSPAWN_CHECK(message != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to create message");
        *outMsg = message;
    }

    uint32_t reminderLen = bufferLen;
    const uint8_t *reminderBuffer = buffer;
    if (*msgRecvLen < sizeof(AppSpawnMsg)) {  // recv partial message
        if ((bufferLen + *msgRecvLen) >= sizeof(AppSpawnMsg)) {
            int ret = memcpy_s(((uint8_t *)&message->msgHeader) + *msgRecvLen,
                sizeof(message->msgHeader) - *msgRecvLen,
                buffer, sizeof(message->msgHeader) - *msgRecvLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");

            ret = AppSpawnMsgRebuild(message, &message->msgHeader);
            APPSPAWN_CHECK(ret == 0, return -1, "Failed to alloc buffer for receive msg");
            reminderLen = bufferLen - (sizeof(message->msgHeader) - *msgRecvLen);
            reminderBuffer = buffer + sizeof(message->msgHeader) - *msgRecvLen;
            *msgRecvLen = sizeof(message->msgHeader);
        } else {
            int ret = memcpy_s(((uint8_t *)&message->msgHeader) + *msgRecvLen,
                sizeof(message->msgHeader) - *msgRecvLen, buffer, bufferLen);
            APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
            *msgRecvLen += bufferLen;
            return 0;
        }
    }
    // do not copy msg header
    uint32_t realCopy = (reminderLen + *msgRecvLen) > message->msgHeader.msgLen ?
        message->msgHeader.msgLen - *msgRecvLen : reminderLen;
    if (message->buffer == NULL) {  // only has msg header
        return 0;
    }
    APPSPAWN_LOGV("HandleRecvBuffer msgRecvLen: %{public}u reminderLen %{public}u realCopy %{public}u",
        *msgRecvLen, reminderLen, realCopy);
    int ret = memcpy_s(message->buffer + *msgRecvLen - sizeof(message->msgHeader),
        message->msgHeader.msgLen - *msgRecvLen, reminderBuffer, realCopy);
    APPSPAWN_CHECK(ret == EOK, return -1, "Failed to copy recv buffer");
    *msgRecvLen += realCopy;
    if (realCopy < reminderLen) {
        *reminder = reminderLen - realCopy;
    }
    return 0;
}

int SendAppSpawnMsgToChild(AppSpawnForkCtx *forkCtx, AppSpawnMsgNode *message)
{
    uint8_t *mem = (uint8_t *)shmat(forkCtx->shmId, NULL, 0);
    APPSPAWN_CHECK(mem != (uint8_t *)(-1),
        return -1, "Failed to attach shm errno %{public}d", errno);
    // copy msg header
    int ret = memcpy_s(mem, forkCtx->memSize, &message->msgHeader, sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(ret == 0, return APPSPAWN_SYSTEM_ERROR, "Failed to write msg header to shared memory");
    ret = memcpy_s(mem + sizeof(AppSpawnMsg), forkCtx->memSize - sizeof(AppSpawnMsg),
        message->buffer, message->msgHeader.msgLen - sizeof(AppSpawnMsg));
    APPSPAWN_CHECK(ret == 0, return APPSPAWN_SYSTEM_ERROR, "Failed to write msg header to shared memory");
    return 0;
}

int GetAppPropertyCode(const struct tagAppSpawningCtx *appProperty)
{
    return (appProperty != NULL && appProperty->message != NULL) ?
        appProperty->message->msgHeader.msgType : MAX_TYPE_INVALID;
}

const char *GetProcessName(const struct tagAppSpawningCtx *property)
{
    if (property == NULL || property->message == NULL) {
        return NULL;
    }
    return property->message->msgHeader.processName;
}

const char *GetBundleName(const struct tagAppSpawningCtx *property)
{
    AppSpawnMsgBundleInfo *info = (AppSpawnMsgBundleInfo *)GetAppSpawnMsgInfo(property->message, TLV_BUNDLE_INFO);
    if (info != NULL) {
        return info->bundleName;
    }
    return NULL;
}

pid_t GetPidFromTerminationMsg(AppSpawnMsgNode *message)
{
    pid_t *pid = (pid_t *)GetAppSpawnMsgInfo(message, TLV_RENDER_TERMINATION_INFO);
    if (pid != NULL) {
        return *pid;
    }
    return -1;
}

void *GetAppProperty(const struct tagAppSpawningCtx *property, uint32_t type)
{
    APPSPAWN_CHECK(property != NULL && property->message != NULL,
        return NULL, "Invalid property for type %{public}u", type);
    return GetAppSpawnMsgInfo(property->message, type);
}

uint8_t *GetAppPropertyEx(const struct tagAppSpawningCtx *property, const char *name, uint32_t *len)
{
    APPSPAWN_CHECK(name != NULL, return NULL, "Invalid name ");
    APPSPAWN_CHECK(property != NULL && property->message != NULL && property->message->buffer != NULL,
        return NULL, "Invalid property for name %{public}s", name);

    APPSPAWN_LOGV("GetAppPropertyEx tlvCount %{public}d name %{public}s", property->message->tlvCount, name);
    for (uint32_t index = TLV_MAX; index < (TLV_MAX + property->message->tlvCount); index++) {
        if (property->message->tlvOffset[index] >= (property->message->msgHeader.msgLen - sizeof(AppSpawnMsg))) {
            return NULL;
        }
        uint8_t *data = property->message->buffer + property->message->tlvOffset[index];
        if (((AppSpawnTlv *)data)->tlvType != TLV_MAX) {
            continue;
        }
        AppSpawnTlvEx *tlv = (AppSpawnTlvEx *)data;
        if (strcmp(tlv->tlvName, name) != 0) {
            continue;
        }
        if (len != NULL) {
            *len = tlv->dataLen;
        }
        return data + sizeof(AppSpawnTlvEx);
    }
    return NULL;
}

static inline void DumpMsgFlags(const char *info, const AppSpawnMsgFlags *msgFlags)
{
    APPSPAPWN_DUMP("%{public}s count: %{public}u ", info, msgFlags->count);
    for (uint32_t i = 0; i < msgFlags->count; i++) {
        APPSPAPWN_DUMP("%{public}s flags: 0x%{public}x", info, msgFlags->flags[i]);
    }
}

static inline void DumpMsgDacInfo(const AppSpawnMsgDacInfo *dacInfo)
{
    APPSPAPWN_DUMP("App dac info uid: %{public}d gid: %{public}d count: %{public}d",
        dacInfo->uid, dacInfo->gid, dacInfo->gidCount);
    for (uint32_t i = 0; i < dacInfo->gidCount; i++) {
        APPSPAPWN_DUMP("gid group[%{public}d]: %{public}d", i, dacInfo->gidTable[i]);
    }
}

static inline void DumpMsgExInfo(const AppSpawnTlv *tlv)
{
    if (tlv->tlvType != TLV_MAX) {
        APPSPAPWN_DUMP("App tlv info: [%{public}d %{public}d]", tlv->tlvType, tlv->tlvLen);
        return;
    }
    AppSpawnTlvEx *tlvEx = (AppSpawnTlvEx *)(tlv);
    APPSPAPWN_DUMP("App extend info name: %{public}s len: %{public}u",tlvEx->tlvName, tlvEx->dataLen);
    if (tlvEx->dataType == DATA_TYPE_STRING) {
        APPSPAPWN_DUMP("App extend info value: '%{public}s'", (char *)(tlvEx + 1));
    }
}

void DumpNormalProperty(const AppSpawningCtx *property)
{
    APPSPAWN_CHECK_ONLY_EXPER(property != NULL && property->message != NULL, return);
    for (uint32_t i = 0; i < TLV_MAX + property->message->tlvCount; i++) {
        if (property->message->tlvOffset[i] == INVALID_OFFSET) {
            continue;
        }
        AppSpawnTlv *tlv = (AppSpawnTlv *)(property->message->buffer + property->message->tlvOffset[i]);
        switch (tlv->tlvType) {
            case TLV_MSG_FLAGS:
                DumpMsgFlags("property flags", (AppSpawnMsgFlags *)(tlv + 1));
                break;
            case TLV_PERMISSION:
                DumpMsgFlags("permission flags", (AppSpawnMsgFlags *)(tlv + 1));
                break;
            case TLV_ACCESS_TOKEN_INFO:
                APPSPAPWN_DUMP("App access token info: %{public}" PRId64 "",
                    ((AppSpawnMsgAccessToken *)(tlv + 1))->accessTokenIdEx);
                break;
            case TLV_DAC_INFO:
                DumpMsgDacInfo((AppSpawnMsgDacInfo *)(tlv + 1));
                break;
            case TLV_BUNDLE_INFO:
                APPSPAPWN_DUMP("App bundle info name: \"%{public}s\" index: %{public}d",
                    ((AppSpawnMsgBundleInfo *)(tlv + 1))->bundleName,
                    ((AppSpawnMsgBundleInfo *)(tlv + 1))->bundleIndex);
                break;
            case TLV_OWNER_INFO:
                APPSPAPWN_DUMP("App owner info: \"%{public}s\" ", ((AppSpawnMsgOwnerId *)(tlv + 1))->ownerId);
                break;
            case TLV_DOMAIN_INFO:
                APPSPAPWN_DUMP("App domain info hap: 0x%{public}x apl: \"%{public}s\"",
                    ((AppSpawnMsgDomainInfo *)(tlv + 1))->hapFlags, ((AppSpawnMsgDomainInfo *)(tlv + 1))->apl);
                break;
            case TLV_INTERNET_INFO:
                APPSPAPWN_DUMP("App internet permission info [%{public}d %{public}d]",
                    ((AppSpawnMsgInternetInfo *)(tlv + 1))->setAllowInternet,
                    ((AppSpawnMsgInternetInfo *)(tlv + 1))->allowInternet);
                break;
            default:
                DumpMsgExInfo(tlv);
                break;
        }
    }
}
