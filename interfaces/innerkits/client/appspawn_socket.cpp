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

#include "appspawn_socket.h"

#include <cerrno>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/socket.h>

#ifdef APPSPAWN_NEW_CLIENT
#include "appspawn_msg.h"
#include "interfaces/innerkits_new/include/appspawn.h"
#include "interfaces/innerkits_new/module_engine/include/appspawn_msg.h"
#else
#include "pubdef.h"
#endif
#include "appspawn_utils.h"
#include "securec.h"

namespace OHOS {
namespace AppSpawn {
AppSpawnSocket::AppSpawnSocket(const std::string &name)
{
    socketName_ = name;
}

AppSpawnSocket::~AppSpawnSocket()
{
    if (socketFd_ > 0) {
        CloseSocket(socketFd_);
        socketFd_ = -1;
    }
}

int AppSpawnSocket::GetSocketFd() const
{
    return socketFd_;
}

int AppSpawnSocket::PackSocketAddr()
{
    APPSPAWN_CHECK(!socketName_.empty(), return -EINVAL, "Invalid socket name: empty");
    (void)memset_s(&socketAddr_, sizeof(socketAddr_), 0, sizeof(socketAddr_));

    socklen_t pathLen = 0;
    if (socketName_[0] == '/') {
        pathLen = socketName_.length();
    } else {
        pathLen = socketDir_.length() + socketName_.length();
    }
    socklen_t pathSize = sizeof(socketAddr_.sun_path);
    if (pathLen >= pathSize) {
        APPSPAWN_LOGE("Invalid socket name: '%{public}s' too long", socketName_.c_str());
        return -1;
    }

    int len = 0;
    if (socketName_[0] == '/') {
        len = snprintf_s(socketAddr_.sun_path, pathSize, (pathSize - 1), "%s", socketName_.c_str());
    } else {
        len = snprintf_s(socketAddr_.sun_path, pathSize, (pathSize - 1), "%s%s",
            socketDir_.c_str(), socketName_.c_str());
    }
    APPSPAWN_CHECK(static_cast<int>(pathLen) == len, return -1, "Failed to copy socket path");

    socketAddr_.sun_family = AF_LOCAL;
    socketAddrLen_ = offsetof(struct sockaddr_un, sun_path) + pathLen + 1;

    return 0;
}

int AppSpawnSocket::CreateSocket()
{
    int socketFd = socket(AF_UNIX, SOCK_STREAM, 0);  // SOCK_SEQPACKET
    APPSPAWN_CHECK(socketFd >= 0, return -errno, "Failed to create socket: %{public}d", errno);

    int flag = 1;
    int ret = setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    APPSPAWN_LOGV("Created socket with fd %{public}d, setsockopt %{public}d", socketFd, ret);
    return socketFd;
}

void AppSpawnSocket::CloseSocket(int &socketFd)
{
    if (socketFd >= 0) {
        APPSPAWN_LOGV("Closed socket with fd %{public}d", socketFd);
        int flag = 0;
        setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        close(socketFd);
        socketFd = -1;
    }
}

int AppSpawnSocket::ReadSocketMessage(int socketFd, void *buf, int len)
{
    if (socketFd < 0 || len <= 0 || buf == nullptr) {
        APPSPAWN_LOGE("Invalid args: socket %{public}d, len %{public}d, buf might be nullptr", socketFd, len);
        return -1;
    }
#ifndef APPSPAWN_NEW_CLIENT
    APPSPAWN_CHECK(memset_s(buf, len, 0, len) == EOK, return -1, "Failed to memset read buf");

    ssize_t rLen = TEMP_FAILURE_RETRY(read(socketFd, buf, len));
    while ((rLen < 0) && (errno == EAGAIN)) {
        rLen = TEMP_FAILURE_RETRY(read(socketFd, buf, len));
    }
    APPSPAWN_CHECK(rLen >= 0, return -EFAULT,
        "Read message from fd %{public}d error %{public}zd: %{public}d", socketFd, rLen, errno);
    return rLen;
#else
    APPSPAWN_LOGV("ReadSocketMessage result_ %{public}d, childPid_ %{public}d", result_, childPid_);
    if (result_ == 0) {
        (void)memcpy_s(buf, len, &childPid_, sizeof(childPid_));
        return sizeof(childPid_);
    }
    return -EFAULT;
#endif
}

#ifdef APPSPAWN_NEW_CLIENT
static std::string GetExtraInfoByType(const AppParameter *parameter, const std::string &type)
{
    if (parameter->extraInfo.totalLength == 0 || parameter->extraInfo.data == nullptr) {
        return "";
    }

    std::string extraInfoStr = std::string(parameter->extraInfo.data);
    std::size_t firstPos = extraInfoStr.find(type);
    if (firstPos == std::string::npos && firstPos != (extraInfoStr.size() - 1)) {
        return "";
    }

    extraInfoStr = extraInfoStr.substr(firstPos + type.size());
    std::size_t secondPos = extraInfoStr.find(type);
    if (secondPos == std::string::npos) {
        return "";
    }
    return extraInfoStr.substr(0, secondPos);
}

static int AddBaseTlv(AppSpawnClientHandle clientHandle, const AppParameter *parameter, AppSpawnReqMsgHandle reqHandle)
{
    int ret = AppSpawnReqMsgSetBundleInfo(reqHandle, parameter->bundleIndex, parameter->bundleName);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add bundle info");

    AppDacInfo dacInfo;
    dacInfo.uid = parameter->uid;
    dacInfo.gid = parameter->gid;
    dacInfo.gidCount = parameter->gidCount;
    (void)memcpy_s(dacInfo.gidTable, sizeof(dacInfo.gidTable), parameter->gidTable, sizeof(dacInfo.gidTable));
    ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add dac info ");

    for (uint32_t i = 0; i < 32; i++) {  // 32 bits
        if (((parameter->flags >> i) & 0x1) == 1) {
            APPSPAWN_LOGV("AddBaseTlv flags %{public}d", i);
            AppSpawnReqMsgSetAppFlag(reqHandle, i);
        }
    }

    ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, parameter->hapFlags, parameter->apl);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add domain info ");

    ret = AppSpawnReqMsgSetAppInternetPermissionInfo(reqHandle, parameter->allowInternet, parameter->setAllowInternet);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add interPermission ");

    if (strlen(parameter->ownerId) > 0) {
        ret = AppSpawnReqMsgSetAppOwnerId(reqHandle, parameter->ownerId);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add ownerId info ");
    }

    if (strlen(parameter->renderCmd) > 0) {
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, MSG_EXT_NAME_RENDER_CMD, parameter->renderCmd);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add renderCmd ");
    }
    ret = AppSpawnReqMsgSetAppAccessToken(reqHandle, parameter->accessTokenIdEx);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add ownerId info");
    return 0;
}

int AppSpawnSocket::SendMessage(const uint8_t *buffer, uint32_t bufferLen)
{
    int ret = 0;
    if (clientHandle_ == nullptr) {
        ret = AppSpawnClientInit(socketName_.c_str(), &clientHandle_);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to create client %{public}s", socketName_.c_str());
    }
    const AppParameter *parameter = reinterpret_cast<const AppParameter *>(buffer);
    AppSpawnReqMsgHandle reqHandle = 0;
    ret = AppSpawnReqMsgCreate(static_cast<uint32_t>(parameter->code), parameter->processName, &reqHandle);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create req %{public}s", socketName_.c_str());
    ret = AddBaseTlv(clientHandle_, parameter, reqHandle);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create req %{public}s", socketName_.c_str());

    ret = AppSpawnReqMsgSetFlags(reqHandle, TLV_PERMISSION, parameter->mountPermissionFlags);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to add permission flags info req %{public}s", socketName_.c_str());

    std::string strExt = GetExtraInfoByType(parameter, "|HspList|");
    if (!strExt.empty()) {
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "HspList", strExt.c_str());
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add HspList %{public}s", socketName_.c_str());
    }
    strExt = GetExtraInfoByType(parameter, "|Overlay|");
    if (!strExt.empty()) {
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "Overlay", strExt.c_str());
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add Overlay %{public}s", socketName_.c_str());
    }
    strExt = GetExtraInfoByType(parameter, "|DataGroup|");
    if (!strExt.empty()) {
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "DataGroup", strExt.c_str());
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add DataGroup %{public}s", socketName_.c_str());
    }
    strExt = GetExtraInfoByType(parameter, "|AppEnv|");
    if (!strExt.empty()) {
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, "AppEnv", strExt.c_str());
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add AppEnv %{public}s", socketName_.c_str());
    }
    AppSpawnResult result = {};
    ret = AppSpawnClientSendMsg(clientHandle_, reqHandle, &result);
    result_ = ret;
    APPSPAWN_LOGV("WriteSocketMessage processName: %{public}s ret: %{public}d, childPid_: %{public}d",
        parameter->processName, ret, result.pid);
    if (ret == 0 && result.pid > 0) {
        childPid_ = (pid_t)result.pid;
        return 0;
    }
    return ret;
}
#endif

int AppSpawnSocket::WriteSocketMessage(int socketFd, const void *buf, int len)
{
    if (socketFd < 0 || len <= 0 || buf == nullptr) {
        APPSPAWN_LOGE("Invalid args: socket %{public}d, len %{public}d, buf might be nullptr", socketFd, len);
        return -1;
    }
#ifdef APPSPAWN_NEW_CLIENT
    int ret = 0;
    if (currMsgLen_ == 0) {
        const AppParameter *parameter = reinterpret_cast<const AppParameter *>(buf);
        if (parameter->extraInfo.totalLength == 0) {
            ret = SendMessage(reinterpret_cast<const uint8_t *>(buf), static_cast<uint32_t>(len));
            currMsgLen_ = 0;
            if (ret == 0) {
                return len;
            }
        }
        message_.resize(sizeof(AppParameter) + parameter->extraInfo.totalLength);
        ret = memcpy_s(message_.data(), message_.size(), buf, len);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to copy msg: %{public}u recv: %{public}u", currMsgLen_, len);
        currMsgLen_ = len;
        APPSPAWN_LOGV("WriteSocketMessage total %{public}u", message_.size());
    } else if ((currMsgLen_ + len) > message_.size()) {
        APPSPAWN_LOGE("WriteSocketMessage invalid msg: %{public}u recv: %{public}u", currMsgLen_, len);
        return -1;
    } else {
        ret = memcpy_s(message_.data() + currMsgLen_, message_.size() - currMsgLen_, buf, len);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to copy msg: %{public}u recv: %{public}u", currMsgLen_, len);
        currMsgLen_ += len;
    }
    if (currMsgLen_ < message_.size()) {
        return len;
    }
    ret = SendMessage(message_.data(), message_.size());
    message_.clear();
    currMsgLen_ = 0;
    return (ret == 0) ? len : ret;
#else
    ssize_t written = 0;
    ssize_t remain = static_cast<ssize_t>(len);
    const uint8_t *offset = reinterpret_cast<const uint8_t *>(buf);
    for (ssize_t wLen = 0; remain > 0; offset += wLen, remain -= wLen, written += wLen) {
        wLen = write(socketFd, offset, remain);
        APPSPAWN_LOGV("socket fd %{public}d, wLen %{public}zd", socketFd, wLen);
        bool isRet = (wLen <= 0) && (errno != EINTR);
        APPSPAWN_CHECK(!isRet, return -errno,
            "Failed to write message to fd %{public}d, error %{public}zd: %{public}d", socketFd, wLen, errno);
    }
    return written;
#endif
}
}  // namespace AppSpawn
}  // namespace OHOS
