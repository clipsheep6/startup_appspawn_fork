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

#include "appspawn_adapter.h"

#include "appspawn_hook.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "access_token.h"
#include "token_setproc.h"
#include "tokenid_kit.h"
#include "nlohmann/json.hpp"

#ifdef WITH_SELINUX
#include "hap_restorecon.h"
#include "selinux/selinux.h"
#endif
#ifdef WITH_SECCOMP
#include "seccomp_policy.h"
#include <sys/prctl.h>
const char *RENDERER_NAME = "renderer";
#endif

#define NWEBSPAWN_SERVER_NAME "nwebspawn"
using namespace OHOS::Security::AccessToken;

int SetAppAccessToken(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s", "SetAppAccessToken");
    int32_t ret = 0;
    uint64_t tokenId = 0;
    AppSpawnMsgAccessToken *tokenInfo = (AppSpawnMsgAccessToken *)GetAppProperty(property, TLV_ACCESS_TOKEN_INFO);
    APPSPAWN_CHECK(tokenInfo != NULL, return APPSPAWN_INVALID_MSG,
        "No access token in msg %{public}s", GetProcessName(property));
    APPSPAWN_LOGV("AppSpawnServer::set access token %{public}" PRId64 ", accessTokenId  %{public}u %{public}d",
        tokenInfo->accessTokenIdEx, tokenInfo->accessTokenId, IsNWebSpawnMode(content));

    if (IsNWebSpawnMode(content)) {
        TokenIdKit tokenIdKit;
        tokenId = tokenIdKit.GetRenderTokenID(tokenInfo->accessTokenIdEx);
    } else {
        tokenId = tokenInfo->accessTokenIdEx;
    }
    ret = SetSelfTokenID(tokenId);
    APPSPAWN_CHECK(ret == 0, return APPSPAWN_INVALID_ACCESS_TOKEN,
        "set access token id failed, ret: %{public}d %{public}s", ret, GetProcessName(property));

    APPSPAWN_LOGV("SetAppAccessToken success for %{public}s", GetProcessName(property));
    return 0;
}

int SetSelinuxCon(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
#ifdef WITH_SELINUX
    APPSPAWN_LOGV("SetSelinuxCon IsDeveloperModeOn %{public}d", IsDeveloperModeOn(property));
    if (GetAppPropertyCode(property) == MSG_SPAWN_NATIVE_PROCESS) {
        if (!IsDeveloperModeOn(property)) {
            APPSPAWN_LOGE("Denied Launching a native process: not in developer mode");
            return APPSPAWN_NOT_SUPPORT_NATIVE;
        }
        return 0;
    }
    if (IsNWebSpawnMode(content)) {
        setcon("u:r:isolated_render:s0");
        return 0;
    }
    AppSpawnMsgDomainInfo *msgDomainInfo = (AppSpawnMsgDomainInfo *)GetAppProperty(property, TLV_DOMAIN_INFO);
    APPSPAWN_CHECK(msgDomainInfo != NULL, return APPSPAWN_NO_TLV,
        "No domain info in req form %{public}s", GetProcessName(property))
    HapContext hapContext;
    HapDomainInfo hapDomainInfo;
    hapDomainInfo.apl = msgDomainInfo->apl;
    hapDomainInfo.packageName = GetProcessName(property);
    hapDomainInfo.hapFlags = msgDomainInfo->hapFlags;
    if (TestAppMsgFlagsSet(property, APP_FLAGS_DEBUGGABLE)) {
        hapDomainInfo.hapFlags |= SELINUX_HAP_DEBUGGABLE;
    }
    int32_t ret = hapContext.HapDomainSetcontext(hapDomainInfo);
    if (TestAppMsgFlagsSet(property, APP_FLAGS_ASANENABLED)) {
        ret = 0;
    }
    APPSPAWN_CHECK(ret == 0, return APPSPAWN_INVALID_ACCESS_TOKEN,
        "Set domain context failed, ret: %{public}d %{public}s", ret, GetProcessName(property));
    APPSPAWN_LOGV("SetSelinuxCon success for %{public}s", GetProcessName(property));
#endif
    return 0;
}

int SetUidGidFilter(const AppSpawnMgr *content)
{
#ifdef WITH_SECCOMP
    bool ret = false;
    if (IsNWebSpawnMode(content)) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
            APPSPAWN_LOGE("Failed to set no new privs");
        }
        ret = SetSeccompPolicyWithName(INDIVIDUAL, NWEBSPAWN_NAME);
    } else {
        ret = SetSeccompPolicyWithName(INDIVIDUAL, APPSPAWN_NAME);
    }
    if (!ret) {
        APPSPAWN_LOGE("Failed to set APPSPAWN seccomp filter and exit");
        _exit(0x7f);
    }
    APPSPAWN_LOGV("SetUidGidFilter success");
#endif
    return 0;
}

int SetSeccompFilter(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
#ifdef WITH_SECCOMP
    const char *appName = APP_NAME;
    SeccompFilterType type = APP;
    if (IsNWebSpawnMode(content)) {
        return 0;
    }
    if (!SetSeccompPolicyWithName(type, appName)) {
        APPSPAWN_LOGE("Failed to set %{public}s seccomp filter and exit", appName);
        return -EINVAL;
    }
    APPSPAWN_LOGV("SetSeccompFilter success for %{public}s", GetProcessName(property));
#endif
    return 0;
}

int SetInternetPermission(const AppSpawningCtx *property)
{
    AppSpawnMsgInternetInfo *info = (AppSpawnMsgInternetInfo *)GetAppProperty(property, TLV_INTERNET_INFO);
    APPSPAWN_CHECK(info != NULL, return 0,
        "No tlv internet permission info in req form %{public}s", GetProcessName(property));
    APPSPAWN_LOGV("SetInternetPermission %{public}d %{public}d",  info->setAllowInternet, info->allowInternet);
    if (info->setAllowInternet == 1 && info->allowInternet == 0) {
        DisallowInternet();
    }
    return 0;
}

int32_t SetEnvInfo(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    uint32_t size = 0;
    char *envStr = reinterpret_cast<char *>(GetAppPropertyEx(property, "AppEnv", &size));
    if (size == 0 || envStr == NULL) {
        return 0;
    }
    int ret = 0;
    std::string appEnvInfo(envStr);
    nlohmann::json envs = nlohmann::json::parse(appEnvInfo.c_str(), nullptr, false);
    APPSPAWN_CHECK(!envs.is_discarded(), return -1, "SetEnvInfo: json parse failed");

    for (nlohmann::json::iterator it = envs.begin(); it != envs.end(); ++it) {
        APPSPAWN_CHECK(it.value().is_string(), return -1, "SetEnvInfo: element type error");
        std::string name = it.key();
        std::string value = it.value();
        ret = setenv(name.c_str(), value.c_str(), 1);
        APPSPAWN_CHECK(ret == 0, return ret, "setenv failed, errno: %{public}d", errno);
    }
    return ret;
}
