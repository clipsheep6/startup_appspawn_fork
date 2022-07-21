/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include <algorithm>
#include <ctime>
#include <map>
#include <string>
#include "application_info.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "appspawn_service.h"
#include "appspawn_adapter.h"
struct RenderProcessNode {
    RenderProcessNode(time_t now, int exit):recordTime_(now), exitStatus_(exit) {}
    time_t recordTime_;
    int exitStatus_;
};

namespace {
    constexpr int32_t RENDER_PROCESS_MAX_NUM = 16;
    std::map<int32_t, RenderProcessNode> g_renderProcessMap;
    void *g_nwebHandle = nullptr;
    std::string LOAD_LIB_DIR;
}

OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr()
{
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        APPSPAWN_LOGE("GetBundleMgr GetSystemAbilityManager is null");
        return nullptr;
    }
    auto bundleMgrSa = samgr->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APPSPAWN_LOGE("GetBundleMgr GetSystemAbility is null");
        return nullptr;
    }
    return OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(bundleMgrSa);
}

bool GetNativeLibraryPath(void)
{
    const std::string NWEB_BUNDLE_NAME = "com.ohos.nweb";
    std::vector<int> userIds;
    if (OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds) != OHOS::ERR_OK) {
        APPSPAWN_LOGE("QueryActiveOsAccountIds failed!");
        return false;
    }
    if (userIds.empty()) {
        APPSPAWN_LOGE("QueryActiveOsAccountIds userIds empty");
        return false;
    }
    auto reqUserId = userIds[0];
    auto iBundleMgr = GetBundleMgr();
    if (!iBundleMgr) {
        APPSPAWN_LOGE("can not get iBundleMgr");
        return false;
    }
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    bool result = iBundleMgr->
        GetApplicationInfo(NWEB_BUNDLE_NAME, OHOS::AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, reqUserId, appInfo);
    if (!result) {
        APPSPAWN_LOGE("GetApplicationInfo failed");
        return false;
    }
    LOAD_LIB_DIR = appInfo.codePath + "/" + appInfo.nativeLibraryPath;
    return true;
}

void LoadExtendLib(AppSpawnContent *content)
{
    if (!GetNativeLibraryPath()) {
        APPSPAWN_LOGE("GetNativeLibraryPath failed");
        return;
    }
#ifdef __MUSL__
    Dl_namespace dlns;
    dlns_init(&dlns, "nweb_ns");
    dlns_create(&dlns, LOAD_LIB_DIR.c_str());
    void *handle = dlopen_ns(&dlns, "libweb_engine.so", RTLD_NOW | RTLD_GLOBAL);
#else
    const std::string ENGINE_LIB_DIR = LOAD_LIB_DIR + "/libweb_engine.so";
    void *handle = dlopen(ENGINE_LIB_DIR.c_str(), RTLD_NOW | RTLD_GLOBAL);
#endif
    if (handle == nullptr) {
        APPSPAWN_LOGE("Fail to dlopen libweb_engine.so, [%s]", dlerror());
    } else {
        APPSPAWN_LOGI("Success to dlopen libweb_engine.so");
    }

#ifdef __MUSL__
    g_nwebHandle = dlopen_ns(&dlns, "libnweb_render.so", RTLD_NOW | RTLD_GLOBAL);
#else
    const std::string RENDER_LIB_DIR = LOAD_LIB_DIR + "/libnweb_render.so";
    g_nwebHandle = dlopen(RENDER_LIB_DIR.c_str(), RTLD_NOW | RTLD_GLOBAL);
#endif
    if (g_nwebHandle == nullptr) {
        APPSPAWN_LOGE("Fail to dlopen libnweb_render.so, [%s]", dlerror());
    } else {
        APPSPAWN_LOGI("Success to dlopen libnweb_render.so");
    }
}

void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    using FuncType = void (*)(const char *cmd);

    FuncType funcNWebRenderMain = reinterpret_cast<FuncType>(dlsym(g_nwebHandle, "NWebRenderMain"));
    if (funcNWebRenderMain == nullptr) {
        APPSPAWN_LOGI("webviewspawn dlsym ERROR=%s", dlerror());
        return;
    }

    funcNWebRenderMain(appProperty->property.renderCmd);
}

static void DumpRenderProcessExitedMap()
{
    APPSPAWN_LOGI("dump render process exited array:");

    for (auto& it : g_renderProcessMap) {
        APPSPAWN_LOGV("[pid, time, exitedStatus] = [%d, %ld, %d]",
            it.first, it.second.recordTime_, it.second.exitStatus_);
    }
}

void RecordRenderProcessExitedStatus(pid_t pid, int status)
{
    if (g_renderProcessMap.size() < RENDER_PROCESS_MAX_NUM) {
        RenderProcessNode node(time(nullptr), status);
        g_renderProcessMap.insert({pid, node});
        return;
    }

    APPSPAWN_LOGV("render process map size reach max, need to erase oldest data.");
    DumpRenderProcessExitedMap();
    auto oldestData = std::min_element(g_renderProcessMap.begin(), g_renderProcessMap.end(),
        [](const std::pair<int32_t, RenderProcessNode>& left, const std::pair<int32_t, RenderProcessNode>& right) {
            return left.second.recordTime_ < right.second.recordTime_;
        });

    g_renderProcessMap.erase(oldestData);
    RenderProcessNode node(time(nullptr), status);
    g_renderProcessMap.insert({pid, node});
    DumpRenderProcessExitedMap();
}

int GetRenderProcessTerminationStatus(int32_t pid, int *status)
{
    if (status == nullptr) {
        return -1;
    }

    auto it = g_renderProcessMap.find(pid);
    if (it != g_renderProcessMap.end()) {
        *status = it->second.exitStatus_;
        g_renderProcessMap.erase(it);
        return 0;
    }

    APPSPAWN_LOGE("not find pid[%d] in render process exited map", pid);
    DumpRenderProcessExitedMap();
    return -1;
}
