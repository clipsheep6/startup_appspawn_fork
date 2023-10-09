/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include <fstream>
#include <sstream>
#include "appspawn_mount_permission.h"
#include "nlohmann/json.hpp"
#include "appspawn_server.h"  

namespace OHOS {
namespace AppSpawn {
std::string AppspawnMountPermission::appPermissionPath("/system/etc/sandbox/appdata-sandbox.json");
std::string AppspawnMountPermission::g_permission("permission");
std::set<std::string> AppspawnMountPermission::appSandboxPremission_ = {};
bool AppspawnMountPermission::g_IsLoad = false;
std::mutex AppspawnMountPermission::g_mutex;

void AppspawnMountPermission::LoadPermissionNames(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    nlohmann::json appSandboxPremission;
    std::string path = appPermissionPath;
    APPSPAWN_LOGI("LoadPermissionNames %{public}s", path.c_str());
	std::ifstream jsonFileStream;
    jsonFileStream.open(path.c_str(), std::ios::in);
    APPSPAWN_CHECK_ONLY_EXPER(jsonFileStream.is_open(), return);
    std::ostringstream buf;
    char ch;
    while (buf && jsonFileStream.get(ch)) {
        buf.put(ch);
    }
    jsonFileStream.close();
    appSandboxPremission = nlohmann::json::parse(buf.str(), nullptr, false);
    APPSPAWN_CHECK(appSandboxPremission.is_structured(), return, "Parse json file into jsonObj failed.");
    for (auto config : appSandboxPremission[g_permission]) {
        for (auto it : config.items()) {
            APPSPAWN_LOGI("LoadPermissionNames %{public}s", it.key().c_str());
            appSandboxPremission_.insert(it.key());
        }
    }
    APPSPAWN_LOGI("LoadPermissionNames size: %{public}lu", static_cast<unsigned long>(appSandboxPremission_.size()));
    g_IsLoad = true;
}

std::set<std::string> AppspawnMountPermission::GetMountPermissionList()
{
    if(!g_IsLoad){
        LoadPermissionNames();
        APPSPAWN_LOGI("GetMountPermissionList LoadPermissionNames");
    }
    return appSandboxPremission_;
}

uint32_t AppspawnMountPermission::GenPermissionCode(const std::set<std::string> &permissions)
{
    uint32_t result = 0;
    if (permissions.size() == 0) {
        return result;
    }
    uint32_t flagIndex = 1;
    for (std::string mountPermission : GetMountPermissionList()) {
        for (std::string inputPermission : permissions) {
            if (mountPermission.compare(inputPermission) == 0) {
                result |= flagIndex;
            }
        }
        flagIndex <<= 1;
    }
    return result;
}

bool AppspawnMountPermission::IsMountPermission(uint32_t code, const std::string permission)
{
    for (std::string mountPermission : GetMountPermissionList()) {
        if (mountPermission.compare(permission) == 0) {
            return code & 1;
        }
        code >>= 1;
    }
    return false;
} // AppSpawn
} // OHOS
}
