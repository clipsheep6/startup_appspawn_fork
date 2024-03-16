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

#include <set>
#include <fstream>
#include <sstream>
#include "interfaces/innerkits/include/appspawn_mount_permission.h"
#include "interfaces/innerkits_new/permission/appspawn_mount_permission.h"
#include "config_policy_utils.h"
#include "appspawn_utils.h"

namespace OHOS {
namespace AppSpawn {
namespace {
const std::string APP_PERMISSION_PATH("/appdata-sandbox.json");
const std::string PERMISSION_FIELD("permission");
}
std::set<std::string> AppspawnMountPermission::appSandboxPremission_ = {};
bool AppspawnMountPermission::isLoad_ = false;
std::mutex AppspawnMountPermission::mutex_;

void AppspawnMountPermission::LoadPermissionNames(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isLoad_) {
        return;
    }
    appSandboxPremission_.clear();
    int max = GetMaxPermissionIndex();
    for (int i = 0; i < max; i++) {
        const char *name = GetPermissionByIndex(i);
        if (name != nullptr) {
            appSandboxPremission_.insert(std::string(name));
        }
    }
    APPSPAWN_LOGI("LoadPermissionNames size: %{public}lu", static_cast<unsigned long>(appSandboxPremission_.size()));
    isLoad_ = true;
}

std::set<std::string> AppspawnMountPermission::GetMountPermissionList()
{
    if (!isLoad_) {
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
    for (std::string inputPermission : permissions) {
        int index = GetPermissionIndex(inputPermission.c_str());
        if (index == INVALID_PERMISSION_INDEX) {
            continue;
        }
        result |= index <<= 1;
    }
    return result;
}

bool AppspawnMountPermission::IsMountPermission(uint32_t code, const std::string permission)
{
    int index = GetPermissionIndex(permission.c_str());
    if (index != INVALID_PERMISSION_INDEX) {
        return (code >> index) & 1;
    }
    return false;
} // AppSpawn
} // OHOS
}
