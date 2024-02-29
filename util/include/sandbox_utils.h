/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_UTILS_H
#define SANDBOX_UTILS_H

#include <string>
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppSpawn {
class SandboxUtils {
public:
    static std::vector<std::string> split(std::string &str, const std::string &pattern);
    static int GetSandboxConfigs(std::vector<nlohmann::json> &jsonConfigs);
    static bool GetJsonObjFromJson(nlohmann::json &jsonObj, const std::string &jsonPath);
    static std::string GetStringFromJson(const nlohmann::json &json, const std::string &key);
    static bool GetBoolValueFromJson(const nlohmann::json &config, const std::string &key, bool def = false);
    static uint32_t GetIntValueFromJson(const nlohmann::json &config, const std::string &key, uint32_t def = 0);
};
}  // namespace AppSpawn
}  // namespace OHOS
#endif  // SANDBOX_UTILS_H
