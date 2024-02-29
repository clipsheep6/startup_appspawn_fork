/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "sandbox_utils.h"

#include <climits>
#include <fstream>
#include <sstream>
#include <vector>

#include "appspawn_utils.h"
#include "config_policy_utils.h"
#include "securec.h"

using namespace std;
using namespace OHOS;

namespace OHOS {
namespace AppSpawn {
namespace {
const std::string APP_JSON_CONFIG("/appdata-sandbox.json");
}

std::string SandboxUtils::GetStringFromJson(const nlohmann::json &json, const std::string &key)
{
    APPSPAWN_CHECK(json.is_object(), return "", "json is not object.");
    bool isRet = json.find(key) != json.end() && json.at(key).is_string();
    if (isRet) {
        return json.at(key).get<std::string>();
    }
    return "";
}

bool SandboxUtils::GetBoolValueFromJson(const nlohmann::json &config, const std::string &key, bool def)
{
    if (config.find(key) != config.end()) {
        std::string v = config[key].get<std::string>();
        if (v == "true" || v == "ON" || v == "True") {
            return true;
        }
    }
    return def;
}

uint32_t SandboxUtils::GetIntValueFromJson(const nlohmann::json &config, const std::string &key, uint32_t def)
{
    if (config.find(key) != config.end()) {
        return config[key].get<uint32_t>();
    }
    return def;
}

std::vector<std::string> SandboxUtils::split(std::string &str, const std::string &pattern)
{
    std::string::size_type pos;
    std::vector<std::string> result;
    str += pattern;
    size_t size = str.size();

    for (unsigned int i = 0; i < size; i++) {
        pos = str.find(pattern, i);
        if (pos < size) {
            std::string tempStr = str.substr(i, pos - i);
            tempStr = tempStr.substr(tempStr.find_first_not_of(" \n\r\t"));
            tempStr = tempStr.substr(0, tempStr.find_last_not_of(" \n\r\t") + 1);
            result.push_back(tempStr);
            i = pos + pattern.size() - 1;
        }
    }

    return result;
}

bool SandboxUtils::GetJsonObjFromJson(nlohmann::json &jsonObj, const std::string &jsonPath)
{
    APPSPAWN_CHECK(jsonPath.length() <= PATH_MAX, return false, "jsonPath is too long");
    std::ifstream jsonFileStream;
    jsonFileStream.open(jsonPath.c_str(), std::ios::in);
    APPSPAWN_CHECK_ONLY_EXPER(jsonFileStream.is_open(), return false);
    std::ostringstream buf;
    char ch;
    while (buf && jsonFileStream.get(ch)) {
        buf.put(ch);
    }
    jsonFileStream.close();
    jsonObj = nlohmann::json::parse(buf.str(), nullptr, false);
    APPSPAWN_CHECK(jsonObj.is_structured(), return false, "Parse json file into jsonObj failed.");
    return true;
}

int SandboxUtils::GetSandboxConfigs(std::vector<nlohmann::json> &jsonConfigs)
{
    // load sandbox config
    nlohmann::json appSandboxConfig;
    CfgFiles *files = GetCfgFiles("etc/sandbox");
    if (files == nullptr) {
        return APPSPAWN_NO_SANDBOX;
    }
    for (int i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        if (files->paths[i] == nullptr) {
            continue;
        }
        std::string path = files->paths[i];
        path += APP_JSON_CONFIG;
        APPSPAWN_LOGI("LoadAppSandboxConfig %{public}s", path.c_str());
        bool rc = GetJsonObjFromJson(appSandboxConfig, path);
        APPSPAWN_CHECK(rc, return APPSPAWN_LOAD_SANDBOX_FAIL,
            "Failed to load app data sandbox config %{public}s", path.c_str());
        jsonConfigs.push_back(appSandboxConfig);
    }
    FreeCfgFiles(files);
    return 0;
}
}  // namespace AppSpawn
}  // namespace OHOS
