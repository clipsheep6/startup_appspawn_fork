/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "appspawn_silk.h"
#include <set>
#include "appspawn_server.h"
#include "json_utils.h"

using namespace OHOS::AppSpawn;

static const std::string ENABLED_SILK_JSON_CONFIG("/vendor/etc/silk/silk.json");
static const std::string ENABLED_SILK_APP_LIST_KEY("enabled_app_list");
std::set<std::string> g_enabledSilkApps = {};

static void GetEnabledAppNameArray(const std::string &configName,
                                   const std::string &keyName,
                                   std::set<std::string> &enabledAppNameArray)
{
    nlohmann::json silkJson;
    bool rc = JsonUtils::GetJsonObjFromJson(silkJson, configName);
    if (rc == false) {
        APPSPAWN_LOGV("config is not exist %{public}s", configName.c_str());
        return;
    }
    APPSPAWN_CHECK_ONLY_EXPER(rc, return);
    if (silkJson.find(keyName) == silkJson.end()) {
        return;
    }

    nlohmann::json appListJson = silkJson[keyName];
    uint32_t appCount = appListJson.size();
    for (uint32_t i = 0; i < appCount; ++i) {
        nlohmann::json appName = appListJson[i];
        if (!enabledAppNameArray.count(appName.get<std::string>())) {
            APPSPAWN_LOGI("Enable silk appName %{public}s", appName.get<std::string>().c_str());
            enabledAppNameArray.insert(appName.get<std::string>());
        }
    }
}

void ParseSilkConfig(void)
{
    GetEnabledAppNameArray(ENABLED_SILK_JSON_CONFIG, ENABLED_SILK_APP_LIST_KEY, g_enabledSilkApps);
}

bool IsSilkEnabled(const char *packageName)
{
    bool isEnabled = false;

    for (std::string appName : g_enabledSilkApps) {
        if (appName.compare(packageName) == 0) {
            isEnabled = true;
            APPSPAWN_LOGI("Enable Silk AppName %{public}s", appName.c_str());
        }
    }
    return isEnabled;
}
