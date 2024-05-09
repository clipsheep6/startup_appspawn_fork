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
#include <cstring>
#include <set>
#include <string>
#include <dlfcn.h>
#include <fstream>
#include "appspawn_silk.h"
#include "appspawn_server.h"
#include "cJSON.h"
#include "json_utils.h"
#include "appspawn_utils.h"
#include "config_policy_utils.h"

static const std::string SILK_JSON_CONFIG_NAME("/silk.json");
static const std::string SILK_JSON_ENABLE_ITEM("enabled_app_list");
static const std::string SILK_JSON_LIBRARY_PATH("/vendor/lib64/chipsetsdk/libsilk.so.0.1");

typedef struct TagParseJsonContext {
    std::set<std::string> appList;
} ParseJsonContext;

static ParseJsonContext *g_silkContext = nullptr;

static int ParseSilkConfig(const cJSON *root, ParseJsonContext *context)
{
    int ret = -1;
    APPSPAWN_LOGE("cyx: ParseSilkConfig start");
    cJSON *silkJson = cJSON_GetObjectItemCaseSensitive(root, SILK_JSON_ENABLE_ITEM.c_str());
    if (silkJson == nullptr) {
        return -2;
    }
    APPSPAWN_LOGE("cyx: silk json not null");
    int moduleCount = cJSON_GetArraySize(silkJson);
    APPSPAWN_LOGE("cyx: silk json count %{public}d", moduleCount);
    for (int i = 0; i < moduleCount; ++i) {
        const char *appName = cJSON_GetStringValue(cJSON_GetArrayItem(silkJson, i));
        APPSPAWN_LOGE("cyx: silk json appname %{public}s", appName);
        if (appName == nullptr) {
            break;
        }
        APPSPAWN_LOGE("Enable silk appName %{public}s", appName);
        if (!context->appList.count(appName)) {
            context->appList.insert(appName);
        }
        ret = 0;
    }
    APPSPAWN_LOGE("cyx: ParseSilkConfig end");
    return ret;
}

void LoadSilkConfig(void)
{
    APPSPAWN_LOGE("cyx: load LoadSilkConfig start");
    std::string silkJsonPath("/vendor/etc/silk/silk.json");
    std::ifstream file(silkJsonPath);
    if (!file.good()) {
        APPSPAWN_LOGE("cyx silk.json is null!\n"); 
        return;
    }
    APPSPAWN_LOGE("cyx silk.json is not null cc\n");
    cJSON *root = GetJsonObjFromFile("/vendor/etc/silk/silk.json");
    if (root == nullptr) {
        APPSPAWN_LOGE("cyx: root is null");
    } else {
        APPSPAWN_LOGE("cyx: root is not null");
    }
    APPSPAWN_CHECK(root != nullptr, return,
                   "Failed to load silk config");
    g_silkContext = new ParseJsonContext();
    if (g_silkContext == nullptr) {
        APPSPAWN_LOGE("new silk context failed");
        return;
    }
    int ret = ParseSilkConfig(root, g_silkContext);
    APPSPAWN_LOGE("cyx:ret:%{public}d", ret);
    if (ret != 0) {
        delete g_silkContext;
        g_silkContext = nullptr;
    }
    cJSON_Delete(root);
    APPSPAWN_LOGE("cyx: load LoadSilkConfig end");
}

void LoadSilkLibrary(const char *packageName)
{
    if (packageName == nullptr || g_silkContext == nullptr) {
        return;
    }
    for (std::string appName : g_silkContext->appList) {
        APPSPAWN_LOGE("cyx: LoadSilkLibrary appName %{public}s", appName.c_str());
        if (appName.compare(packageName) == 0) {
            void *handle = dlopen(SILK_JSON_LIBRARY_PATH.c_str(), RTLD_NOW);
            APPSPAWN_LOGI("Enable Silk AppName %{public}s result:%{public}s",
                appName.c_str(), handle ? "success" : "failed");
        }
    }
    if (g_silkContext != nullptr) {
        g_silkContext->appList.clear();
        delete g_silkContext;
        g_silkContext = nullptr;
    }
}