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
    APPSPAWN_LOGE("cyx: load LoadSilkConfig end");
}

void LoadSilkLibrary(const char *packageName)
{
    if (packageName == nullptr || g_silkContext == nullptr) {
        APPSPAWN_LOGE("cyx LoadSilkLibrary null\n");
        return;
    }
}