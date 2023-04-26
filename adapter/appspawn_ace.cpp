/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <set>
#include "appspawn_service.h"
#include "config_policy_utils.h"
#include "hitrace_meter.h"
#include "js_runtime.h"
#include "parameters.h"
#include "runtime.h"
#include "json_utils.h"
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/app/main_thread.h"

using namespace OHOS::AppSpawn;

#ifdef ASAN_DETECTOR
static const bool DEFAULT_PRELOAD_VALUE = false;
#else
static const bool DEFAULT_PRELOAD_VALUE = true;
#endif
static const std::string PRELOAD_JSON_CONFIG("/appspawn_preload.json");

static void GetPreloadModules(const std::string &configName, std::set<std::string> &modules)
{
    // Preload napi module
    nlohmann::json preloadJson;
    bool rc = JsonUtils::GetJsonObjFromJson(preloadJson, configName);
    APPSPAWN_CHECK_ONLY_EXPER(rc, return);
    // no config
    if (preloadJson.find("napi") == preloadJson.end()) {
        return;
    }

    nlohmann::json modulesJson = preloadJson["napi"];
    uint32_t moduleCount = modulesJson.size();
    for (uint32_t i = 0; i < moduleCount; ++i) {
        nlohmann::json moduleName = modulesJson[i];
        APPSPAWN_LOGV("moduleName %{public}s", moduleName.get<std::string>().c_str());
        if (!modules.count(moduleName.get<std::string>())) {
            modules.insert(moduleName.get<std::string>());
        }
    }
}

static void PreloadModule(void)
{
    OHOS::AbilityRuntime::Runtime::Options options;
    options.lang = OHOS::AbilityRuntime::Runtime::Language::JS;
    options.loadAce = true;
    options.preload = true;

    auto runtime = OHOS::AbilityRuntime::Runtime::Create(options);
    if (!runtime) {
        APPSPAWN_LOGE("LoadExtendLib: Failed to create runtime");
        return;
    }
    std::set<std::string> modules = {};
    CfgFiles *files = GetCfgFiles("etc/appspawn");
    if (files == nullptr) {
        APPSPAWN_LOGE("LoadExtendLib: Get cfg file fail");
        return;
    }
    for (int i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        if (files->paths[i] == nullptr) {
            continue;
        }
        std::string path = files->paths[i];
        path += PRELOAD_JSON_CONFIG;
        APPSPAWN_LOGI("PreloadModules path %{public}s", path.c_str());
        GetPreloadModules(path, modules);
    }
    FreeCfgFiles(files);
    for (std::string moduleName : modules) {
        APPSPAWN_LOGI("moduleName %{public}s", moduleName.c_str());
        runtime->PreloadSystemModule(moduleName);
    }
    // Save preloaded runtime
    OHOS::AbilityRuntime::Runtime::SavePreloaded(std::move(runtime));
}

void LoadExtendLib(AppSpawnContent *content)
{
    const char *acelibdir("libace.z.so");
    APPSPAWN_LOGI("LoadExtendLib: Start calling dlopen acelibdir.");
    void *aceAbilityLib = dlopen(acelibdir, RTLD_NOW | RTLD_GLOBAL);
    APPSPAWN_CHECK(aceAbilityLib != nullptr, return, "Fail to dlopen %{public}s, [%{public}s]", acelibdir, dlerror());
    APPSPAWN_LOGI("LoadExtendLib: Success to dlopen %{public}s", acelibdir);

    bool preload = OHOS::system::GetBoolParameter("const.appspawn.preload", DEFAULT_PRELOAD_VALUE);
    if (!preload) {
        APPSPAWN_LOGI("LoadExtendLib: Do not preload JS VM");
        return;
    }

    APPSPAWN_LOGI("LoadExtendLib: Start preload JS VM");
    SetTraceDisabled(true);
#ifndef APPSPAWN_TEST
    PreloadModule();
#endif
    SetTraceDisabled(false);
    APPSPAWN_LOGI("LoadExtendLib: End preload JS VM");
}

void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGI("AppExecFwk::MainThread::Start");
#ifndef APPSPAWN_TEST
    OHOS::AppExecFwk::MainThread::Start();
#endif
}
