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

#include <cerrno>
#include <cstring>
#include <dlfcn.h>
#include <set>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "appspawn_hook.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "appspawn_utils.h"
#include "config_policy_utils.h"
#include "hitrace_meter.h"
#include "js_runtime.h"
#include "parameters.h"
#include "command_lexer.h"
#include "resource_manager.h"
#include "sandbox_utils.h"
#ifndef APPSPAWN_TEST
#include "runtime.h"
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/app/main_thread.h"
#include "ace_forward_compatibility.h"
#endif

using namespace OHOS::AppSpawn;
using namespace OHOS::Global;

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
    bool rc = SandboxUtils::GetJsonObjFromJson(preloadJson, configName);
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

static void LoadExtendLib(void)
{
    const char *acelibdir = OHOS::Ace::AceForwardCompatibility::GetAceLibName();
    APPSPAWN_LOGI("LoadExtendLib: Start calling dlopen acelibdir.");
    void *aceAbilityLib = dlopen(acelibdir, RTLD_NOW | RTLD_LOCAL);
    APPSPAWN_CHECK(aceAbilityLib != nullptr, return, "Fail to dlopen %{public}s, [%{public}s]", acelibdir, dlerror());
    APPSPAWN_LOGI("LoadExtendLib: Success to dlopen %{public}s", acelibdir);

    OHOS::AppExecFwk::MainThread::PreloadExtensionPlugin();
    bool preload = OHOS::system::GetBoolParameter("persist.appspawn.preload", DEFAULT_PRELOAD_VALUE);
    if (!preload) {
        APPSPAWN_LOGI("LoadExtendLib: Do not preload JS VM");
        return;
    }

    APPSPAWN_LOGI("LoadExtendLib: Start preload JS VM");
    SetTraceDisabled(true);
    PreloadModule();
    SetTraceDisabled(false);

    Resource::ResourceManager *systemResMgr = Resource::GetSystemResourceManagerNoSandBox();
    APPSPAWN_CHECK(systemResMgr != nullptr, return, "Fail to get system resource manager");
    APPSPAWN_LOGI("LoadExtendLib: End preload JS VM");
}

static void RunChildThread(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    std::string checkExit;
    if (OHOS::system::GetBoolParameter("persist.init.debug.checkexit", true)) {
        checkExit = std::to_string(getpid());
    }
    setenv(APPSPAWN_CHECK_EXIT, checkExit.c_str(), true);
    OHOS::AppExecFwk::MainThread::Start();
    unsetenv(APPSPAWN_CHECK_EXIT);
}

static void RunChildByRenderCmd(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    uint32_t len = 0;
    char *renderCmd = reinterpret_cast<char *>(GetAppPropertyEx(property, MSG_EXT_NAME_RENDER_CMD, &len));
    if (renderCmd == NULL || !IsDeveloperModeOn(property)) {
        APPSPAWN_LOGE("Denied launching a native process: not in developer mode");
        return;
    }
    APPSPAWN_LOGI("renderCmd %{public}s", renderCmd);
    std::vector<std::string> args;
    std::string command(renderCmd);
    CommandLexer lexer(command);
    if (!lexer.GetAllArguments(args)) {
        return;
    }
    if (args.empty()) {
        APPSPAWN_LOGE("Failed to run a native process: empty command %{public}s", renderCmd);
        return;
    }
    std::vector<char *> options;
    for (const auto &arg : args) {
        options.push_back(const_cast<char *>(arg.c_str()));
    }
    options.push_back(nullptr);
    execvp(args[0].c_str(), options.data());
    // If it succeeds calling execvp, it never returns.
    int err = errno;
    APPSPAWN_LOGE("Failed to launch a native process with execvp: %{public}s", strerror(err));
    return;
}

static void RunChildProcessor(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_CHECK(client != NULL && content != NULL, return, "Invalid client");
    AppSpawningCtx *property = reinterpret_cast<AppSpawningCtx *>(client);
    if (GetAppPropertyCode(property) == MSG_SPAWN_NATIVE_PROCESS) {
        RunChildByRenderCmd(reinterpret_cast<AppSpawnMgr *>(content), property);
    } else {
        RunChildThread(reinterpret_cast<AppSpawnMgr *>(content), property);
    }
}

static int AppSpawnPreload(AppSpawnMgr *content)
{
    if (IsNWebSpawnMode(content)) {
        return 0;
    }
    // register
    RegChildLooper(&content->content, RunChildProcessor);
    LoadExtendLib();
    return 0;
}

MODULE_CONSTRUCTOR(void)
{
    APPSPAWN_LOGV("Load ace module ...");
    AddPreloadHook(HOOK_PRIO_STEP1, AppSpawnPreload);
}
