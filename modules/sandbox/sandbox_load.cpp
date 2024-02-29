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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <cstdbool>
#include <string>
#include <set>
#include <vector>

#include "appspawn_msg.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "nlohmann/json.hpp"
#include "parameters.h"
#include "parameter.h"
#include "securec.h"
#include "sandbox_utils.h"

using namespace std;

namespace {
    const std::string MODULE_TEST_BUNDLE_NAME("moduleTestProcessName");
    const std::string g_sandBoxAppInstallPath = "/data/accounts/account_0/applications/";
    const std::string g_bundleResourceSrcPath = "/data/service/el1/public/bms/bundle_resources/";
    const std::string g_bundleResourceDestPath = "/data/storage/bundle_resources/";
    const std::string g_dataBundles = "/data/bundles/";
    const std::string g_sandBoxDir = "/mnt/sandbox/";

    const char *g_actionStatus = "check-action-status";
    const char *g_appBase = "app-base";
    const char *g_appResources = "app-resources";
    const char *g_commonPrefix = "common";
    const char *g_destMode = "dest-mode";
    const char *g_fsType = "fs-type";
    const char *g_linkName = "link-name";
    const char *g_mountPrefix = "mount-paths";
    const char *g_gidPrefix = "gids";
    const char *g_privatePrefix = "individual";
    const char *g_permissionPrefix = "permission";
    const char *g_srcPath = "src-path";
    const char *g_sandBoxPath = "sandbox-path";
    const char *g_sandBoxFlags = "sandbox-flags";
    const char *g_sandBoxFlagsCustomized = "sandbox-flags-customized";
    const char *g_sandBoxOptions = "options";
    const char *g_dacOverrideSensitive = "dac-override-sensitive";
    const char *g_sandBoxShared = "sandbox-shared";
    const char *g_sandBoxSwitchPrefix = "sandbox-switch";
    const char *g_symlinkPrefix = "symbol-links";
    const char *g_sandboxRootPrefix = "sandbox-root";
    const char *g_topSandBoxSwitchPrefix = "top-sandbox-switch";
    const char *g_targetName = "target-name";
    const char *g_flagePoint = "flags-point";
    const char *g_mountSharedFlag = "mount-shared-flag";
    const char *g_flags = "flags";
    const char *g_appAplName = "app-apl-name";
    const char *g_sandBoxNsFlags = "sandbox-ns-flags";
    const std::string FILE_CROSS_APP_MODE = "ohos.permission.FILE_CROSS_APP";
    static const std::map<std::string, mode_t> g_mountFlagsMap = { {"rec", MS_REC}, {"MS_REC", MS_REC},
        {"bind", MS_BIND}, {"MS_BIND", MS_BIND}, {"move", MS_MOVE}, {"MS_MOVE", MS_MOVE},
        {"slave", MS_SLAVE}, {"MS_SLAVE", MS_SLAVE}, {"rdonly", MS_RDONLY}, {"MS_RDONLY", MS_RDONLY},
        {"shared", MS_SHARED}, {"MS_SHARED", MS_SHARED}, {"unbindable", MS_UNBINDABLE},
        {"MS_UNBINDABLE", MS_UNBINDABLE}, {"remount", MS_REMOUNT}, {"MS_REMOUNT", MS_REMOUNT},
        {"nosuid", MS_NOSUID}, {"MS_NOSUID", MS_NOSUID}, {"nodev", MS_NODEV}, {"MS_NODEV", MS_NODEV},
        {"noexec", MS_NOEXEC}, {"MS_NOEXEC", MS_NOEXEC}, {"noatime", MS_NOATIME}, {"MS_NOATIME", MS_NOATIME},
        {"lazytime", MS_LAZYTIME}, {"MS_LAZYTIME", MS_LAZYTIME}
    };

    static const std::map<std::string, mode_t> g_modeMap = {
        {"S_IRUSR", S_IRUSR}, {"S_IWUSR", S_IWUSR}, {"S_IXUSR", S_IXUSR},
        {"S_IRGRP", S_IRGRP}, {"S_IWGRP", S_IWGRP}, {"S_IXGRP", S_IXGRP},
        {"S_IROTH", S_IROTH}, {"S_IWOTH", S_IWOTH}, {"S_IXOTH", S_IXOTH},
        {"S_IRWXU", S_IRWXU}, {"S_IRWXG", S_IRWXG}, {"S_IRWXO", S_IRWXO}
    };
}

namespace OHOS {
namespace AppSpawn {
class SandboxLoad {
private:
    static bool AppSandboxPidNsIsSupport(void)
    {
        return OHOS::system::GetBoolParameter("const.sandbox.pidns.support", true);
    }

    static bool CheckAppFullMountEnable(void)
    {
        return OHOS::system::GetBoolParameter("const.filemanager.full_mount.enable", false);
    }

    static std::string GetStringFromJson(const nlohmann::json &json, const std::string &key)
    {
        APPSPAWN_CHECK(json.is_object(), return "", "json is not object.");
        bool isRet = json.find(key) != json.end() && json.at(key).is_string();
        if (isRet) {
            return json.at(key).get<std::string>();
        }
        return "";
    }

    static bool GetBoolValueFromJson(const nlohmann::json &config, const std::string &key, bool def = false)
    {
        if (config.find(key) != config.end()) {
            std::string v = config[key].get<std::string>();
            if (v == "true" || v == "ON" || v == "True") {
                return true;
            }
        }
        return def;
    }

    static unsigned long GetMountFlagsFromConfig(const std::vector<std::string> &vec)
    {
        unsigned long mountFlags = 0;
        for (unsigned int i = 0; i < vec.size(); i++) {
            if (g_mountFlagsMap.count(vec[i])) {
                mountFlags |= g_mountFlagsMap.at(vec[i]);
            }
        }
        return mountFlags;
    }

    static uint32_t GetSandboxNsFlags(const nlohmann::json &appConfig)
    {
        uint32_t nsFlags = 0;
        const std::map<std::string, uint32_t> namespaceFlagsMap = {
            {"pid", CLONE_NEWPID}, {"net", CLONE_NEWNET}
        };

        if (appConfig.find(g_sandBoxNsFlags) == appConfig.end()) {
            return 0;
        }
        const auto vec = appConfig[g_sandBoxNsFlags].get<std::vector<std::string>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            if (namespaceFlagsMap.count(vec[j])) {
                nsFlags |= namespaceFlagsMap.at(vec[j]);
            }
        }
        return nsFlags;
    }

    static std::string GetSandboxRoot(AppSpawnSandbox &sandbox, const nlohmann::json &sandboxConfig)
    {
        std::string sandboxRoot = "";
        if (sandboxConfig.find(g_sandboxRootPrefix) != sandboxConfig.end()) {
            sandboxRoot = sandboxConfig[g_sandboxRootPrefix].get<std::string>();
        }
        if (strcmp(sandboxRoot.c_str(), sandbox.defaultRootPath) == 0) {
            return "";
        }
        return sandboxRoot;
    }

    static mode_t GetChmodFromJson(const nlohmann::json &config)
    {
        mode_t mode = 0;
        std::string fileModeStr = GetStringFromJson(config, g_destMode);
        if (fileModeStr == "") {
            return mode;
        }

        std::vector<std::string> modeVec = SandboxUtils::split(fileModeStr, "|");
        for (unsigned int i = 0; i < modeVec.size(); i++) {
            if (g_modeMap.count(modeVec[i])) {
                mode |= g_modeMap.at(modeVec[i]);
            }
        }
        return mode;
    }

    static uint32_t GetFlagsFromJson(const nlohmann::json &config)
    {
        const std::map<std::string, int> flagsMap = {
            {"0", 0}, {"START_FLAGS_BACKUP", 1}, {"DLP_MANAGER", 2}
        };

        if (config.find(g_flags) != config.end()) {
            std::string flagStr = config.at(g_flags).get<std::string>();
            if (flagsMap.count(flagStr)) {
                return 1 << flagsMap.at(flagStr);
            }
        }
        return 0;
    }

    static int GetGidsFromJson(const nlohmann::json &config, uint32_t &count, gid_t gidTable[])
    {
        count = 0;
        if (config.find(g_gidPrefix) == config.end()) {
            return 0;
        }
        nlohmann::json gids = config[g_gidPrefix];
        uint32_t size = gids.size();
        for (uint32_t i = 0; i < size; i++) {
            if (count < APP_MAX_GIDS) {
                gidTable[count++] = gids[i].get<uint32_t>();
            }
        }
        return 0;
    }

    static PathMountNode *DecodeMountPathConfig(const nlohmann::json &config)
    {
        std::string srcPath = GetStringFromJson(config, g_srcPath);
        std::string dstPath = GetStringFromJson(config, g_sandBoxPath);
        if (srcPath.empty() || dstPath.empty()) {
            return nullptr;
        }

        PathMountNode *sandboxNode = CreatePathMountNode();
        APPSPAWN_CHECK_ONLY_EXPER(sandboxNode != nullptr, return NULL);
        sandboxNode->source = strdup(srcPath.c_str());
        sandboxNode->target = strdup(dstPath.c_str());

        if (config.find(g_sandBoxFlags) != config.end()) {
            sandboxNode->mountFlags = GetMountFlagsFromConfig(config[g_sandBoxFlags].get<std::vector<std::string>>());
        }
        if (config.find(g_sandBoxFlagsCustomized) != config.end()) {
            sandboxNode->customizedFlags =
                GetMountFlagsFromConfig(config[g_sandBoxFlagsCustomized].get<std::vector<std::string>>());
        }
        sandboxNode->destMode = GetChmodFromJson(config);
        sandboxNode->mountSharedFlag = GetBoolValueFromJson(config, g_mountSharedFlag);
        sandboxNode->checkErrorFlag = GetBoolValueFromJson(config, g_actionStatus);
        sandboxNode->dacOverrideSensitive = GetBoolValueFromJson(config, g_dacOverrideSensitive);
        std::string value = GetStringFromJson(config, g_sandBoxOptions);
        if (!value.empty()) {
            sandboxNode->options = strdup(value.c_str());
        }
        value = GetStringFromJson(config, g_fsType);
        if (!value.empty()) {
            sandboxNode->fsType = strdup(value.c_str());
        }
        value = GetStringFromJson(config, g_appAplName);
        if (!value.empty()) {
            sandboxNode->appAplName = strdup(value.c_str());
        }
        return sandboxNode;
    }

    static int DecodeMountPathsConfig(AppSpawnSandbox &sandbox,
        const nlohmann::json &mountConfigs, uint32_t flagsPoint, SandboxSection &section)
    {
        uint32_t mountPointSize = mountConfigs.size();
        for (uint32_t i = 0; i < mountPointSize; i++) {
            nlohmann::json mntPoint = mountConfigs[i];
            PathMountNode *sandboxNode = DecodeMountPathConfig(mntPoint);
            APPSPAWN_CHECK_ONLY_EXPER(sandboxNode != nullptr, continue);
            sandboxNode->flagsPoint = flagsPoint;
            sandboxNode->isFlagsPoint = (flagsPoint & APP_FLAGS_SECTION) == APP_FLAGS_SECTION;
            AddPathNode(&sandboxNode->sandboxNode, &section);
        }
        return 0;
    }

    static int DecodeSymbolLinksConfig(AppSpawnSandbox &sandbox,
        const nlohmann::json &symbolLinkConfigs, uint32_t flagsPoint, SandboxSection &section)
    {
        uint32_t symlinkPointSize = symbolLinkConfigs.size();
        for (uint32_t i = 0; i < symlinkPointSize; i++) {
            nlohmann::json symPoint = symbolLinkConfigs[i];
            std::string target = GetStringFromJson(symPoint, g_targetName);
            std::string linkName = GetStringFromJson(symPoint, g_linkName);
            if (target.empty() || linkName.empty()) {
                continue;
            }

            SymbolLinkNode *node = CreateSymbolLinkNode();
            APPSPAWN_CHECK_ONLY_EXPER(node != nullptr, return -1);
            node->destMode = GetChmodFromJson(symPoint);
            node->checkErrorFlag = GetBoolValueFromJson(symPoint, g_actionStatus);
            node->target = strdup(target.c_str());
            node->linkName = strdup(linkName.c_str());
            AddPathNode(&node->sandboxNode, &section);
        }
        return 0;
    }

    static void SandboxSectionSetRootPath(AppSpawnSandbox &sandbox,
        SandboxSection &section, const nlohmann::json &configs, uint32_t flags)
    {
        // only compare with defaultRootPath
        std::string sandboxRoot = "";
        if (configs.find(g_sandboxRootPrefix) != configs.end()) {
            sandboxRoot = configs[g_sandboxRootPrefix].get<std::string>();
        }
        if (strcmp(sandboxRoot.c_str(), sandbox.defaultRootPath) == 0) {
            sandboxRoot = "";
        }
        char **rootPath = NULL;
        if (TEST_FLAGS_BY_INDEX(flags, APP_FLAGS_BACKUP_EXTENSION)) {
            rootPath = &section.rootFlagsPath[0];
        } else if (TEST_FLAGS_BY_INDEX(flags, APP_FLAGS_DLP_MANAGER)) {
            rootPath = &section.rootFlagsPath[1];
        } else {
            rootPath = &section.rootPath;
        }
        if (*rootPath != NULL) {
            APPSPAWN_LOGW("Root path has been set %{public}s new %{public}s ", *rootPath, sandboxRoot.c_str());
            free(*rootPath);
            *rootPath = NULL;
        }

        *rootPath = sandboxRoot.empty() ? NULL : strdup(sandboxRoot.c_str());
        return;
    }

    static int DecodeBaseConfig(AppSpawnSandbox &sandbox,
        const nlohmann::json &configs, SandboxSection &section, const std::string &configName)
    {
        int ret = 0;
        if (configs.find(g_mountPrefix) != configs.end()) { // mount-paths
            ret = DecodeMountPathsConfig(sandbox, configs[g_mountPrefix], 0, section);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);
        }
        if (configs.find(g_symlinkPrefix) != configs.end()) { // symbol-links
            ret = DecodeSymbolLinksConfig(sandbox, configs[g_symlinkPrefix], 0, section);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        }
        if (configs.find(g_flagePoint) == configs.end()) { // flags-point
            return 0;
        }
        nlohmann::json flagConfigs = configs[g_flagePoint];
        uint32_t flagsSize = flagConfigs.size();
        for (uint32_t i = 0; i < flagsSize; i++) {
            nlohmann::json config = flagConfigs[i];
            uint32_t flagsPoint = GetFlagsFromJson(config);
            flagsPoint |= APP_FLAGS_SECTION;
            SandboxSectionSetRootPath(sandbox, section, config, flagsPoint);

            if (config.find(g_mountPrefix) != config.end()) { // mount-paths
                ret = DecodeMountPathsConfig(sandbox, config[g_mountPrefix], flagsPoint, section);
                APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);
            }
            if (config.find(g_symlinkPrefix) != config.end()) { // symbol-links
                ret = DecodeSymbolLinksConfig(sandbox, config[g_symlinkPrefix], flagsPoint, section);
                APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
            }
        }
        return 0;
    }

    static int DecodeCommConfig(AppSpawnSandbox &sandbox, const nlohmann::json &commonConfig)
    {
        int ret = 0;
        // "top-sandbox-switch": "ON", default sandbox switch is on
        if (sandbox.topSandboxSwitch == 0) {
            sandbox.topSandboxSwitch = GetBoolValueFromJson(commonConfig, g_topSandBoxSwitchPrefix, true);
        }

        // app-base
        if (commonConfig.find(g_appBase) != commonConfig.end()) {
            nlohmann::json config = commonConfig[g_appBase][0];
            APPSPAWN_LOGV("Load app base config ");
            sandbox.sandboxNsFlags[0] = GetSandboxNsFlags(config);
            APPSPAWN_LOGV("Load app base sandboxNsFlags '%{public}x' ", sandbox.sandboxNsFlags[0]);
            SandboxSectionSetRootPath(sandbox, sandbox.section, config, 0);

            ret = DecodeBaseConfig(sandbox, config, sandbox.section, g_appBase);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        }
        // app-resources
        if (commonConfig.find(g_appResources) != commonConfig.end()) {
            nlohmann::json config = commonConfig[g_appResources][0];
            APPSPAWN_LOGV("Load app resource config");
            SandboxSectionSetRootPath(sandbox, sandbox.section, config, 0);

            ret = DecodeBaseConfig(sandbox, config, sandbox.section, g_appResources);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        }
        return ret;
    }

    static int DecodePrivateConfig(AppSpawnSandbox &sandbox, const nlohmann::json &privateConfigs)
    {
        int ret = 0;
        for (auto it = privateConfigs.begin(); it != privateConfigs.end(); it++) {
            nlohmann::json config = it.value()[0];
            SandboxPrivateNode *node = CreateSandboxPrivateNode(it.key().c_str());
            APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);

            if (strcmp(OHOS_RENDER, it.key().c_str()) == 0) { // nweb namespace flags
                sandbox.sandboxNsFlags[1] = GetSandboxNsFlags(config);
            }
            // "sandbox-switch": "ON", default sandbox switch is on
            node->section.sandboxSwitch = GetBoolValueFromJson(config, g_sandBoxSwitchPrefix, true);
            // "sandbox-shared"
            node->section.sandboxShared = GetBoolValueFromJson(config, g_sandBoxShared);
            SandboxSectionSetRootPath(sandbox, node->section, config, 0);

            ret = DecodeBaseConfig(sandbox, config, node->section, it.key());
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
            // success, insert section
            AddPathNode(&node->sandboxNode, &sandbox.privateNodeQueue);
        }
        return 0;
    }

    static int DecodePermissionConfig(AppSpawnSandbox &sandbox, const nlohmann::json &permissionConfigs)
    {
        uint32_t gidTable[APP_MAX_GIDS] = {};
        int ret = 0;
        for (auto it = permissionConfigs.begin(); it != permissionConfigs.end(); it++) {
            nlohmann::json config = it.value()[0];
            uint32_t gidCount = 0;
            ret = GetGidsFromJson(config, gidCount, gidTable);
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return -1);

            SandboxPermissionNode *node = CreateSandboxPermissionNode(it.key().c_str(), gidCount, gidTable);
            APPSPAWN_CHECK_ONLY_EXPER(node != NULL, return -1);

            // "sandbox-switch": "ON",
            node->section.sandboxSwitch = GetBoolValueFromJson(config, g_sandBoxSwitchPrefix);
            // "sandbox-shared"
            node->section.sandboxShared = GetBoolValueFromJson(config, g_sandBoxShared);
            SandboxSectionSetRootPath(sandbox, node->section, config, 0);

            ret = DecodeBaseConfig(sandbox, config, node->section, it.key());
            APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
            // success, insert section
            AddPathNode(&node->sandboxNode, &sandbox.permissionNodeQueue);
        }
        return 0;
    }

public:
    static int DecodeAppSandboxConfig(AppSpawnSandbox &sandbox, const nlohmann::json &appSandboxConfig)
    {
        int ret = 0;
        if (appSandboxConfig.find(g_commonPrefix) != appSandboxConfig.end() &&
            appSandboxConfig[g_commonPrefix].size() > 0) {
            ret = DecodeCommConfig(sandbox, appSandboxConfig[g_commonPrefix][0]);
            APPSPAWN_CHECK(ret == 0, return ret, "Load common config fail result: %{public}d ", ret);
        }

        if (appSandboxConfig.find(g_privatePrefix) != appSandboxConfig.end() &&
            appSandboxConfig[g_privatePrefix].size() > 0) {
            ret = DecodePrivateConfig(sandbox, appSandboxConfig[g_privatePrefix][0]);
            APPSPAWN_CHECK(ret == 0, return ret, "Load private config fail result: %{public}d ", ret);
        }

        if (appSandboxConfig.find(g_permissionPrefix) != appSandboxConfig.end() &&
            appSandboxConfig[g_permissionPrefix].size() > 0) {
            ret = DecodePermissionConfig(sandbox, appSandboxConfig[g_permissionPrefix][0]);
            APPSPAWN_CHECK(ret == 0, return ret, "Load permission config fail result: %{public}d ", ret);
        }
        return ret;
    }

    static int LoadAppSandboxConfig(AppSpawnSandbox &sandbox)
    {
        std::vector<nlohmann::json> jsonConfigs;
        int ret = SandboxUtils::GetSandboxConfigs(jsonConfigs);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
        if (jsonConfigs.empty()) {
            APPSPAWN_LOGW("No sandbox config");
        }
        for (auto config : jsonConfigs) {
            DecodeAppSandboxConfig(sandbox, config);
        }
        sandbox.pidNamespaceSupport = AppSandboxPidNsIsSupport();
        sandbox.appFullMountEnable = CheckAppFullMountEnable();
        APPSPAWN_LOGI("Sandbox pidNamespaceSupport: %{public}d appFullMountEnable: %{public}d",
            sandbox.pidNamespaceSupport, sandbox.appFullMountEnable);
        return 0;
    }

    static void DumpMountFlags(const char *info, unsigned long mountFlags)
    {
        std::string dump;
        bool first = true;
        for (const auto &item : g_mountFlagsMap) {
            if ((item.second & mountFlags) != 0) {
                if (!first) {
                    dump += "|";
                }
                first = false;
                dump += item.first;
            }
        }
        APPSPAPWN_DUMP("%{public}s[0x%{public}x] %{public}s", info, static_cast<uint32_t>(mountFlags), dump.c_str());
    }

    static void DumpMode(const char *info, mode_t mode)
    {
        std::string dump;
        bool first = true;
        for (const auto &item : g_modeMap) {
            if ((item.second & mode) == item.second) {
                if (!first) {
                    dump += "|";
                }
                first = false;
                dump += item.first;
            }
        }
        APPSPAPWN_DUMP("%{public}s[0x%{public}x] %{public}s", info, static_cast<uint32_t>(mode), dump.c_str());
    }
}; // for class
}
}

#ifdef __cplusplus
extern "C" {
#endif
int LoadAppSandboxConfig(AppSpawnSandbox *sandbox)
{
    return OHOS::AppSpawn::SandboxLoad::LoadAppSandboxConfig(*sandbox);
}
void DumpMountFlags(const char *info, unsigned long mountFlags)
{
    return OHOS::AppSpawn::SandboxLoad::DumpMountFlags(info, mountFlags);
}
void DumpMode(const char *info, mode_t mode)
{
    return OHOS::AppSpawn::SandboxLoad::DumpMode(info, mode);
}
#ifdef __cplusplus
}
#endif
