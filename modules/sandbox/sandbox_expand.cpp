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
#include <sstream>
#include <fstream>
#include <string>
#include <set>
#include <vector>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_msg.h"
#include "appspawn_sandbox.h"
#include "appspawn_utils.h"
#include "nlohmann/json.hpp"
#include "securec.h"
#include "sandbox_utils.h"

using namespace std;

namespace{
const std::string g_hspList_key_bundles = "bundles";
const std::string g_hspList_key_modules = "modules";
const std::string g_hspList_key_versions = "versions";
const std::string g_overlayPath = "/data/storage/overlay/";
const std::string g_groupList_key_dataGroupId = "dataGroupId";
const std::string g_groupList_key_gid = "gid";
const std::string g_groupList_key_dir = "dir";
const std::string HSPLIST_SOCKET_TYPE = "|HspList|";
const std::string OVERLAY_SOCKET_TYPE = "|Overlay|";
const std::string DATA_GROUP_SOCKET_TYPE = "|DataGroup|";
const std::string g_sandboxGroupPath = "/data/storage/el2/group/";
const std::string g_sandboxHspInstallPath = "/data/storage/el1/bundle/";
const char* g_fileSeparator = "/";

static inline bool CheckPath(const std::string& name)
{
    return !name.empty() && name != "." && name != ".." && name.find("/") == std::string::npos;
}
}

namespace OHOS {
namespace AppSpawn {
class SandboxExpand {
public:
    static int32_t MountAllHsp(const SandboxContext &context, const char *hspListInfo)
    {
        int ret = 0;
        std::string sandboxPackagePath = context.sandboxPackagePath;
        nlohmann::json hsps = nlohmann::json::parse(hspListInfo, nullptr, false);
        APPSPAWN_CHECK(!hsps.is_discarded() && hsps.contains(g_hspList_key_bundles) && hsps.contains(g_hspList_key_modules)
            && hsps.contains(g_hspList_key_versions), return -1, "MountAllHsp: json parse failed");

        nlohmann::json& bundles = hsps[g_hspList_key_bundles];
        nlohmann::json& modules = hsps[g_hspList_key_modules];
        nlohmann::json& versions = hsps[g_hspList_key_versions];
        APPSPAWN_CHECK(bundles.is_array() && modules.is_array() && versions.is_array() && bundles.size() == modules.size()
            && bundles.size() == versions.size(), return -1, "MountAllHsp: value is not arrary or sizes are not same");

        APPSPAWN_LOGI("MountAllHsp: app = %{public}s, cnt = %{public}lu",
            context.bundleName, static_cast<unsigned long>(bundles.size()));
        for (uint32_t i = 0; i < bundles.size(); i++) {
            // elements in json arrary can be different type
            APPSPAWN_CHECK(bundles[i].is_string() && modules[i].is_string() && versions[i].is_string(),
                return -1, "MountAllHsp: element type error");

            std::string libBundleName = bundles[i];
            std::string libModuleName = modules[i];
            std::string libVersion = versions[i];
            APPSPAWN_CHECK(CheckPath(libBundleName) && CheckPath(libModuleName) && CheckPath(libVersion),
                return -1, "MountAllHsp: path error");

            std::string libPhysicalPath = PHYSICAL_APP_INSTALL_PATH + libBundleName + "/" + libVersion + "/" + libModuleName;
            std::string mntPath = sandboxPackagePath + g_sandboxHspInstallPath + libBundleName + "/" + libModuleName;
            MakeDirRecursive(mntPath.c_str(), FILE_MODE);
            MountArg mountArg = {
                    libPhysicalPath.c_str(),
                    mntPath.c_str(),
                    NULL,
                    MS_REC | MS_BIND,
                    NULL,
                    MS_SLAVE
                };
            ret = SandboxMountPath(&mountArg);
            APPSPAWN_CHECK(ret == 0, return ret, "mount library failed %{public}d", ret);
        }
        return ret;
    }

    static int32_t MountAllGroup(const SandboxContext &context, const char *dataGroupInfo)
    {
        int ret = 0;
        std::string sandboxPackagePath = context.sandboxPackagePath;
        nlohmann::json groups = nlohmann::json::parse(dataGroupInfo, nullptr, false);
        APPSPAWN_CHECK(!groups.is_discarded() && groups.contains(g_groupList_key_dataGroupId)
            && groups.contains(g_groupList_key_gid) && groups.contains(g_groupList_key_dir), return -1,
                "MountAllGroup: json parse failed");

        nlohmann::json& dataGroupIds = groups[g_groupList_key_dataGroupId];
        nlohmann::json& gids = groups[g_groupList_key_gid];
        nlohmann::json& dirs = groups[g_groupList_key_dir];
        APPSPAWN_CHECK(dataGroupIds.is_array() && gids.is_array() && dirs.is_array() && dataGroupIds.size() == gids.size()
            && dataGroupIds.size() == dirs.size(), return -1, "MountAllGroup: value is not arrary or sizes are not same");
        APPSPAWN_LOGI("MountAllGroup: app = %{public}s, cnt = %{public}lu",
            GetBundleName(context.property), static_cast<unsigned long>(dataGroupIds.size()));
        for (uint32_t i = 0; i < dataGroupIds.size(); i++) {
            // elements in json arrary can be different type
            APPSPAWN_CHECK(dataGroupIds[i].is_string() && gids[i].is_string() && dirs[i].is_string(),
                return -1, "MountAllGroup: element type error");

            std::string libPhysicalPath = dirs[i];
            APPSPAWN_CHECK(!CheckPath(libPhysicalPath), return -1, "MountAllGroup: path error");

            size_t lastPathSplitPos = libPhysicalPath.find_last_of(g_fileSeparator);
            APPSPAWN_CHECK(lastPathSplitPos != std::string::npos, return -1, "MountAllGroup: path error");

            std::string dataGroupUuid = libPhysicalPath.substr(lastPathSplitPos + 1);
            std::string mntPath = sandboxPackagePath + g_sandboxGroupPath + dataGroupUuid;
            MakeDirRecursive(mntPath.c_str(), FILE_MODE);
            MountArg mountArg = {
                    libPhysicalPath.c_str(),
                    mntPath.c_str(),
                    NULL,
                    MS_REC | MS_BIND,
                    NULL,
                    MS_SLAVE
                };
            ret = SandboxMountPath(&mountArg);
            APPSPAWN_CHECK(ret == 0, return ret, "mount library failed %{public}d", ret);
        }
        return ret;
    }

    static int32_t SetOverlayAppSandboxConfig(const SandboxContext &context, const char *overlayInfo)
    {
        int ret = 0;
        std::string sandboxPackagePath = context.sandboxPackagePath;
        set<string> mountedSrcSet;
        std::string overlayString(overlayInfo);
        vector<string> splits = SandboxUtils::split(overlayString, "|");
        std::string sandboxOverlayPath = sandboxPackagePath + g_overlayPath;
        for (auto hapPath : splits) {
            size_t pathIndex = hapPath.find_last_of(g_fileSeparator);
            if (pathIndex == std::string::npos) {
                continue;
            }
            std::string srcPath = hapPath.substr(0, pathIndex);
            if (mountedSrcSet.find(srcPath) != mountedSrcSet.end()) {
                APPSPAWN_LOGV("%{public}s have mounted before, no need to mount twice.", srcPath.c_str());
                continue;
            }

            auto bundleNameIndex = srcPath.find_last_of(g_fileSeparator);
            std::string destPath = sandboxOverlayPath + srcPath.substr(bundleNameIndex + 1, srcPath.length());
            MountArg mountArg = {
                    srcPath.c_str(), destPath.c_str(),
                    nullptr,
                    MS_REC | MS_BIND,
                    nullptr,
                    MS_SHARED
                };
            int retMount = SandboxMountPath(&mountArg);
            if (retMount != 0) {
                APPSPAWN_LOGE("fail to mount overlay path, src is %{public}s.", hapPath.c_str());
                ret = retMount;
            }

            mountedSrcSet.emplace(srcPath);
        }
        return ret;
    }
}; // for class
}
}

static int ProcessHSPListConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)GetAppPropertyEx(context->property, name, &size);
    if (size == 0 || extInfo == NULL) {
        return 0;
    }
    return OHOS::AppSpawn::SandboxExpand::MountAllHsp(*context, extInfo);
}

static int ProcessDataGroupConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)GetAppPropertyEx(context->property, name, &size);
    if (size == 0 || extInfo == NULL) {
        return 0;
    }
    return OHOS::AppSpawn::SandboxExpand::MountAllGroup(*context, extInfo);
}

static int ProcessOverlayAppConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name)
{
    uint32_t size = 0;
    char *extInfo = (char *)GetAppPropertyEx(context->property, name, &size);
    if (size == 0 || extInfo == NULL) {
        return 0;
    }
    return OHOS::AppSpawn::SandboxExpand::SetOverlayAppSandboxConfig(*context, extInfo);
}

struct ListNode g_sandboxExpandCfgList = { &g_sandboxExpandCfgList, &g_sandboxExpandCfgList };
static int AppSandboxExpandAppCfgCompareName(ListNode *node, void *data)
{
    AppSandboxExpandAppCfgNode *varNode = ListEntry(node, AppSandboxExpandAppCfgNode, node);
    return strncmp((char *)data, varNode->name, strlen(varNode->name));
}

static int AppSandboxExpandAppCfgComparePrio(ListNode *node1, ListNode *node2)
{
    AppSandboxExpandAppCfgNode *varNode1 = ListEntry(node1, AppSandboxExpandAppCfgNode, node);
    AppSandboxExpandAppCfgNode *varNode2 = ListEntry(node2, AppSandboxExpandAppCfgNode, node);
    return varNode1->prio - varNode2->prio;
}

static const AppSandboxExpandAppCfgNode *GetAppSandboxExpandAppCfg(const char *name)
{
    ListNode *node = OH_ListFind(&g_sandboxExpandCfgList,
        const_cast<void *>(reinterpret_cast<const void *>(name)), AppSandboxExpandAppCfgCompareName);
    if (node == NULL) {
        return NULL;
    }
    return ListEntry(node, AppSandboxExpandAppCfgNode, node);
}

int RegisterExpandSandboxCfgHandler(const char *name, int prio, ProcessExpandSandboxCfg handleExpandCfg)
{
    APPSPAWN_CHECK_ONLY_EXPER(name != nullptr && handleExpandCfg != nullptr, return APPSPAWN_INVALID_ARG);
    if (GetAppSandboxExpandAppCfg(name) != nullptr) {
        return APPSPAWN_NODE_EXIST;
    }

    size_t len = APPSPAWN_ALIGN(strlen(name) + 1);
    AppSandboxExpandAppCfgNode *node = (AppSandboxExpandAppCfgNode *)malloc(sizeof(AppSandboxExpandAppCfgNode) + len);
    APPSPAWN_CHECK(node != NULL, return APPSPAWN_SYSTEM_ERROR, "Failed to create sandbox");
    // ext data init
    OH_ListInit(&node->node);
    node->cfgHandle = handleExpandCfg;
    node->prio = prio;
    int ret = strcpy_s(node->name, len, name);
    APPSPAWN_CHECK(ret == 0, free(node); return -1, "Failed to copy name %{public}s", name);
    OH_ListAddWithOrder(&g_sandboxExpandCfgList, &node->node, AppSandboxExpandAppCfgComparePrio);
    return 0;
}

int ProcessExpandAppSandboxConfig(const SandboxContext *context, const AppSpawnSandbox *appSandBox, const char *name)
{
    APPSPAWN_CHECK_ONLY_EXPER(context != nullptr && appSandBox != nullptr, return APPSPAWN_INVALID_ARG);
    APPSPAWN_CHECK_ONLY_EXPER(name != nullptr, return APPSPAWN_INVALID_ARG);
    APPSPAWN_LOGE("ProcessExpandAppSandboxConfig %{public}s.", name);
    const AppSandboxExpandAppCfgNode *node = GetAppSandboxExpandAppCfg(name);
    if (node != nullptr && node->cfgHandle != nullptr) {
        return node->cfgHandle(context, appSandBox, name);
    }
    return 0;
}

void AddDefaultExpandAppSandboxConfigHandle(void)
{
    RegisterExpandSandboxCfgHandler("HspList", 0, ProcessHSPListConfig);
    RegisterExpandSandboxCfgHandler("DataGroup", 1, ProcessDataGroupConfig);
    RegisterExpandSandboxCfgHandler("Overlay", 2, ProcessOverlayAppConfig);
}

void ClearExpandAppSandboxConfigHandle(void)
{
    OH_ListRemoveAll(&g_sandboxExpandCfgList, NULL);
}

