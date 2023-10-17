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

#include <algorithm>
#include <fcntl.h>
#include <set>
#include <unistd.h>
#include <vector>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <cerrno>
#include <set>

#include "json_utils.h"
#include "securec.h"
#include "appspawn_server.h"
#include "appspawn_service.h"
#include "appspawn_mount_permission.h"

#ifdef WITH_SELINUX
#include "hap_restorecon.h"
#endif

using namespace std;
using namespace OHOS;

namespace OHOS {
namespace AppSpawn {
namespace {
    constexpr int32_t UID_BASE = 200000;
    constexpr int32_t FUSE_OPTIONS_MAX_LEN = 128;
    constexpr int32_t DLP_FUSE_FD = 1000;
    constexpr static mode_t FILE_MODE = 0711;
    constexpr static mode_t BASIC_MOUNT_FLAGS = MS_REC | MS_BIND;
    constexpr std::string_view APL_SYSTEM_CORE("system_core");
    constexpr std::string_view APL_SYSTEM_BASIC("system_basic");
    const std::string g_physicalAppInstallPath = "/data/app/el1/bundle/public/";
    const std::string g_sandboxGroupPath = "/data/storage/el2/group/";
    const std::string g_sandboxHspInstallPath = "/data/storage/el1/bundle/";
    const std::string g_sandBoxAppInstallPath = "/data/accounts/account_0/applications/";
    const std::string g_bundleResourceSrcPath = "/data/service/el1/public/bms/bundle_resources/";
    const std::string g_bundleResourceDestPath = "/data/storage/bundle_resources/";
    const std::string g_dataBundles = "/data/bundles/";
    const std::string g_userId = "<currentUserId>";
    const std::string g_packageName = "<PackageName>";
    const std::string g_packageNameIndex = "<PackageName_index>";
    const std::string g_sandBoxDir = "/mnt/sandbox/";
    const std::string g_statusCheck = "true";
    const std::string g_sbxSwitchCheck = "ON";
    const std::string g_dlpBundleName = "com.ohos.dlpmanager";
    const std::string g_internal = "__internal__";
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
    const char *g_actionStatuc = "check-action-status";
    const char *g_appBase = "app-base";
    const char *g_appResources = "app-resources";
    const char *g_appAplName = "app-apl-name";
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
    const char *g_sandBoxShared = "sandbox-shared";
    const char *g_sandBoxSwitchPrefix = "sandbox-switch";
    const char *g_symlinkPrefix = "symbol-links";
    const char *g_sandboxRootPrefix = "sandbox-root";
    const char *g_topSandBoxSwitchPrefix = "top-sandbox-switch";
    const char *g_targetName = "target-name";
    const char *g_flagePoint = "flags-point";
    const char *g_mountSharedFlag = "mount-shared-flag";
    const char *g_flags = "flags";
    const char *g_sandBoxNameSpace = "sandbox-namespace";
    const char *g_sandBoxCloneFlags = "clone-flags";
    const char* g_fileSeparator = "/";
    const char* g_overlayDecollator = "|";
    const std::string g_sandBoxRootDir = "/mnt/sandbox/";
    const std::string g_ohosRender = "__internal__.com.ohos.render";
    const std::string g_sandBoxRootDirNweb = "/mnt/sandbox/com.ohos.render/";
}

nlohmann::json SandboxUtils::appNamespaceConfig_;
std::vector<nlohmann::json> SandboxUtils::appSandboxConfig_ = {};

void SandboxUtils::StoreNamespaceJsonConfig(nlohmann::json &appNamespaceConfig)
{
    SandboxUtils::appNamespaceConfig_ = appNamespaceConfig;
}

nlohmann::json SandboxUtils::GetNamespaceJsonConfig(void)
{
    return SandboxUtils::appNamespaceConfig_;
}

void SandboxUtils::StoreJsonConfig(nlohmann::json &appSandboxConfig)
{
    SandboxUtils::appSandboxConfig_.push_back(appSandboxConfig);
}

std::vector<nlohmann::json> &SandboxUtils::GetJsonConfig()
{
    return SandboxUtils::appSandboxConfig_;
}

static uint32_t NamespaceFlagsFromConfig(const std::vector<std::string> &vec)
{
    const std::map<std::string, uint32_t> NamespaceFlagsMap = { {"mnt", CLONE_NEWNS}, {"pid", CLONE_NEWPID} };
    uint32_t cloneFlags = 0;

    for (unsigned int j = 0; j < vec.size(); j++) {
        if (NamespaceFlagsMap.count(vec[j])) {
            cloneFlags |= NamespaceFlagsMap.at(vec[j]);
        }
    }
    return cloneFlags;
}

uint32_t SandboxUtils::GetNamespaceFlagsFromConfig(const char *bundleName)
{
    nlohmann::json config = SandboxUtils::GetNamespaceJsonConfig();
    uint32_t cloneFlags = CLONE_NEWNS;

    if (config.find(g_sandBoxNameSpace) == config.end()) {
        APPSPAWN_LOGE("namespace config is not found");
        return 0;
    }

    nlohmann::json namespaceApp = config[g_sandBoxNameSpace][0];
    if (namespaceApp.find(bundleName) == namespaceApp.end()) {
        return cloneFlags;
    }

    nlohmann::json app = namespaceApp[bundleName][0];
    cloneFlags |= NamespaceFlagsFromConfig(app[g_sandBoxCloneFlags].get<std::vector<std::string>>());
    return cloneFlags;
}

static void MakeDirRecursive(const std::string &path, mode_t mode)
{
    size_t size = path.size();
    if (size == 0) {
        return;
    }

    size_t index = 0;
    do {
        size_t pathIndex = path.find_first_of('/', index);
        index = pathIndex == std::string::npos ? size : pathIndex + 1;
        std::string dir = path.substr(0, index);
#ifndef APPSPAWN_TEST
        APPSPAWN_CHECK(!(access(dir.c_str(), F_OK) < 0 && mkdir(dir.c_str(), mode) < 0),
            return, "errno is %{public}d, mkdir %{public}s failed", errno, dir.c_str());
#endif
    } while (index < size);
}

int32_t SandboxUtils::DoAppSandboxMountOnce(const char *originPath, const char *destinationPath,
                                            const char *fsType, unsigned long mountFlags,
                                            const char *options, mode_t mountSharedFlag)
{
    // To make sure destinationPath exist
    MakeDirRecursive(destinationPath, FILE_MODE);
#ifndef APPSPAWN_TEST
    int ret = 0;
    // to mount fs and bind mount files or directory
    ret = mount(originPath, destinationPath, fsType, mountFlags, options);
    if (ret != 0) {
        APPSPAWN_LOGI("errno is: %{public}d, bind mount %{public}s to %{public}s", errno, originPath,
                      destinationPath);
        return ret;
    }
    ret = mount(NULL, destinationPath, NULL, mountSharedFlag, NULL);
    APPSPAWN_CHECK(ret == 0, return ret,
        "errno is: %{public}d, private mount to %{public}s failed", errno, destinationPath);
#endif
    return 0;
}

static std::string& replace_all(std::string& str, const std::string& old_value, const std::string& new_value)
{
    while (true) {
        std::string::size_type pos(0);
        if ((pos = str.find(old_value)) != std::string::npos) {
            str.replace(pos, old_value.length(), new_value);
        } else {
            break;
        }
    }
    return str;
}

static std::vector<std::string> split(std::string &str, const std::string &pattern)
{
    std::string::size_type pos;
    std::vector<std::string> result;
    str += pattern;
    size_t size = str.size();

    for (unsigned int i = 0; i < size; i++) {
        pos = str.find(pattern, i);
        if (pos < size) {
            std::string s = str.substr(i, pos - i);
            result.push_back(s);
            i = pos + pattern.size() - 1;
        }
    }

    return result;
}

void SandboxUtils::DoSandboxChmod(nlohmann::json jsonConfig, std::string &sandboxRoot)
{
    const std::map<std::string, mode_t> modeMap = {{"S_IRUSR", S_IRUSR}, {"S_IWUSR", S_IWUSR}, {"S_IXUSR", S_IXUSR},
                                                   {"S_IRGRP", S_IRGRP}, {"S_IWGRP", S_IWGRP}, {"S_IXGRP", S_IXGRP},
                                                   {"S_IROTH", S_IROTH}, {"S_IWOTH", S_IWOTH}, {"S_IXOTH", S_IXOTH},
                                                   {"S_IRWXU", S_IRWXU}, {"S_IRWXG", S_IRWXG}, {"S_IRWXO", S_IRWXO}};
    std::string fileModeStr;
    mode_t mode = 0;

    bool rc = JsonUtils::GetStringFromJson(jsonConfig, g_destMode, fileModeStr);
    if (rc == false) {
        return;
    }

    std::vector<std::string> modeVec = split(fileModeStr, "|");
    for (unsigned int i = 0; i < modeVec.size(); i++) {
        if (modeMap.count(modeVec[i])) {
            mode |= modeMap.at(modeVec[i]);
        }
    }

    chmod(sandboxRoot.c_str(), mode);
}

unsigned long SandboxUtils::GetMountFlagsFromConfig(const std::vector<std::string> &vec)
{
    const std::map<std::string, mode_t> MountFlagsMap = { {"rec", MS_REC}, {"MS_REC", MS_REC},
                                                          {"bind", MS_BIND}, {"MS_BIND", MS_BIND},
                                                          {"move", MS_MOVE}, {"MS_MOVE", MS_MOVE},
                                                          {"slave", MS_SLAVE}, {"MS_SLAVE", MS_SLAVE},
                                                          {"rdonly", MS_RDONLY}, {"MS_RDONLY", MS_RDONLY},
                                                          {"shared", MS_SHARED}, {"MS_SHARED", MS_SHARED},
                                                          {"unbindable", MS_UNBINDABLE},
                                                          {"MS_UNBINDABLE", MS_UNBINDABLE},
                                                          {"remount", MS_REMOUNT}, {"MS_REMOUNT", MS_REMOUNT},
                                                          {"nosuid", MS_NOSUID}, {"MS_NOSUID", MS_NOSUID},
                                                          {"nodev", MS_NODEV}, {"MS_NODEV", MS_NODEV},
                                                          {"noexec", MS_NOEXEC}, {"MS_NOEXEC", MS_NOEXEC},
                                                          {"noatime", MS_NOATIME}, {"MS_NOATIME", MS_NOATIME},
                                                          {"lazytime", MS_LAZYTIME}, {"MS_LAZYTIME", MS_LAZYTIME}};
    unsigned long mountFlags = 0;

    for (unsigned int i = 0; i < vec.size(); i++) {
        if (MountFlagsMap.count(vec[i])) {
            mountFlags |= MountFlagsMap.at(vec[i]);
        }
    }

    return mountFlags;
}

string SandboxUtils::ConvertToRealPath(const ClientSocket::AppProperty *appProperty, std::string path)
{
    if (path.find(g_packageNameIndex) != std::string::npos) {
        std::string bundleNameIndex = appProperty->bundleName;
        bundleNameIndex = bundleNameIndex + "_" + std::to_string(appProperty->bundleIndex);
        path = replace_all(path, g_packageNameIndex, bundleNameIndex);
    }

    if (path.find(g_packageName) != std::string::npos) {
        path = replace_all(path, g_packageName, appProperty->bundleName);
    }

    if (path.find(g_userId) != std::string::npos) {
        path = replace_all(path, g_userId, std::to_string(appProperty->uid / UID_BASE));
    }

    return path;
}

std::string SandboxUtils::GetSbxPathByConfig(const ClientSocket::AppProperty *appProperty, nlohmann::json &config)
{
    std::string sandboxRoot = "";
    if (config.find(g_sandboxRootPrefix) != config.end()) {
        sandboxRoot = config[g_sandboxRootPrefix].get<std::string>();
        sandboxRoot = ConvertToRealPath(appProperty, sandboxRoot);
    } else {
        sandboxRoot = g_sandBoxDir + appProperty->bundleName;
        APPSPAWN_LOGE("read sandbox-root config failed, set sandbox-root to default root"
            "app name is %{public}s", appProperty->bundleName);
    }

    return sandboxRoot;
}

bool SandboxUtils::GetSbxSwitchStatusByConfig(nlohmann::json &config)
{
    if (config.find(g_sandBoxSwitchPrefix) != config.end()) {
        std::string switchStatus = config[g_sandBoxSwitchPrefix].get<std::string>();
        if (switchStatus == g_sbxSwitchCheck) {
            return true;
        } else {
            return false;
        }
    }

    // if not find sandbox-switch node, default switch status is true
    return true;
}

static bool CheckMountConfig(nlohmann::json &mntPoint, const ClientSocket::AppProperty *appProperty,
                             bool checkFlag)
{
    bool istrue = mntPoint.find(g_srcPath) == mntPoint.end() || mntPoint.find(g_sandBoxPath) == mntPoint.end()
            || mntPoint.find(g_sandBoxFlags) == mntPoint.end();
    APPSPAWN_CHECK(!istrue, return false, "read mount config failed, app name is %{public}s", appProperty->bundleName);

    if (mntPoint[g_appAplName] != nullptr) {
        std::string app_apl_name = mntPoint[g_appAplName].get<std::string>();
        const char *p_app_apl = nullptr;
        p_app_apl = app_apl_name.c_str();
        if (!strcmp(p_app_apl, appProperty->apl)) {
            return false;
        }
    }

    const std::string configSrcPath = mntPoint[g_srcPath].get<std::string>();
    // special handle wps and don't use /data/app/xxx/<Package> config
    if (checkFlag && (configSrcPath.find("/data/app") != std::string::npos &&
        (configSrcPath.find("/base") != std::string::npos ||
         configSrcPath.find("/database") != std::string::npos
        ) && configSrcPath.find(g_packageName) != std::string::npos)) {
        return false;
    }

    return true;
}

static int32_t DoDlpAppMountStrategy(const ClientSocket::AppProperty *appProperty,
                                     const std::string &srcPath, const std::string &sandboxPath,
                                     const std::string &fsType, unsigned long mountFlags)
{
    // umount fuse path, make sure that sandbox path is not a mount point
    umount2(sandboxPath.c_str(), MNT_DETACH);

    int fd = open("/dev/fuse", O_RDWR);
    APPSPAWN_CHECK(fd != -1, return -EINVAL, "open /dev/fuse failed, errno is %{public}d", errno);

    char options[FUSE_OPTIONS_MAX_LEN];
    (void)sprintf_s(options, sizeof(options), "fd=%d,rootmode=40000,user_id=%d,group_id=%d,allow_other", fd,
        appProperty->uid, appProperty->gid);

    // To make sure destinationPath exist
    MakeDirRecursive(sandboxPath, FILE_MODE);

    int ret = 0;
#ifndef APPSPAWN_TEST
    ret = mount(srcPath.c_str(), sandboxPath.c_str(), fsType.c_str(), mountFlags, options);
    APPSPAWN_CHECK(ret == 0, return ret, "DoDlpAppMountStrategy failed, bind mount %{public}s to %{public}s"
        "failed %{public}d", srcPath.c_str(), sandboxPath.c_str(), errno);

    ret = mount(NULL, sandboxPath.c_str(), NULL, MS_SHARED, NULL);
    APPSPAWN_CHECK(ret == 0, return ret,
        "errno is: %{public}d, private mount to %{public}s failed", errno, sandboxPath.c_str());
#endif
    /* close DLP_FUSE_FD and dup FD to it */
    close(DLP_FUSE_FD);
    ret = dup2(fd, DLP_FUSE_FD);
    APPSPAWN_CHECK_ONLY_LOG(ret != -1, "dup fuse fd %{public}d failed, errno is %{public}d", fd, errno);
    return ret;
}

static int32_t HandleSpecialAppMount(const ClientSocket::AppProperty *appProperty,
                                     const std::string &srcPath, const std::string &sandboxPath,
                                     const std::string &fsType, unsigned long mountFlags)
{
    std::string bundleName = appProperty->bundleName;

    /* dlp application mount strategy */
    /* dlp is an example, we should change to real bundle name later */
    if (bundleName.find(g_dlpBundleName) != std::string::npos) {
        if (fsType.empty()) {
            return -1;
        } else {
            return DoDlpAppMountStrategy(appProperty, srcPath, sandboxPath, fsType, mountFlags);
        }
    }

    return -1;
}

static uint32_t ConvertFlagStr(const std::string &flagStr)
{
    const std::map<std::string, int> flagsMap = {{"0", 0}, {"START_FLAGS_BACKUP", 1},
                                                 {"DLP_MANAGER", 2}};

    if (flagsMap.count(flagStr)) {
        return 1 << flagsMap.at(flagStr);
    }

    return 0;
}

int SandboxUtils::DoAllMntPointsMount(const ClientSocket::AppProperty *appProperty,
    nlohmann::json &appConfig, const std::string &section)
{
    std::string bundleName = appProperty->bundleName;
    if (appConfig.find(g_mountPrefix) == appConfig.end()) {
        APPSPAWN_LOGV("mount config is not found in %{public}s, app name is %{public}s",
            section.c_str(), bundleName.c_str());
        return 0;
    }

    bool checkFlag = false;
    if (appConfig.find(g_flags) != appConfig.end()) {
        if (((ConvertFlagStr(appConfig[g_flags].get<std::string>()) & appProperty->flags) != 0) &&
            bundleName.find("wps") != std::string::npos) {
            checkFlag = true;
        }
    }

    nlohmann::json mountPoints = appConfig[g_mountPrefix];
    std::string sandboxRoot = GetSbxPathByConfig(appProperty, appConfig);
    unsigned int mountPointSize = mountPoints.size();

    for (unsigned int i = 0; i < mountPointSize; i++) {
        nlohmann::json mntPoint = mountPoints[i];

        if (CheckMountConfig(mntPoint, appProperty, checkFlag) == false) {
            continue;
        }

        std::string srcPath = ConvertToRealPath(appProperty, mntPoint[g_srcPath].get<std::string>());
        std::string sandboxPath = sandboxRoot + ConvertToRealPath(appProperty,
                                                                  mntPoint[g_sandBoxPath].get<std::string>());
        unsigned long mountFlags = GetMountFlagsFromConfig(mntPoint[g_sandBoxFlags].get<std::vector<std::string>>());
        std::string fsType = (mntPoint.find(g_fsType) != mntPoint.end()) ? mntPoint[g_fsType].get<std::string>() : "";
        const char* fsTypePoint = fsType.empty() ? nullptr : fsType.c_str();
        mode_t mountSharedFlag = (mntPoint.find(g_mountSharedFlag) != mntPoint.end()) ? MS_SHARED : MS_SLAVE;

        /* if app mount failed for special strategy, we need deal with common mount config */
        int ret = HandleSpecialAppMount(appProperty, srcPath, sandboxPath, fsType, mountFlags);
        if (ret < 0) {
            ret = DoAppSandboxMountOnce(srcPath.c_str(), sandboxPath.c_str(), fsTypePoint,
                                        mountFlags, nullptr, mountSharedFlag);
        }
        if (ret) {
            std::string actionStatus = g_statusCheck;
            (void)JsonUtils::GetStringFromJson(mntPoint, g_actionStatuc, actionStatus);
            if (actionStatus == g_statusCheck) {
                APPSPAWN_LOGE("DoAppSandboxMountOnce section %{public}s failed, %{public}s",
                    section.c_str(), sandboxPath.c_str());
                return ret;
            }
        }

        DoSandboxChmod(mntPoint, sandboxRoot);
    }

    return 0;
}

int32_t SandboxUtils::DoAddGid(ClientSocket::AppProperty *appProperty,
    nlohmann::json &appConfig, const char* permissionName, const std::string &section)
{
    std::string bundleName = appProperty->bundleName;
    if (appConfig.find(g_gidPrefix) == appConfig.end()) {
        APPSPAWN_LOGV("gids config is not found in %{public}s, app name is %{public}s permission is %{public}s",
            section.c_str(), bundleName.c_str(), permissionName);
        return 0;
    }
    nlohmann::json gids = appConfig[g_gidPrefix];
    unsigned int gidSize = gids.size();
    for (unsigned int i = 0; i < gidSize; i++) {
        if (appProperty->gidCount < APP_MAX_GIDS) {
            APPSPAWN_LOGI("add gid to gitTable in %{public}s, permission is %{public}s, gid:%{public}u",
                bundleName.c_str(), permissionName, gids[i].get<uint32_t>());
            appProperty->gidTable[appProperty->gidCount++] = gids[i].get<uint32_t>();
        }
    }
    return 0;
}

int SandboxUtils::DoAllSymlinkPointslink(const ClientSocket::AppProperty *appProperty, nlohmann::json &appConfig)
{
    APPSPAWN_CHECK(appConfig.find(g_symlinkPrefix) != appConfig.end(), return 0, "symlink config is not found,"
        "maybe result sandbox launch failed app name is %{public}s", appProperty->bundleName);

    nlohmann::json symlinkPoints = appConfig[g_symlinkPrefix];
    std::string sandboxRoot = GetSbxPathByConfig(appProperty, appConfig);
    unsigned int symlinkPointSize = symlinkPoints.size();

    for (unsigned int i = 0; i < symlinkPointSize; i++) {
        nlohmann::json symPoint = symlinkPoints[i];

        // Check the validity of the symlink configuration
        if (symPoint.find(g_targetName) == symPoint.end() || symPoint.find(g_linkName) == symPoint.end()) {
            APPSPAWN_LOGE("read symlink config failed, app name is %{public}s", appProperty->bundleName);
            continue;
        }

        std::string targetName = ConvertToRealPath(appProperty, symPoint[g_targetName].get<std::string>());
        std::string linkName = sandboxRoot + ConvertToRealPath(appProperty, symPoint[g_linkName].get<std::string>());
        APPSPAWN_LOGV("symlink, from %{public}s to %{public}s", targetName.c_str(), linkName.c_str());

        int ret = symlink(targetName.c_str(), linkName.c_str());
        if (ret && errno != EEXIST) {
            APPSPAWN_LOGE("errno is %{public}d, symlink failed, %{public}s", errno, linkName.c_str());

            std::string actionStatus = g_statusCheck;
            (void)JsonUtils::GetStringFromJson(symPoint, g_actionStatuc, actionStatus);
            if (actionStatus == g_statusCheck) {
                return ret;
            }
        }

        DoSandboxChmod(symPoint, sandboxRoot);
    }

    return 0;
}

int32_t SandboxUtils::DoSandboxFilePrivateBind(const ClientSocket::AppProperty *appProperty,
                                               nlohmann::json &wholeConfig)
{
    nlohmann::json privateAppConfig = wholeConfig[g_privatePrefix][0];
    if (privateAppConfig.find(appProperty->bundleName) != privateAppConfig.end()) {
        APPSPAWN_LOGV("DoSandboxFilePrivateBind %{public}s", appProperty->bundleName);
        return DoAllMntPointsMount(appProperty, privateAppConfig[appProperty->bundleName][0], g_privatePrefix);
    }

    return 0;
}

int32_t SandboxUtils::DoSandboxFilePermissionBind(ClientSocket::AppProperty *appProperty,
    nlohmann::json &wholeConfig)
{
    if (wholeConfig.find(g_permissionPrefix) == wholeConfig.end()) {
        APPSPAWN_LOGV("DoSandboxFilePermissionBind not found permission information in config file");
        return 0;
    }
    nlohmann::json permissionAppConfig = wholeConfig[g_permissionPrefix][0];
    for (nlohmann::json::iterator it = permissionAppConfig.begin(); it != permissionAppConfig.end(); ++it) {
        const std::string permissionstr = it.key();
        APPSPAWN_LOGV("DoSandboxFilePermissionBind mountPermissionFlags %{public}u",
                      appProperty -> mountPermissionFlags);
        if (AppspawnMountPermission::IsMountPermission(appProperty -> mountPermissionFlags, permissionstr)) {
            DoAddGid(appProperty, permissionAppConfig[permissionstr][0], permissionstr.c_str(), g_permissionPrefix);
            DoAllMntPointsMount(appProperty, permissionAppConfig[permissionstr][0], g_permissionPrefix);
        } else {
            APPSPAWN_LOGV("DoSandboxFilePermissionBind false %{public}s permission %{public}s",
                appProperty->bundleName, permissionstr.c_str());
        }
    }
    return 0;
}

std::set<std::string> SandboxUtils::GetMountPermissionNames()
{
    std::set<std::string> permissionSet;
    for (auto config : SandboxUtils::GetJsonConfig()) {
        if (config.find(g_permissionPrefix) == config.end()) {
            continue;
        }
        nlohmann::json permissionAppConfig = config[g_permissionPrefix][0];
        for (auto it = permissionAppConfig.begin(); it != permissionAppConfig.end(); it++) {
            permissionSet.insert(it.key());
        }
    }
    APPSPAWN_LOGI("GetMountPermissionNames size: %{public}lu", static_cast<unsigned long>(permissionSet.size()));
    return permissionSet;
}

int32_t SandboxUtils::DoSandboxFilePrivateSymlink(const ClientSocket::AppProperty *appProperty,
                                                  nlohmann::json &wholeConfig)
{
    nlohmann::json privateAppConfig = wholeConfig[g_privatePrefix][0];
    if (privateAppConfig.find(appProperty->bundleName) != privateAppConfig.end()) {
        return DoAllSymlinkPointslink(appProperty, privateAppConfig[appProperty->bundleName][0]);
    }

    return 0;
}

int32_t SandboxUtils::HandleFlagsPoint(const ClientSocket::AppProperty *appProperty,
                                       nlohmann::json &appConfig)
{
    if (appConfig.find(g_flagePoint) == appConfig.end()) {
        return 0;
    }

    nlohmann::json flagsPoints = appConfig[g_flagePoint];
    unsigned int flagsPointSize = flagsPoints.size();

    for (unsigned int i = 0; i < flagsPointSize; i++) {
        nlohmann::json flagPoint = flagsPoints[i];

        if (flagPoint.find(g_flags) != flagPoint.end()) {
            std::string flagsStr = flagPoint[g_flags].get<std::string>();
            uint32_t flag = ConvertFlagStr(flagsStr);
            if ((appProperty->flags & flag) != 0) {
                return DoAllMntPointsMount(appProperty, flagPoint, g_flagePoint);
            }
        } else {
            APPSPAWN_LOGE("read flags config failed, app name is %{public}s", appProperty->bundleName);
        }
    }

    return 0;
}

int32_t SandboxUtils::DoSandboxFilePrivateFlagsPointHandle(const ClientSocket::AppProperty *appProperty,
                                                           nlohmann::json &wholeConfig)
{
    nlohmann::json privateAppConfig = wholeConfig[g_privatePrefix][0];
    if (privateAppConfig.find(appProperty->bundleName) != privateAppConfig.end()) {
        return HandleFlagsPoint(appProperty, privateAppConfig[appProperty->bundleName][0]);
    }

    return 0;
}

int32_t SandboxUtils::DoSandboxFileCommonFlagsPointHandle(const ClientSocket::AppProperty *appProperty,
                                                          nlohmann::json &wholeConfig)
{
    nlohmann::json commonConfig = wholeConfig[g_commonPrefix][0];
    if (commonConfig.find(g_appResources) != commonConfig.end()) {
        return HandleFlagsPoint(appProperty, commonConfig[g_appResources][0]);
    }

    return 0;
}

int32_t SandboxUtils::DoSandboxFileCommonBind(const ClientSocket::AppProperty *appProperty, nlohmann::json &wholeConfig)
{
    nlohmann::json commonConfig = wholeConfig[g_commonPrefix][0];
    int ret = 0;

    if (commonConfig.find(g_appBase) != commonConfig.end()) {
        ret = DoAllMntPointsMount(appProperty, commonConfig[g_appBase][0], g_appBase);
        if (ret) {
            return ret;
        }
    }

    if (commonConfig.find(g_appResources) != commonConfig.end()) {
        ret = DoAllMntPointsMount(appProperty, commonConfig[g_appResources][0], g_appResources);
    }

    return ret;
}

int32_t SandboxUtils::DoSandboxFileCommonSymlink(const ClientSocket::AppProperty *appProperty,
                                                 nlohmann::json &wholeConfig)
{
    nlohmann::json commonConfig = wholeConfig[g_commonPrefix][0];
    int ret = 0;

    if (commonConfig.find(g_appBase) != commonConfig.end()) {
        ret = DoAllSymlinkPointslink(appProperty, commonConfig[g_appBase][0]);
        if (ret) {
            return ret;
        }
    }

    if (commonConfig.find(g_appResources) != commonConfig.end()) {
        ret = DoAllSymlinkPointslink(appProperty, commonConfig[g_appResources][0]);
    }

    return ret;
}

int32_t SandboxUtils::SetPrivateAppSandboxProperty_(const ClientSocket::AppProperty *appProperty,
                                                    nlohmann::json &config)
{
    int ret = DoSandboxFilePrivateBind(appProperty, config);
    APPSPAWN_CHECK(ret == 0, return ret, "DoSandboxFilePrivateBind failed");

    ret = DoSandboxFilePrivateSymlink(appProperty, config);
    APPSPAWN_CHECK_ONLY_LOG(ret == 0, "DoSandboxFilePrivateSymlink failed");

    ret = DoSandboxFilePrivateFlagsPointHandle(appProperty, config);
    APPSPAWN_CHECK_ONLY_LOG(ret == 0, "DoSandboxFilePrivateFlagsPointHandle failed");

    return ret;
}

int32_t SandboxUtils::SetPermissionAppSandboxProperty_(ClientSocket::AppProperty *appProperty,
    nlohmann::json &config)
{
    int ret = DoSandboxFilePermissionBind(appProperty, config);
    APPSPAWN_CHECK(ret == 0, return ret, "DoSandboxFilePermissionBind failed");
    return ret;
}


int32_t SandboxUtils::SetRenderSandboxProperty(const ClientSocket::AppProperty *appProperty,
                                               std::string &sandboxPackagePath)
{
    return 0;
}

int32_t SandboxUtils::SetRenderSandboxPropertyNweb(const ClientSocket::AppProperty *appProperty,
                                                   std::string &sandboxPackagePath)
{
    for (auto config : SandboxUtils::GetJsonConfig()) {
        nlohmann::json privateAppConfig = config[g_privatePrefix][0];

        if (privateAppConfig.find(g_ohosRender) != privateAppConfig.end()) {
            int ret = DoAllMntPointsMount(appProperty, privateAppConfig[g_ohosRender][0], g_ohosRender);
            APPSPAWN_CHECK(ret == 0, return ret, "DoAllMntPointsMount failed, %{public}s",
                appProperty->bundleName);
            ret = DoAllSymlinkPointslink(appProperty, privateAppConfig[g_ohosRender][0]);
            APPSPAWN_CHECK(ret == 0, return ret, "DoAllSymlinkPointslink failed, %{public}s",
                appProperty->bundleName);
            ret = HandleFlagsPoint(appProperty, privateAppConfig[g_ohosRender][0]);
            APPSPAWN_CHECK_ONLY_LOG(ret == 0, "HandleFlagsPoint for render-sandbox failed, %{public}s",
                appProperty->bundleName);
        }
    }
    return 0;
}

int32_t SandboxUtils::SetPrivateAppSandboxProperty(const ClientSocket::AppProperty *appProperty)
{
    int ret = 0;
    for (auto config : SandboxUtils::GetJsonConfig()) {
        ret = SetPrivateAppSandboxProperty_(appProperty, config);
        APPSPAWN_CHECK(ret == 0, return ret, "parse adddata-sandbox config failed");
    }
    return ret;
}

static bool GetSandboxPrivateSharedStatus(const string &bundleName)
{
    bool result = false;
    for (auto config : SandboxUtils::GetJsonConfig()) {
        nlohmann::json privateAppConfig = config[g_privatePrefix][0];
        if (privateAppConfig.find(bundleName) != privateAppConfig.end() &&
            privateAppConfig[bundleName][0].find(g_sandBoxShared) !=
            privateAppConfig[bundleName][0].end()) {
            string sandboxSharedStatus =
                privateAppConfig[bundleName][0][g_sandBoxShared].get<std::string>();
            if (sandboxSharedStatus == g_statusCheck) {
                result = true;
            }
        }
    }
    return result;
}

int32_t SandboxUtils::SetPermissionAppSandboxProperty(ClientSocket::AppProperty *appProperty)
{
    int ret = 0;
    for (auto config : SandboxUtils::GetJsonConfig()) {
        ret = SetPermissionAppSandboxProperty_(appProperty, config);
        APPSPAWN_CHECK(ret == 0, return ret, "parse adddata-sandbox config failed");
    }
    return ret;
}


int32_t SandboxUtils::SetCommonAppSandboxProperty_(const ClientSocket::AppProperty *appProperty,
                                                   nlohmann::json &config)
{
    int rc = 0;

    rc = DoSandboxFileCommonBind(appProperty, config);
    APPSPAWN_CHECK(rc == 0, return rc, "DoSandboxFileCommonBind failed, %{public}s", appProperty->bundleName);

    // if sandbox switch is off, don't do symlink work again
    if (CheckAppSandboxSwitchStatus(appProperty) == true && (CheckTotalSandboxSwitchStatus(appProperty) == true)) {
        rc = DoSandboxFileCommonSymlink(appProperty, config);
        APPSPAWN_CHECK(rc == 0, return rc, "DoSandboxFileCommonSymlink failed, %{public}s", appProperty->bundleName);
    }

    rc = DoSandboxFileCommonFlagsPointHandle(appProperty, config);
    APPSPAWN_CHECK_ONLY_LOG(rc == 0, "DoSandboxFilePrivateFlagsPointHandle failed");

    return rc;
}

int32_t SandboxUtils::SetCommonAppSandboxProperty(const ClientSocket::AppProperty *appProperty,
                                                  std::string &sandboxPackagePath)
{
    int ret = 0;
    for (auto jsonConfig : SandboxUtils::GetJsonConfig()) {
        ret = SetCommonAppSandboxProperty_(appProperty, jsonConfig);
        APPSPAWN_CHECK(ret == 0, return ret,
            "parse appdata config for common failed, %{public}s", sandboxPackagePath.c_str());
    }

    ret = MountAllHsp(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(ret == 0, return ret, "mount extraInfo failed, %{public}s", sandboxPackagePath.c_str());

    ret = MountAllGroup(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(ret == 0, return ret, "mount groupList failed, %{public}s", sandboxPackagePath.c_str());

    if (strcmp(appProperty->apl, APL_SYSTEM_BASIC.data()) == 0 ||
        strcmp(appProperty->apl, APL_SYSTEM_CORE.data()) == 0 ||
        (appProperty->flags & APP_ACCESS_BUNDLE_DIR) != 0) {
        // need permission check for system app here
        std::string destbundlesPath = sandboxPackagePath + g_dataBundles;
        DoAppSandboxMountOnce(g_physicalAppInstallPath.c_str(), destbundlesPath.c_str(), "", BASIC_MOUNT_FLAGS,
                              nullptr);
    }

    return 0;
}

static inline bool CheckPath(const std::string& name)
{
    return !name.empty() && name != "." && name != ".." && name.find("/") == std::string::npos;
}

static std::string GetExtraInfoByType(const ClientSocket::AppProperty *appProperty, const std::string &type)
{
    if (appProperty->extraInfo.totalLength == 0 || appProperty->extraInfo.data == NULL) {
        return "";
    }

    std::string extraInfoStr = std::string(appProperty->extraInfo.data);
    std::size_t firstPos = extraInfoStr.find(type);
    if (firstPos == std::string::npos && firstPos != (extraInfoStr.size() - 1)) {
        return "";
    }

    extraInfoStr = extraInfoStr.substr(firstPos + type.size());
    std::size_t secondPos = extraInfoStr.find(type);
    if (secondPos == std::string::npos) {
        return "";
    }
    return extraInfoStr.substr(0, secondPos);
}

int32_t SandboxUtils::MountAllHsp(const ClientSocket::AppProperty *appProperty, std::string &sandboxPackagePath)
{
    int ret = 0;
    string hspListInfo = GetExtraInfoByType(appProperty, HSPLIST_SOCKET_TYPE);
    if (hspListInfo.length() == 0) {
        return ret;
    }

    nlohmann::json hsps = nlohmann::json::parse(hspListInfo.c_str(), nullptr, false);
    APPSPAWN_CHECK(!hsps.is_discarded() && hsps.contains(g_hspList_key_bundles) && hsps.contains(g_hspList_key_modules)
        && hsps.contains(g_hspList_key_versions), return -1, "MountAllHsp: json parse failed");

    nlohmann::json& bundles = hsps[g_hspList_key_bundles];
    nlohmann::json& modules = hsps[g_hspList_key_modules];
    nlohmann::json& versions = hsps[g_hspList_key_versions];
    APPSPAWN_CHECK(bundles.is_array() && modules.is_array() && versions.is_array() && bundles.size() == modules.size()
        && bundles.size() == versions.size(), return -1, "MountAllHsp: value is not arrary or sizes are not same");

    APPSPAWN_LOGI("MountAllHsp: app = %{public}s, cnt = %{public}lu",
        appProperty->bundleName, static_cast<unsigned long>(bundles.size()));
    for (uint32_t i = 0; i < bundles.size(); i++) {
        // elements in json arrary can be different type
        APPSPAWN_CHECK(bundles[i].is_string() && modules[i].is_string() && versions[i].is_string(),
            return -1, "MountAllHsp: element type error");

        std::string libBundleName = bundles[i];
        std::string libModuleName = modules[i];
        std::string libVersion = versions[i];
        APPSPAWN_CHECK(CheckPath(libBundleName) && CheckPath(libModuleName) && CheckPath(libVersion),
            return -1, "MountAllHsp: path error");

        std::string libPhysicalPath = g_physicalAppInstallPath + libBundleName + "/" + libVersion + "/" + libModuleName;
        std::string mntPath =  sandboxPackagePath + g_sandboxHspInstallPath + libBundleName + "/" + libModuleName;
        ret = DoAppSandboxMountOnce(libPhysicalPath.c_str(), mntPath.c_str(), "", BASIC_MOUNT_FLAGS, nullptr);
        APPSPAWN_CHECK(ret == 0, return ret, "mount library failed %{public}d", ret);
    }
    return ret;
}

int32_t SandboxUtils::DoSandboxRootFolderCreateAdapt(std::string &sandboxPackagePath)
{
#ifndef APPSPAWN_TEST
    int rc = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
    APPSPAWN_CHECK(rc == 0, return rc, "set propagation slave failed");
#endif
    MakeDirRecursive(sandboxPackagePath, FILE_MODE);

    // bind mount "/" to /mnt/sandbox/<packageName> path
    // rootfs: to do more resources bind mount here to get more strict resources constraints
#ifndef APPSPAWN_TEST
    rc = mount("/", sandboxPackagePath.c_str(), NULL, BASIC_MOUNT_FLAGS, NULL);
    APPSPAWN_CHECK(rc == 0, return rc, "mount bind / failed, %{public}d", errno);
#endif
    return 0;
}

int32_t SandboxUtils::MountAllGroup(const ClientSocket::AppProperty *appProperty, std::string &sandboxPackagePath)
{
    int ret = 0;
    string dataGroupInfo = GetExtraInfoByType(appProperty, DATA_GROUP_SOCKET_TYPE);
    if (dataGroupInfo.length() == 0) {
        return ret;
    }

    nlohmann::json groups = nlohmann::json::parse(dataGroupInfo.c_str(), nullptr, false);
    APPSPAWN_CHECK(!groups.is_discarded() && groups.contains(g_groupList_key_dataGroupId)
        && groups.contains(g_groupList_key_gid) && groups.contains(g_groupList_key_dir), return -1,
            "MountAllGroup: json parse failed");

    nlohmann::json& dataGroupIds = groups[g_groupList_key_dataGroupId];
    nlohmann::json& gids = groups[g_groupList_key_gid];
    nlohmann::json& dirs = groups[g_groupList_key_dir];
    APPSPAWN_CHECK(dataGroupIds.is_array() && gids.is_array() && dirs.is_array() && dataGroupIds.size() == gids.size()
        && dataGroupIds.size() == dirs.size(), return -1, "MountAllGroup: value is not arrary or sizes are not same");
    APPSPAWN_LOGI("MountAllGroup: app = %{public}s, cnt = %{public}lu",
        appProperty->bundleName, static_cast<unsigned long>(dataGroupIds.size()));
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
        ret = DoAppSandboxMountOnce(libPhysicalPath.c_str(), mntPath.c_str(), "", BASIC_MOUNT_FLAGS, nullptr);
        APPSPAWN_CHECK(ret == 0, return ret, "mount library failed %d", ret);
    }
    return ret;
}

int32_t SandboxUtils::DoSandboxRootFolderCreate(const ClientSocket::AppProperty *appProperty,
                                                std::string &sandboxPackagePath)
{
#ifndef APPSPAWN_TEST
    int rc = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
    if (rc) {
        return rc;
    }
#endif
    DoAppSandboxMountOnce(sandboxPackagePath.c_str(), sandboxPackagePath.c_str(), "",
                          BASIC_MOUNT_FLAGS, nullptr);

    return 0;
}

bool SandboxUtils::CheckBundleNameForPrivate(const std::string &bundleName)
{
    if (bundleName.find(g_internal) != std::string::npos) {
        return false;
    }
    return true;
}

bool SandboxUtils::CheckTotalSandboxSwitchStatus(const ClientSocket::AppProperty *appProperty)
{
    for (auto wholeConfig : SandboxUtils::GetJsonConfig()) {
        nlohmann::json commonAppConfig = wholeConfig[g_commonPrefix][0];
        if (commonAppConfig.find(g_topSandBoxSwitchPrefix) != commonAppConfig.end()) {
            std::string switchStatus = commonAppConfig[g_topSandBoxSwitchPrefix].get<std::string>();
            if (switchStatus == g_sbxSwitchCheck) {
                return true;
            } else {
                return false;
            }
        }
    }
    // default sandbox switch is on
    return true;
}

bool SandboxUtils::CheckAppSandboxSwitchStatus(const ClientSocket::AppProperty *appProperty)
{
    bool rc = true;
    for (auto wholeConfig : SandboxUtils::GetJsonConfig()) {
        APPSPAWN_LOGV("CheckAppSandboxSwitchStatus middle ");
        nlohmann::json privateAppConfig = wholeConfig[g_privatePrefix][0];
        if (privateAppConfig.find(appProperty->bundleName) != privateAppConfig.end()) {
            nlohmann::json appConfig = privateAppConfig[appProperty->bundleName][0];
            rc = GetSbxSwitchStatusByConfig(appConfig);
            APPSPAWN_LOGE("CheckAppSandboxSwitchStatus middle, %{public}d", rc);
            if (rc) {
                break;
            }
        }
    }
    // default sandbox switch is on
    return rc;
}

static int CheckBundleName(const std::string &bundleName)
{
    if (bundleName.empty() || bundleName.size() > APP_LEN_BUNDLE_NAME) {
        return -1;
    }
    if (bundleName.find('\\') != std::string::npos || bundleName.find('/') != std::string::npos) {
        return -1;
    }
    return 0;
}

int32_t SandboxUtils::SetOverlayAppSandboxProperty(const ClientSocket::AppProperty *appProperty,
                                                   string &sandboxPackagePath)
{
    int ret = 0;
    if ((appProperty->flags & APP_OVERLAY_FLAG) != APP_OVERLAY_FLAG) {
        return ret;
    }

    string overlayInfo = GetExtraInfoByType(appProperty, OVERLAY_SOCKET_TYPE);
    set<string> mountedSrcSet;
    vector<string> splits = split(overlayInfo, g_overlayDecollator);
    string sandboxOverlayPath = sandboxPackagePath + g_overlayPath;
    for (auto hapPath : splits) {
        size_t pathIndex = hapPath.find_last_of(g_fileSeparator);
        if (pathIndex == string::npos) {
            continue;
        }
        std::string srcPath = hapPath.substr(0, pathIndex);
        if (mountedSrcSet.find(srcPath) != mountedSrcSet.end()) {
            APPSPAWN_LOGV("%{public}s have mounted before, no need to mount twice.", srcPath.c_str());
            continue;
        }

        auto bundleNameIndex = srcPath.find_last_of(g_fileSeparator);
        string destPath = sandboxOverlayPath + srcPath.substr(bundleNameIndex + 1, srcPath.length());
        int32_t retMount = DoAppSandboxMountOnce(srcPath.c_str(), destPath.c_str(),
                                                 nullptr, BASIC_MOUNT_FLAGS, nullptr);
        if (retMount != 0) {
            APPSPAWN_LOGE("fail to mount overlay path, src is %s.", hapPath.c_str());
            ret = retMount;
        }

        mountedSrcSet.emplace(srcPath);
    }
    return ret;
}

int32_t SandboxUtils::SetBundleResourceAppSandboxProperty(const ClientSocket::AppProperty *appProperty,
                                                   string &sandboxPackagePath)
{
    int ret = 0;
    if ((appProperty->flags & GET_BUNDLE_RESOURCES_FLAG) != GET_BUNDLE_RESOURCES_FLAG) {
        return ret;
    }

    string srcPath = g_bundleResourceSrcPath;
    string destPath = sandboxPackagePath + g_bundleResourceDestPath;
    ret = DoAppSandboxMountOnce(
        srcPath.c_str(), destPath.c_str(), nullptr, BASIC_MOUNT_FLAGS, nullptr);
    return ret;
}

int32_t SandboxUtils::SetAppSandboxProperty(AppSpawnClient *client)
{
    APPSPAWN_CHECK(client != NULL, return -1, "Invalid appspwn client");
    AppSpawnClientExt *clientExt = reinterpret_cast<AppSpawnClientExt *>(client);
    ClientSocket::AppProperty *appProperty = &clientExt->property;
    if (CheckBundleName(appProperty->bundleName) != 0) {
        return -1;
    }
    std::string sandboxPackagePath = g_sandBoxRootDir;
    const std::string bundleName = appProperty->bundleName;
    bool sandboxSharedStatus = GetSandboxPrivateSharedStatus(bundleName);
    sandboxPackagePath += bundleName;
    MakeDirRecursive(sandboxPackagePath.c_str(), FILE_MODE);
    int rc = 0;
    // when CLONE_NEWPID is enabled, CLONE_NEWNS must be enabled.
    if (!(client->cloneFlags & CLONE_NEWPID)) {
        // add pid to a new mnt namespace
        rc = unshare(CLONE_NEWNS);
        APPSPAWN_CHECK(rc == 0, return rc, "unshare failed, packagename is %{public}s", bundleName.c_str());
    }

    // check app sandbox switch
    if ((CheckTotalSandboxSwitchStatus(appProperty) == false) ||
        (CheckAppSandboxSwitchStatus(appProperty) == false)) {
        rc = DoSandboxRootFolderCreateAdapt(sandboxPackagePath);
    } else if (!sandboxSharedStatus) {
        rc = DoSandboxRootFolderCreate(appProperty, sandboxPackagePath);
    }
    APPSPAWN_CHECK(rc == 0, return rc, "DoSandboxRootFolderCreate failed, %{public}s", bundleName.c_str());
    rc = SetCommonAppSandboxProperty(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetCommonAppSandboxProperty failed, packagename is %{public}s",
        bundleName.c_str());
    if (CheckBundleNameForPrivate(bundleName)) {
        rc = SetPrivateAppSandboxProperty(appProperty);
        APPSPAWN_CHECK(rc == 0, return rc, "SetPrivateAppSandboxProperty failed, packagename is %{public}s",
            bundleName.c_str());
    }
    rc = SetPermissionAppSandboxProperty(appProperty);
    APPSPAWN_CHECK(rc == 0, return rc, "SetPermissionAppSandboxProperty failed, packagename is %{public}s",
        bundleName.c_str());

    rc = SetOverlayAppSandboxProperty(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetOverlayAppSandboxProperty failed, packagename is %s",
        bundleName.c_str());

    rc = SetBundleResourceAppSandboxProperty(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetBundleResourceAppSandboxProperty failed, packagename is %s",
        bundleName.c_str());

#ifndef APPSPAWN_TEST
    rc = chdir(sandboxPackagePath.c_str());
    APPSPAWN_CHECK(rc == 0, return rc, "chdir failed, packagename is %{public}s, path is %{public}s",
        bundleName.c_str(), sandboxPackagePath.c_str());

    if (sandboxSharedStatus) {
        rc = chroot(sandboxPackagePath.c_str());
        APPSPAWN_CHECK(rc == 0, return rc, "chroot failed, path is %{public}s errno is %{public}d",
            sandboxPackagePath.c_str(), errno);
        return 0;
    }

    rc = syscall(SYS_pivot_root, sandboxPackagePath.c_str(), sandboxPackagePath.c_str());
    APPSPAWN_CHECK(rc == 0, return rc, "errno is %{public}d, pivot root failed, packagename is %{public}s",
        errno, bundleName.c_str());

    rc = umount2(".", MNT_DETACH);
    APPSPAWN_CHECK(rc == 0, return rc, "MNT_DETACH failed, packagename is %{public}s", bundleName.c_str());
#endif
    return 0;
}

int32_t SandboxUtils::SetAppSandboxPropertyNweb(AppSpawnClient *client)
{
    APPSPAWN_CHECK(client != NULL, return -1, "Invalid appspwn client");
    AppSpawnClientExt *clientExt = reinterpret_cast<AppSpawnClientExt *>(client);
    ClientSocket::AppProperty *appProperty = &clientExt->property;
    if (CheckBundleName(appProperty->bundleName) != 0) {
        return -1;
    }
    std::string sandboxPackagePath = g_sandBoxRootDirNweb;
    const std::string bundleName = appProperty->bundleName;
    bool sandboxSharedStatus = GetSandboxPrivateSharedStatus(bundleName);
    sandboxPackagePath += bundleName;
    MakeDirRecursive(sandboxPackagePath.c_str(), FILE_MODE);
    int rc = 0;
    // when CLONE_NEWPID is enabled, CLONE_NEWNS must be enabled.
    if (!(client->cloneFlags & CLONE_NEWPID)) {
        // add pid to a new mnt namespace
        rc = unshare(CLONE_NEWNS);
        APPSPAWN_CHECK(rc == 0, return rc, "unshare failed, packagename is %{public}s", bundleName.c_str());
    }

    // check app sandbox switch
    if ((CheckTotalSandboxSwitchStatus(appProperty) == false) ||
        (CheckAppSandboxSwitchStatus(appProperty) == false)) {
        rc = DoSandboxRootFolderCreateAdapt(sandboxPackagePath);
    } else if (!sandboxSharedStatus) {
        rc = DoSandboxRootFolderCreate(appProperty, sandboxPackagePath);
    }
    APPSPAWN_CHECK(rc == 0, return rc, "DoSandboxRootFolderCreate failed, %{public}s", bundleName.c_str());
    // rendering process can be created by different apps,
    // and the bundle names of these apps are different,
    // so we can't use the method SetPrivateAppSandboxProperty
    // which mount dirs by using bundle name.
    rc = SetRenderSandboxPropertyNweb(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetRenderSandboxPropertyNweb failed, packagename is %{public}s",
        sandboxPackagePath.c_str());

    rc = SetOverlayAppSandboxProperty(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetOverlayAppSandboxProperty failed, packagename is %s",
        bundleName.c_str());

    rc = SetBundleResourceAppSandboxProperty(appProperty, sandboxPackagePath);
    APPSPAWN_CHECK(rc == 0, return rc, "SetBundleResourceAppSandboxProperty failed, packagename is %s",
        bundleName.c_str());

#ifndef APPSPAWN_TEST
    rc = chdir(sandboxPackagePath.c_str());
    APPSPAWN_CHECK(rc == 0, return rc, "chdir failed, packagename is %{public}s, path is %{public}s",
        bundleName.c_str(), sandboxPackagePath.c_str());

    if (sandboxSharedStatus) {
        rc = chroot(sandboxPackagePath.c_str());
        APPSPAWN_CHECK(rc == 0, return rc, "chroot failed, path is %{public}s errno is %{public}d",
            sandboxPackagePath.c_str(), errno);
        return 0;
    }

    rc = syscall(SYS_pivot_root, sandboxPackagePath.c_str(), sandboxPackagePath.c_str());
    APPSPAWN_CHECK(rc == 0, return rc, "errno is %{public}d, pivot root failed, packagename is %{public}s",
        errno, bundleName.c_str());

    rc = umount2(".", MNT_DETACH);
    APPSPAWN_CHECK(rc == 0, return rc, "MNT_DETACH failed, packagename is %{public}s", bundleName.c_str());
#endif
    return 0;
}
} // namespace AppSpawn
} // namespace OHOS
