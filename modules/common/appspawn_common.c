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
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/capability.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <dlfcn.h>
#include <malloc.h>
#include <sched.h>

#include "appspawn_adapter.h"
#include "appspawn_hook.h"
#include "appspawn_msg.h"
#include "appspawn_service.h"
#include "init_param.h"
#include "parameter.h"
#include "securec.h"

#ifdef CODE_SIGNATURE_ENABLE  // for xpm
#include "code_sign_attr_utils.h"
#endif
#ifdef SECURITY_COMPONENT_ENABLE
#include "sec_comp_enhance_kit_c.h"
#endif
#ifdef WITH_SELINUX
#include "selinux/selinux.h"
#endif

#define DEVICE_NULL_STR "/dev/null"
#define BITLEN32 32
#define PID_NS_INIT_UID 100000  // reserved for pid_ns_init process, avoid app, render proc, etc.
#define PID_NS_INIT_GID 100000

static int SetProcessName(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetProcessName", GetProcessName(property));
    const char *processName = GetProcessName(property);
    APPSPAWN_CHECK(processName != NULL, return -EINVAL, "Can not get process name");
    // 解析时已经检查
    size_t len = strlen(processName);
    char shortName[MAX_LEN_SHORT_NAME] = {0};
    // process short name max length 16 bytes.
    size_t copyLen = len;
    const char *pos = processName;
    if (len >= MAX_LEN_SHORT_NAME) {
        copyLen = MAX_LEN_SHORT_NAME - 1;
        pos += (len - copyLen);
    }
    bool isRet = strncpy_s(shortName, MAX_LEN_SHORT_NAME, pos, copyLen) != EOK;
    APPSPAWN_CHECK(!isRet, return EINVAL, "strncpy_s short name error: %{public}d", errno);

    // set short name
    isRet = prctl(PR_SET_NAME, shortName) == -1;
    APPSPAWN_CHECK(!isRet, return errno, "prctl(PR_SET_NAME) error: %{public}d", errno);

    // reset longProcName
    isRet = memset_s(content->content.longProcName,
        (size_t)content->content.longProcNameLen, 0, (size_t)content->content.longProcNameLen) != EOK;
    APPSPAWN_CHECK(!isRet, return EINVAL, "Failed to memset long process name");

    // set long process name
    isRet = strncpy_s(content->content.longProcName, content->content.longProcNameLen, processName, len) != EOK;
    APPSPAWN_CHECK(!isRet, return EINVAL,
        "strncpy_s long name error: %{public}d longProcNameLen %{public}u", errno, content->content.longProcNameLen);
    return 0;
}

static int SetKeepCapabilities(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetKeepCapabilities", GetProcessName(property));
    AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)GetAppProperty(property, TLV_DAC_INFO);
    APPSPAWN_CHECK(dacInfo != NULL, return APPSPAWN_TLV_NONE,
        "No tlv %{public}d in msg %{public}s", TLV_DOMAIN_INFO, GetProcessName(property));

    // set keep capabilities when user not root.
    if (dacInfo->uid != 0) {
        bool isRet = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1;
        APPSPAWN_CHECK(!isRet, return errno, "set keepcaps failed: %{public}d", errno);
    }
    return 0;
}

static int SetCapabilities(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetCapabilities", GetProcessName(property));
    // init cap
    struct __user_cap_header_struct cap_header;

    bool isRet = memset_s(&cap_header, sizeof(cap_header), 0, sizeof(cap_header)) != EOK;
    APPSPAWN_CHECK(!isRet, return -EINVAL, "Failed to memset cap header");

    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = 0;

    struct __user_cap_data_struct cap_data[2];
    isRet = memset_s(&cap_data, sizeof(cap_data), 0, sizeof(cap_data)) != EOK;
    APPSPAWN_CHECK(!isRet, return -EINVAL, "Failed to memset cap data");

    // init inheritable permitted effective zero
#ifdef GRAPHIC_PERMISSION_CHECK
    const uint64_t inheriTable = 0;
    const uint64_t permitted = 0;
    const uint64_t effective = 0;
#else
    const uint64_t inheriTable = 0x3fffffffff;
    const uint64_t permitted = 0x3fffffffff;
    const uint64_t effective = 0x3fffffffff;
#endif

    cap_data[0].inheritable = (__u32)(inheriTable);
    cap_data[1].inheritable = (__u32)(inheriTable >> BITLEN32);
    cap_data[0].permitted = (__u32)(permitted);
    cap_data[1].permitted = (__u32)(permitted >> BITLEN32);
    cap_data[0].effective = (__u32)(effective);
    cap_data[1].effective = (__u32)(effective >> BITLEN32);

    // set capabilities
    isRet = capset(&cap_header, &cap_data[0]) != 0;
    APPSPAWN_CHECK(!isRet, return -errno, "Failed to capset errno: %{public}d", errno);
    return 0;
}

static void InitDebugParams(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "InitDebugParams", GetProcessName(property));
#if defined(__aarch64__) || defined(__x86_64__)
    const char *debugSoPath = "/system/lib64/libhidebug.so";
#else
    const char *debugSoPath = "/system/lib/libhidebug.so";
#endif
    const char *processName = GetProcessName(property);
    APPSPAWN_CHECK(processName != NULL, return, "Can not get process name ");

    bool isRet = access(debugSoPath, F_OK) != 0;
    APPSPAWN_CHECK(!isRet, return,
        "access failed, errno: %{public}d debugSoPath: %{public}s", errno, debugSoPath);

    void *handle = dlopen(debugSoPath, RTLD_LAZY);
    APPSPAWN_CHECK(handle != NULL, return, "Failed to dlopen libhidebug.so errno: %{public}s", dlerror());

    bool (*initParam)(const char *name);
    initParam = (bool (*)(const char *name))dlsym(handle, "InitEnvironmentParam");
    APPSPAWN_CHECK(initParam != NULL, dlclose(handle);
        return, "Failed to dlsym errno: %{public}s", dlerror());
    (*initParam)(processName);
    dlclose(handle);
}

static void ClearEnvironment(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "ClearEnvironment", GetProcessName(property));
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    // close child fd
    close(property->forkCtx.fd[0]);
    return;
}

static int SetXpmConfig(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetXpmConfig", GetProcessName(property));
#ifdef CODE_SIGNATURE_ENABLE
    // nwebspawn no permission set xpm config
    if (IsNWebSpawnMode(content)) {
        return 0;
    }
    AppSpawnMsgOwnerId *ownerInfo = (AppSpawnMsgOwnerId *)GetAppProperty(property, TLV_OWNER_INFO);
    int ret = InitXpmRegion();
    APPSPAWN_CHECK(ret == 0, return ret, "init xpm region failed: %{public}d", ret);

    if (TestAppMsgFlagsSet(property, APP_FLAGS_DEBUGGABLE)) {
        ret = SetXpmOwnerId(PROCESS_OWNERID_DEBUG, NULL);
    } else if (ownerInfo == NULL) {
        ret = SetXpmOwnerId(PROCESS_OWNERID_COMPAT, NULL);
    } else {
        ret = SetXpmOwnerId(PROCESS_OWNERID_APP, ownerInfo->ownerId);
    }
    APPSPAWN_CHECK(ret == 0, return ret, "set xpm region failed: %{public}d", ret);
#endif
    return 0;
}

static int SetUidGid(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetUidGid", GetProcessName(property));
    AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)GetAppProperty(property, TLV_DAC_INFO);
    APPSPAWN_CHECK(dacInfo != NULL, return APPSPAWN_TLV_NONE,
        "No tlv %{public}d in msg %{public}s", TLV_DAC_INFO, GetProcessName(property));

    // set gids
    int ret = setgroups(dacInfo->gidCount, (const gid_t *)(&dacInfo->gidTable[0]));
    APPSPAWN_CHECK(ret == 0, return errno,
        "setgroups failed: %{public}d, gids.size=%{public}u", errno, dacInfo->gidCount);

    // set gid
    ret = setresgid(dacInfo->gid, dacInfo->gid, dacInfo->gid);
    APPSPAWN_CHECK(ret == 0, return errno,
        "setgid(%{public}u) failed: %{public}d", dacInfo->gid, errno);

    ret = SetSeccompFilter(content, property);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to set setSeccompFilter");

    /* If the effective user ID is changed from 0 to nonzero,
     * then all capabilities are cleared from the effective set
     */
    ret = setresuid(dacInfo->uid, dacInfo->uid, dacInfo->uid);
    APPSPAWN_CHECK(ret == 0, return errno,
        "setuid(%{public}u) failed: %{public}d", dacInfo->uid, errno);

    if (TestAppMsgFlagsSet(property, APP_FLAGS_DEBUGGABLE) && IsDeveloperModeOn(property)) {
        setenv("HAP_DEBUGGABLE", "true", 1);
        if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
            APPSPAWN_LOGE("Failed to set app dumpable: %{public}s", strerror(errno));
        }
    }
    return 0;
}

static int32_t SetFileDescriptors(const AppSpawnMgr *content, const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "SetFileDescriptors", GetProcessName(property));
#ifndef APPSPAWN_TEST
    // close stdin stdout stderr
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    // redirect to /dev/null
    int devNullFd = open(DEVICE_NULL_STR, O_RDWR);
    if (devNullFd == -1) {
        APPSPAWN_LOGE("open dev_null error: %{public}d", errno);
        return (-errno);
    }

    // stdin
    if (dup2(devNullFd, STDIN_FILENO) == -1) {
        APPSPAWN_LOGE("dup2 STDIN error: %{public}d", errno);
        return (-errno);
    };

    // stdout
    if (dup2(devNullFd, STDOUT_FILENO) == -1) {
        APPSPAWN_LOGE("dup2 STDOUT error: %{public}d", errno);
        return (-errno);
    };
    // stderr
    if (dup2(devNullFd, STDERR_FILENO) == -1) {
        APPSPAWN_LOGE("dup2 STDERR error: %{public}d", errno);
        return (-errno);
    };
#endif
    return 0;
}

static int32_t CheckTraceStatus(void)
{
    int fd = open("/proc/self/status", O_RDONLY);
    APPSPAWN_CHECK(fd >= 0, return errno, "Failed to open /proc/self/status error: %{public}d", errno);

    char data[1024] = {0};  // 1024 is data length
    ssize_t dataNum = read(fd, data, sizeof(data));
    (void)close(fd);
    APPSPAWN_CHECK(dataNum > 0, return -1, "Failed to read file /proc/self/status error: %{public}d", errno);

    const char *tracerPid = "TracerPid:\t";
    char *traceStr = strstr(data, tracerPid);
    APPSPAWN_CHECK(traceStr != NULL, return -1, "Not found %{public}s", tracerPid);

    char *separator = strchr(traceStr, '\n');
    APPSPAWN_CHECK(separator != NULL, return -1, "Not found %{public}s", "\n");

    int len = separator - traceStr - strlen(tracerPid);
    char pid = *(traceStr + strlen(tracerPid));
    if (len > 1 || pid != '0') {
        return 0;
    }
    return -1;
}

static int32_t WaitForDebugger(const AppSpawningCtx *property)
{
    // wait for debugger only debugging is required and process is debuggable
    if (TestAppMsgFlagsSet(property, APP_FLAGS_NATIVEDEBUG) &&
        TestAppMsgFlagsSet(property, APP_FLAGS_DEBUGGABLE)) {
        uint32_t count = 0;
        while (CheckTraceStatus() != 0) {
#ifndef APPSPAWN_TEST
            usleep(1000 * 100);  // sleep 1000 * 100 microsecond
#else
            if (count > 0) {
                break;
            }
#endif
            count++;
            // remind users to connect to the debugger every 60 * 10 times
            if (count % (10 * 60) == 0) {
                count = 0;
                APPSPAWN_LOGI("wait for debugger, please attach the process");
            }
        }
    }
    return 0;
}

static bool IsUnlockStatus(uint32_t uid)
{
    uid = uid / UID_BASE;
    if (uid == 0) {
        return true;
    }
    const char rootPath[] = APPSPAWN_BASE_DIR "/data/app/el2/";
    const char basePath[] = "/base";
    size_t allPathSize = strlen(rootPath) + strlen(basePath) + USER_ID_BUFFER_SIZE + 1;
    char *path = (char *)malloc(sizeof(char) * allPathSize);
    APPSPAWN_CHECK(path != NULL, return true, "Failed to malloc path");
    size_t len = sprintf_s(path, allPathSize, "%s%u%s", rootPath, uid, basePath);
    APPSPAWN_CHECK(len > 0 && (len < allPathSize), free(path);
        return true, "Failed to get base path");
    APPSPAWN_LOGV("IsUnlockStatus %{public}s uid: %{public}u", path, uid);
    if (access(path, F_OK) == 0) {
        free(path);
        return true;
    }
    free(path);
    APPSPAWN_LOGI("this is lock status");
    return false;
}

static int MountAppEl2Dir(const AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Process step %{public}s processName:  %{public}s", "MountAppEl2Dir", GetProcessName(property));
    const char rootPath[] = APPSPAWN_BASE_DIR "/mnt/sandbox/";
    const char el2Path[] = "/data/storage/el2";
    AppSpawnMsgDacInfo *dacInfo = (AppSpawnMsgDacInfo *)GetAppProperty(property, TLV_DAC_INFO);
    APPSPAWN_CHECK(dacInfo != NULL, return APPSPAWN_TLV_NONE, "No dac info in msg %{public}s", GetProcessName(property));

    if (IsUnlockStatus(dacInfo->uid)) {
        return 0;
    }
    const char *bundleName = GetBundleName(property);
    size_t allPathSize = strlen(rootPath) + strlen(el2Path) + strlen(bundleName) + USER_ID_BUFFER_SIZE + 2;
    char *path = (char *)malloc(sizeof(char) * (allPathSize));
    APPSPAWN_CHECK(path != NULL, return -1, "Failed to malloc path");
    size_t len = sprintf_s(path, allPathSize, "%s%u/%s%s", rootPath, dacInfo->uid / UID_BASE, bundleName, el2Path);
    APPSPAWN_CHECK(len > 0 && (len < allPathSize), free(path);
        return -1, "Failed to get el2 path");
    APPSPAWN_LOGV("MountAppEl2Dir %{public}s processName:  %{public}s", path, GetProcessName(property));
    if (access(path, F_OK) == 0) {
        free(path);
        return 0;
    }

    int ret = MakeDirRecursive(path, DEFAULT_DIR_MODE);
    MountArg arg = {path, path, NULL, MS_BIND | MS_REC, NULL, MS_SHARED};
    ret = SandboxMountPath(&arg);
    free(path);
    return ret;
}

static int AppSpawnSpawnPrepare(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGV("AppSpawnSpawnPrepare clear env");
    int ret = SetProcessName(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    // close socket id and signal for child
    ClearEnvironment(content, property);

    ResetParamSecurityLabel();

    ret = SetAppAccessToken(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    return 0;
}

static int AppSpawnSpawnStep1(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGV("AppSpawnSpawnStep1 mallopt");
    // enable cache for app process
    mallopt(M_OHOS_CONFIG, M_TCACHE_PERFORMANCE_MODE);
    mallopt(M_OHOS_CONFIG, M_ENABLE_OPT_TCACHE);
    mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_ENABLE);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_ENABLE);

    int ret = SetInternetPermission(property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    return ret;
}

static int AppSpawnSpawnStep6(AppSpawnMgr *content, AppSpawningCtx *property)
{
    (void)umask(DEFAULT_UMASK);
    int ret = SetKeepCapabilities(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetXpmConfig(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    // 这里是否有必要
    ret = SetProcessName(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetUidGid(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetFileDescriptors(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetCapabilities(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetSelinuxCon(content, property) == -1;
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = SetEnvInfo(content, property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

    ret = WaitForDebugger(property);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);

#ifdef SECURITY_COMPONENT_ENABLE
    InitSecCompClientEnhance();
#endif
    return 0;
}

static int AppSpawnCommPreload(AppSpawnMgr *content)
{
    // set uid gid filetr
    int ret = SetUidGidFilter(content);
    APPSPAWN_CHECK_ONLY_EXPER(ret == 0, return ret);
    return ret;
}

static int AppSpawnSpawnAfter(AppSpawnMgr *content, AppSpawningCtx *property)
{
    InitDebugParams(content, property);
    return 0;
}

static int CheckEnabled(const char *param, const char *value)
{
    char tmp[32] = {0};  // 32 max
    int ret = GetParameter(param, "", tmp, sizeof(tmp));
    APPSPAWN_LOGV("IsParameterEnabled key %{public}s ret %{public}d result: %{public}s", param, ret, tmp);
    int enabled = (ret > 0 && strcmp(tmp, value) == 0);
    return enabled;
}

static int AppSpawnPreSpawn(AppSpawnMgr *content, AppSpawningCtx *property)
{
    APPSPAWN_LOGV("Prepare spawn app %{public}s", GetProcessName(property));
    if (TestAppMsgFlagsSet(property, APP_FLAGS_COLD_BOOT)) {
        // check cold start
        property->client.flags |= CheckEnabled("startup.appspawn.cold.boot", "true") ? APP_COLD_START : 0;
        ssize_t nread = readlink("/proc/self/exe",
            property->forkCtx.coldRunPath, sizeof(property->forkCtx.coldRunPath) - 1);
        if (nread <= 0) {
             APPSPAWN_LOGE("Failed to set asan exec path %{public}s", GetProcessName(property));
             return -1;
        }
        property->forkCtx.coldRunPath[nread] = '\0';
    }
    // check developer mode
    property->client.flags |= CheckEnabled("const.security.developermode.state", "true") ? APP_DEVELOPER_MODE : 0;
    MountAppEl2Dir(property);
    return 0;
}

static int EnablePidNs(AppSpawnMgr *content)
{
    APPSPAWN_LOGV("EnablePidNs %d %d", IsNWebSpawnMode(content), IsColdRunMode(content));
    if (IsNWebSpawnMode(content) || IsColdRunMode(content)) {
        return 0;
    }
    if (!(content->content.sandboxNsFlags & CLONE_NEWPID)) {
        return 0;
    }

    int ret = unshare(CLONE_NEWPID);
    APPSPAWN_CHECK(ret == 0, return -1, "unshare CLONE_NWEPID failed, errno=%{public}d", errno);

    pid_t pid = fork();
    if (pid == 0) {
        setuid(PID_NS_INIT_UID);
        setgid(PID_NS_INIT_GID);
#ifdef WITH_SELINUX
        setcon("u:r:pid_ns_init:s0");
#endif
        char *argv[] = {"/system/bin/pid_ns_init", NULL};
        execve("/system/bin/pid_ns_init", argv, NULL);
        _exit(0x7f);
    }
    APPSPAWN_LOGI("Enable pid namespace success.");
    return 0;
}

MODULE_CONSTRUCTOR(void)
{
    APPSPAWN_LOGV("Load common module ...");
    AddPreloadHook(HOOK_PRIO_STEP2, AppSpawnCommPreload);
    AddPreloadHook(HOOK_PRIO_STEP6, EnablePidNs);

    AddAppSpawnHook(HOOK_SPAWN_PREPARE, HOOK_PRIO_STEP1, AppSpawnPreSpawn);
    AddAppSpawnHook(HOOK_SPAWN_CLEAR_ENV, HOOK_PRIO_STEP1, AppSpawnSpawnPrepare);
    AddAppSpawnHook(HOOK_SPAWN_SET_CHILD_PROPERTY, HOOK_PRIO_STEP1, AppSpawnSpawnStep1);
    AddAppSpawnHook(HOOK_SPAWN_SET_CHILD_PROPERTY, HOOK_PRIO_STEP6, AppSpawnSpawnStep6);
    AddAppSpawnHook(HOOK_SPAWN_COMPLETED, HOOK_PRIO_STEP1, AppSpawnSpawnAfter);
}
