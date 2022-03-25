/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "appspawn_service.h"

#include <fcntl.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "appspawn_server.h"
#include "securec.h"

int setProcessName(struct AppSpawnContent_ *content, AppSpawnClient *client,
        char *longProcName, int64_t longProcNameLen)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    size_t len = strlen(appProperty->property.processName) + 1;
    if (longProcName == NULL || longProcNameLen <= 0 || len <= 1) {
        APPSPAWN_LOGE("process name is nullptr or length error");
        return -EINVAL;
    }

    char shortName[MAX_LEN_SHORT_NAME] = {0};
    // process short name max length 16 bytes.
    if (len > MAX_LEN_SHORT_NAME) {
        if (strncpy_s(shortName, MAX_LEN_SHORT_NAME, appProperty->property.processName, MAX_LEN_SHORT_NAME - 1) != EOK) {
            APPSPAWN_LOGE("strncpy_s short name error: %d",errno);
            return -EINVAL;
        }
    } else {
        if (strncpy_s(shortName, MAX_LEN_SHORT_NAME, appProperty->property.processName, len) != EOK) {
            APPSPAWN_LOGE("strncpy_s short name error: %d",errno);
            return -EINVAL;
        }
    }

    // set short name
    if (prctl(PR_SET_NAME, shortName) == -1){
        APPSPAWN_LOGE("prctl(PR_SET_NAME) error: %d", errno);
        return (-errno);
    }

    // reset longProcName
    if (memset_s(longProcName, (size_t)longProcNameLen, 0, (size_t)longProcNameLen) != EOK) {
        APPSPAWN_LOGE("Failed to memset long process name");
        return -EINVAL;
    }

    // set long process name
    if (strncpy_s(longProcName, sizeof(appProperty->property.processName), appProperty->property.processName, len) != EOK) {
        APPSPAWN_LOGE("strncpy_s long name error: %d longProcNameLen %d", errno, longProcNameLen);
        return -EINVAL;
    }

    return 0;
}

int setKeepCapabilities(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    // set keep capabilities when user not root.
    if (appProperty->property.uid != 0) {
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
       APPSPAWN_LOGE("set keepcaps failed: %d",errno);
            return (-errno);
        }
    }
    return 0;
}

int setCapabilities(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    // init cap
    struct __user_cap_header_struct cap_header;

    if (memset_s(&cap_header, sizeof(cap_header), 0, sizeof(cap_header)) != EOK) {
        APPSPAWN_LOGE("Failed to memset cap header");
        return -EINVAL;
    }
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = 0;

    struct __user_cap_data_struct cap_data[2];
    if (memset_s(&cap_data, sizeof(cap_data), 0, sizeof(cap_data)) != EOK) {
        APPSPAWN_LOGE("Failed to memset cap data");
        return -EINVAL;
    }

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
    if (capset(&cap_header, &cap_data[0]) == -1) {
        APPSPAWN_LOGE("capset failed: %d",errno);
        return (-errno);
    }
    return 0;
}

static void ClearEnvironment(AppSpawnContent *content, AppSpawnClient *client)
{
    APPSPAWN_LOGI("ClearEnvironment id %d", client->id);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    // close child fd
    close(appProperty->fd[0]);
    return;
}

int setUidGid(struct AppSpawnContent_ *content, AppSpawnClient *client)
{
    AppSpawnClientExt *appProperty = (AppSpawnClientExt *)client;
    if (strlen(appProperty->property.gidTable)  ==  0) {
        APPSPAWN_LOGE("gitTable is nullptr");
        return (-errno);
    }

    // set gids
    if (setgroups(appProperty->property.gidCount, (const gid_t *)(&appProperty->property.gidTable[0])) == -1) {
        APPSPAWN_LOGE("setgroups failed: %d, gids.size=%u", errno, appProperty->property.gidCount);
        return (-errno);
    }

    // set gid
    if (setresgid(appProperty->property.gid, appProperty->property.gid, appProperty->property.gid) == -1) {
        APPSPAWN_LOGE("setgid(%u) failed: %d", appProperty->property.gid, errno);
        return (-errno);
    }

    // If the effective user ID is changed from 0 to nonzero, then all capabilities are cleared from the effective set
    if (setresuid(appProperty->property.uid, appProperty->property.uid, appProperty->property.uid) == -1) {
        APPSPAWN_LOGE("setuid(%u) failed: %d", appProperty->property.uid, errno);
        return (-errno);
    }

    return 0;
}

void SetContentFunction(AppSpawnContent *content)
{
    APPSPAWN_LOGI("SetContentFunction");
    content->clearEnvironment = ClearEnvironment;
    content->setProcessName = setProcessName;
    content->setKeepCapabilities = setKeepCapabilities;
    content->setUidGid = setUidGid;
}
