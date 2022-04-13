/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "appspawn_server.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef OHOS_DEBUG
#include <time.h>
#endif // OHOS_DEBUG

static int NotifyResToParent(struct AppSpawnContent_ *content, AppSpawnClient *client, int result)
{
    if (content->notifyResToParent != NULL) {
        content->notifyResToParent(content, client, result);
    }
    return 0;
}

void DoStartApp(struct AppSpawnContent_ *content, AppSpawnClient *client, char *longProcName, int64_t longProcNameLen)
{
    APPSPAWN_LOGI("DoStartApp id %d ", client->id);
    int32_t ret = 0;
    if (content->setAppSandbox) {
        ret = content->setAppSandbox(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to set app sandbox");
    }
    if (content->setKeepCapabilities) {
        ret = content->setKeepCapabilities(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to set KeepCapabilities");
    }
    if (content->setProcessName) {
        ret = content->setProcessName(content, client, longProcName, longProcNameLen);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to set setProcessName");
    }

    if (content->setUidGid) {
        ret = content->setUidGid(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to setUidGid");
    }
    if (content->setFileDescriptors) {
        ret = content->setFileDescriptors(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to setFileDescriptors");
    }
    if (content->setCapabilities) {
        ret = content->setCapabilities(content, client);
        APPSPAWN_CHECK(ret == 0, NotifyResToParent(content, client, ret);
            return, "Failed to setCapabilities");
    }
    // notify success to father process and start app process
    NotifyResToParent(content, client, 0);
}

int AppSpawnProcessMsg(struct AppSpawnContent_ *content, AppSpawnClient *client, pid_t *childPid)
{
    APPSPAWN_CHECK(content != NULL, return -1, "Invalid content for appspawn");
    APPSPAWN_CHECK(client != NULL && childPid != NULL, return -1, "Invalid client for appspawn");
    APPSPAWN_LOGI("AppSpawnProcessMsg id %d 0x%x", client->id, client->flags);
    RegisterAppSandbox(content, client);
    pid_t pid = fork();
    if (pid < 0) {
        return -errno;
    } else if (pid == 0) {
#ifdef OHOS_DEBUG
        struct timespec tmStart = {0};
        GetCurTime(&tmStart);
#endif // OHOS_DEBUG

        // close socket id and signal for child
        if (content->clearEnvironment != NULL) {
            content->clearEnvironment(content, client);
        }
        if (content->setAppAccessToken != NULL) {
            content->setAppAccessToken(content, client);
        }
        if (client->flags & APP_COLD_START) {
            if (content->coldStartApp != NULL && content->coldStartApp(content, client) == 0) {
                NotifyResToParent(content, client, 0);
                _exit(0x7f);
                return -1;
            } else {
                DoStartApp(content, client, content->longProcName, content->longProcNameLen);
            }
        } else {
            DoStartApp(content, client, content->longProcName, content->longProcNameLen);
        }
#ifdef OHOS_DEBUG
        struct timespec tmEnd = {0};
        GetCurTime(&tmEnd);
        // 1s = 1000000000ns
        long timeUsed = (tmEnd.tv_sec - tmStart.tv_sec) * 1000000000L + (tmEnd.tv_nsec - tmStart.tv_nsec);
        APPSPAWN_LOGI("App timeused %d %ld ns.", getpid(), timeUsed);
#endif  // OHOS_DEBUG
        if (content->runChildProcessor) {
            content->runChildProcessor(content, client);
        }
        APPSPAWN_LOGI("App exit %d.", getpid());
        _exit(0x7f);
    }
    *childPid = pid;
    return 0;
}

#ifdef OHOS_DEBUG
void GetCurTime(struct timespec *tmCur)
{
    if (tmCur == NULL) {
        return;
    }
    if (clock_gettime(CLOCK_REALTIME, tmCur) != 0) {
        APPSPAWN_LOGE("[appspawn] invoke, get time failed! err %d", errno);
    }
}
#endif  // OHOS_DEBUG