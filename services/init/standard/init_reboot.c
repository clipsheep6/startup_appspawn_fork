/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>

#include "fs_manager/fs_manager.h"
#include "init_log.h"
#include "init_jobs_internal.h"
#include "init_group_manager.h"
#include "init_service.h"
#include "init_service_manager.h"
#include "init_utils.h"
#include "securec.h"

#ifdef PRODUCT_RK
#include <sys/syscall.h>

#define REBOOT_MAGIC1       0xfee1dead
#define REBOOT_MAGIC2       672274793
#define REBOOT_CMD_RESTART2 0xA1B2C3D4
#endif

#define MAX_VALUE_LENGTH 500
#define MAX_COMMAND_SIZE 20
#define MAX_UPDATE_SIZE 100

struct RBMiscUpdateMessage {
    char command[MAX_COMMAND_SIZE];
    char update[MAX_UPDATE_SIZE];
};

static int RBMiscWriteUpdaterMessage(const char *path, const struct RBMiscUpdateMessage *boot)
{
    char *realPath = GetRealPath(path);
    INIT_CHECK_RETURN_VALUE(realPath != NULL, -1);
    int ret = 0;
    FILE *fp = fopen(realPath, "rb+");
    free(realPath);
    realPath = NULL;
    if (fp != NULL) {
        size_t writeLen = fwrite(boot, sizeof(struct RBMiscUpdateMessage), 1, fp);
        INIT_ERROR_CHECK(writeLen == 1, ret = -1, "Failed to write misc for reboot");
        (void)fclose(fp);
    } else {
        ret = -1;
        INIT_LOGE("Failed to open %s", path);
    }
    return ret;
}

static int RBMiscReadUpdaterMessage(const char *path, struct RBMiscUpdateMessage *boot)
{
    int ret = 0;
    FILE *fp = NULL;
    char *realPath = GetRealPath(path);
    if (realPath != NULL) {
        fp = fopen(realPath, "rb");
        free(realPath);
        realPath = NULL;
    } else {
        fp = fopen(path, "rb");
    }
    if (fp != NULL) {
        size_t readLen = fread(boot, 1, sizeof(struct RBMiscUpdateMessage), fp);
        (void)fclose(fp);
        INIT_ERROR_CHECK(readLen > 0, ret = -1, "Failed to read misc for reboot");
    } else {
        ret = -1;
        INIT_LOGE("Failed to open %s errno %d", path, errno);
    }
    return ret;
}

int GetBootModeFromMisc(void)
{
    char miscFile[PATH_MAX] = {0};
    int ret = GetBlockDevicePath("/misc", miscFile, PATH_MAX);
    INIT_ERROR_CHECK(ret == 0, return -1, "Failed to get misc path");
    struct RBMiscUpdateMessage msg;
    ret = RBMiscReadUpdaterMessage(miscFile, &msg);
    INIT_ERROR_CHECK(ret == 0, return -1, "Failed to get misc info");
    if (memcmp(msg.command, "boot_charing", strlen("boot_charing")) == 0) {
        return GROUP_CHARING;
    }
    return 0;
}

static int CheckAndRebootToUpdater(const char *valueData, const char *cmd,
    const char *cmdExt, const char *boot)
{
    char miscFile[PATH_MAX] = {0};
    int ret = GetBlockDevicePath("/misc", miscFile, PATH_MAX);
    INIT_ERROR_CHECK(ret == 0, return -1, "Failed to get misc path for %s.", valueData);

    // "updater" or "updater:"
    struct RBMiscUpdateMessage msg;
    ret = RBMiscReadUpdaterMessage(miscFile, &msg);
    INIT_ERROR_CHECK(ret == 0, return -1, "Failed to get misc info for %s.", cmd);

    if (boot != NULL) {
        ret = snprintf_s(msg.command, MAX_COMMAND_SIZE, MAX_COMMAND_SIZE - 1, "%s", boot);
        INIT_ERROR_CHECK(ret > 0, return -1, "Failed to format cmd for %s.", cmd);
        msg.command[MAX_COMMAND_SIZE - 1] = 0;
    } else {
        ret = memset_s(msg.command, MAX_COMMAND_SIZE, 0, MAX_COMMAND_SIZE);
        INIT_ERROR_CHECK(ret == 0, return -1, "Failed to format cmd for %s.", cmd);
    }

    if ((cmdExt != NULL) && (valueData != NULL) && (strncmp(valueData, cmdExt, strlen(cmdExt)) == 0)) {
        const char *p = valueData + strlen(cmdExt);
        ret = snprintf_s(msg.update, MAX_UPDATE_SIZE, MAX_UPDATE_SIZE - 1, "%s", p);
        INIT_ERROR_CHECK(ret > 0, return -1, "Failed to format param for %s.", cmd);
        msg.update[MAX_UPDATE_SIZE - 1] = 0;
    } else {
        ret = memset_s(msg.update, MAX_UPDATE_SIZE, 0, MAX_UPDATE_SIZE);
        INIT_ERROR_CHECK(ret == 0, return -1, "Failed to format update for %s.", cmd);
    }

    if (RBMiscWriteUpdaterMessage(miscFile, &msg) == 0) {
        return 0;
    }
    return -1;
}

static int DoRebootCmd(const char *cmd, const char *opt)
{
    // by job to stop service and unmount
    DoJobNow("reboot");
    int ret = CheckAndRebootToUpdater(NULL, "reboot", NULL, NULL);
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        return reboot(RB_AUTOBOOT);
#endif
    }
    return 0;
}

static int DoShutdownCmd(const char *cmd, const char *opt)
{
    // by job to stop service and unmount
    DoJobNow("reboot");
    int ret = CheckAndRebootToUpdater(NULL, "reboot", NULL, NULL);
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        return reboot(RB_POWER_OFF);
#endif
    }
    return 0;
}

static int DoUpdaterCmd(const char *cmd, const char *opt)
{
    // by job to stop service and unmount
    DoJobNow("reboot");
    int ret = CheckAndRebootToUpdater(opt, "updater", "updater:", "boot_updater");
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        return reboot(RB_AUTOBOOT);
#endif
    }
    return 0;
}

static int DoFlashdCmd(const char *cmd, const char *opt)
{
    // by job to stop service and unmount
    DoJobNow("reboot");
    int ret = CheckAndRebootToUpdater(opt, "flash", "flash:", "boot_flash");
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        return reboot(RB_AUTOBOOT);
#endif
    }
    return 0;
}

#ifdef PRODUCT_RK
static int DoLoaderCmd(const char *cmd, const char *opt)
{
    syscall(__NR_reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_CMD_RESTART2, "loader");
    return 0;
}
#endif

static int DoSuspendCmd(const char *cmd, const char *opt)
{
    // by job to stop service and unmount
    DoJobNow("suspend");
    int ret = CheckAndRebootToUpdater(NULL, "reboot", NULL, NULL);
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        INIT_LOGE("DoSuspendCmd %s RB_SW_SUSPEND.", cmd);
        return reboot(RB_AUTOBOOT);
#endif
    }
    return 0;
}

#ifdef INIT_TEST
static int DoCharingCmd()
{
    // by job to stop service and unmount
    DoJobNow("reboot");
    int ret = CheckAndRebootToUpdater(NULL, "charing", "charing:", "boot_charing");
    if (ret == 0) {
#ifndef STARTUP_INIT_TEST
        return reboot(RB_AUTOBOOT);
#endif
    }
    return 0;
}
#endif

struct {
    char *cmdName;
    int (*doCmd)(const char *cmd, const char *opt);
} g_rebootCmd[] = {
    { "reboot", DoRebootCmd },
    { "shutdown", DoShutdownCmd },
    { "bootloader", DoShutdownCmd },
    { "updater", DoUpdaterCmd },
    { "flashd", DoFlashdCmd },
#ifdef PRODUCT_RK
    { "loader", DoLoaderCmd },
#endif
    { "suspend", DoSuspendCmd },
#ifdef INIT_TEST
    { "charing", DoCharingCmd }
#endif
};

void ExecReboot(const char *value)
{
    INIT_ERROR_CHECK(value != NULL && strlen(value) <= MAX_VALUE_LENGTH, return, "Invalid arg");
    char *cmd = NULL;
    if (strcmp(value, "reboot") == 0) {
        cmd = "reboot";
    } else if (strncmp(value, "reboot,", strlen("reboot,")) == 0) {
        cmd = (char *)(value + strlen("reboot,"));
    } else {
        INIT_LOGE("Invalid rebot cmd %s.", value);
        return;
    }

    INIT_LOGI("ExecReboot %s param %s.", cmd, value);
    for (int i = 0; i < (int)ARRAY_LENGTH(g_rebootCmd); i++) {
        if (strncmp(cmd, g_rebootCmd[i].cmdName, strlen(g_rebootCmd[i].cmdName)) == 0) {
            int ret = g_rebootCmd[i].doCmd(cmd, cmd);
            INIT_LOGI("Reboot %s %s errno %d .", cmd, (ret == 0) ? "success" : "fail", errno);
            return;
        }
    }
    INIT_LOGE("Invalid reboot cmd %s.", value);
    return;
}
