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

#include "json_utils.h"

#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "appspawn_utils.h"
#include "config_policy_utils.h"
#include "securec.h"

static char *ReadFile(const char *fileName)
{
    char *buffer = NULL;
    FILE *fd = NULL;
    do {
        struct stat fileStat;
        if (stat(fileName, &fileStat) != 0 ||
            fileStat.st_size <= 0 || fileStat.st_size > MAX_JSON_FILE_LEN) {
            return NULL;
        }
        fd = fopen(fileName, "r");
        APPSPAWN_CHECK(fd != NULL, break, "Failed to open file  %{public}s", fileName);

        buffer = (char*)malloc((size_t)(fileStat.st_size + 1));
        APPSPAWN_CHECK(buffer != NULL, break, "Failed to alloc mem %{public}s", fileName);

        int ret = fread(buffer, fileStat.st_size, 1, fd);
        APPSPAWN_CHECK(ret == 1, break, "Failed to read %{public}s to buffer", fileName);
        buffer[fileStat.st_size] = '\0';
        (void)fclose(fd);
        return buffer;
    } while (0);

    if (fd != NULL) {
        (void)fclose(fd);
        fd = NULL;
    }
    if (buffer != NULL) {
        free(buffer);
    }
    return NULL;
}

cJSON *GetJsonObjFromFile(const char *jsonPath)
{
    APPSPAWN_CHECK_ONLY_EXPER(jsonPath != NULL && *jsonPath != '\0', NULL);
    char *buffer = ReadFile(jsonPath);
    APPSPAWN_CHECK_ONLY_EXPER(buffer != NULL, NULL);
    return cJSON_Parse(buffer);
}

int ParseSandboxConfig(const char *basePath, const char *fileName, ParseConfig parseConfig, AppSpawnSandboxCfg *context)
{
    // load sandbox config
    char path[PATH_MAX] = {};
    CfgFiles *files = GetCfgFiles(basePath);
    if (files == NULL) {
        return APPSPAWN_SANDBOX_NONE;
    }
    int ret = 0;
    for (int i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        if (files->paths[i] == NULL) {
            continue;
        }
        int len = snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s%s", files->paths[i], fileName);
        APPSPAWN_CHECK(len > 0 && (size_t)len < sizeof(path), ret = APPSPAWN_SANDBOX_INVALID;
            continue, "Failed to format sandbox config file name %{public}s %{public}s", files->paths[i], fileName);

        APPSPAWN_LOGI("LoadAppSandboxConfig %{public}s", path);
        cJSON *root = GetJsonObjFromFile(path);
        APPSPAWN_CHECK(root != NULL, ret = APPSPAWN_SANDBOX_INVALID;
            continue, "Failed to load app data sandbox config %{public}s", path);
        int rc = parseConfig(root, context);
        if (rc != 0) {
            ret = rc;
        }
        cJSON_Delete(root);
    }
    FreeCfgFiles(files);
    return ret;
}
