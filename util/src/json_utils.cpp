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

#include <climits>
#include <fstream>
#include <sstream>
#include <vector>

#include "appspawn_utils.h"
#include "config_policy_utils.h"
#include "securec.h"

uint32_t GetUint32ArrayFromJson(const cJSON *json, const char *name, uint32_t dataArray[], uint32_t maxCount)
{
    APPSPAWN_CHECK(json != NULL, return 0, "Invalid json");
    APPSPAWN_CHECK(name != NULL, return 0, "Invalid name");
    APPSPAWN_CHECK(dataArray != NULL, return 0, "Invalid dataArray");
    APPSPAWN_CHECK(cJSON_IsObject(json), return 0, "json is not object.");
    cJSON *array = cJSON_GetObjectItemCaseSensitive(json, name);
    APPSPAWN_CHECK_ONLY_EXPER(array != NULL, return 0);
    APPSPAWN_CHECK(cJSON_IsArray(array), return 0, "json is not object.");

    uint32_t count = 0;
    uint32_t arrayLen = cJSON_GetArraySize(array);
    for (int i = 0; i < arrayLen; i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        uint32_t value = (uint32_t)cJSON_GetNumberValue(item);
        if (count < maxCount) {
            dataArray[count++] = value;
        }
    }
    return count;
}

cJSON *GetJsonObjFromFile(const char *jsonPath)
{
    std::ifstream jsonFileStream;
    jsonFileStream.open(jsonPath, std::ios::in);
    APPSPAWN_CHECK_ONLY_EXPER(jsonFileStream.is_open(), return nullptr);
    std::ostringstream buf;
    char ch;
    while (buf && jsonFileStream.get(ch)) {
        buf.put(ch);
    }
    jsonFileStream.close();
    return cJSON_Parse(buf.str().c_str());
}

int ParseSandboxConfig(const char *basePath, const char *fileName, ParseConfig parseConfig, AppSpawnSandboxCfg *context)
{
    // load sandbox config
    CfgFiles *files = GetCfgFiles(basePath);
    if (files == nullptr) {
        return APPSPAWN_SANDBOX_NONE;
    }
    int ret = 0;
    for (int i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        if (files->paths[i] == nullptr) {
            continue;
        }
        std::string path = files->paths[i];
        path += fileName;
        APPSPAWN_LOGI("LoadAppSandboxConfig %{public}s", path.c_str());

        cJSON *root = GetJsonObjFromFile(path.c_str());
        APPSPAWN_CHECK(root != nullptr, ret = APPSPAWN_SANDBOX_INVALID;
            continue, "Failed to load app data sandbox config %{public}s", path.c_str());
        int rc = parseConfig(root, context);
        if (rc != 0) {
            ret = rc;
        }
        cJSON_Delete(root);
    }
    FreeCfgFiles(files);
    return ret;
}
