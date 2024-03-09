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

#ifndef SANDBOX_UTILS_H
#define SANDBOX_UTILS_H

#include <stdbool.h>

#include "appspawn_utils.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct TagAppSpawnSandbox AppSpawnSandbox;
typedef int (*ParseConfig)(const cJSON *root, AppSpawnSandbox *context);
int ParseSandboxConfig(const char *basePath, const char *fileName, ParseConfig parseConfig, AppSpawnSandbox *context);
uint32_t GetUint32ArrayFromJson(const cJSON *json, const char *name, uint32_t dataArray[], uint32_t maxCount);
cJSON *GetJsonObjFromFile(const char *jsonPath);

__attribute__((always_inline)) inline char *GetStringFromJsonObj(const cJSON *json, const char *key)
{
    APPSPAWN_CHECK(json != NULL, return 0, "Invalid json");
    APPSPAWN_CHECK(key != NULL, return 0, "Invalid key");
    APPSPAWN_CHECK(cJSON_IsObject(json), return NULL, "json is not object %{public}s %s", key, cJSON_Print(json));
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(json, key);
    APPSPAWN_CHECK_ONLY_EXPER(obj != NULL, return NULL);
    APPSPAWN_CHECK(cJSON_IsString(obj), return NULL, "json is not string %{public}s %s", key, cJSON_Print(obj));
    return cJSON_GetStringValue(obj);
}

__attribute__((always_inline)) inline bool GetBoolValueFromJsonObj(const cJSON *json, const char *key, bool def)
{
    char *value = GetStringFromJsonObj(json, key);
    APPSPAWN_CHECK_ONLY_EXPER(value != NULL, return def);

    if (strcmp(value, "true") == 0 || strcmp(value, "ON") == 0 || strcmp(value, "True") == 0) {
        return true;
    }
    return false;
}

__attribute__((always_inline)) inline uint32_t GetIntValueFromJsonObj(const cJSON *json, const char *key, uint32_t def)
{
    APPSPAWN_CHECK(json != NULL, return def, "Invalid json");
    APPSPAWN_CHECK(cJSON_IsObject(json), return def, "json is not object.");
    return cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json, key));
}

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // SANDBOX_UTILS_H
