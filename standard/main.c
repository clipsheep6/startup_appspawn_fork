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

#include "appspawn_adapter.h"
#include "appspawn_msg.h"
#include "appspawn_server.h"

int main(int argc, char *const argv[])
{
    if (argc <= 0) {
        return 0;
    }
    // calculate child process long name size
    uintptr_t start = (uintptr_t)argv[0];
    uintptr_t end = (uintptr_t)strchr(argv[argc - 1], 0);
    APPSPAWN_CHECK(end != NULL, return -1, "strchr argv Failed");
    int64_t argvSize = end - start;
    int cold = (argc > PARAM_INDEX) && (strcmp(argv[START_INDEX], "cold-start") == 0);

    AppSpawnContent *content = AppSpawnCreateContent(APPSPAWN_SOCKET_NAME, argv[0], argvSize, cold);
    APPSPAWN_CHECK(content != NULL, return -1, "Invalid content for appspawn");
    APPSPAWN_CHECK(content->initAppSpawn != NULL, return -1, "Invalid content for appspawn");

    // set common operation
    content->loadExtendLib = LoadExtendLib;
    content->runChildProcessor = RunChildProcessor;

    if (cold) {
        content->initAppSpawn(content);
        AppSpawnColdRun(content, argc, argv);
    } else {
        APPSPAWN_CHECK(content->runAppSpawn != NULL, return -1, "Invalid content for appspawn");
        content->initAppSpawn(content);
        // run, to start loop and wait message
        content->runAppSpawn(content);
    }
    return 0;
}
