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
#include <cstring>

#include "appspawn_server.h"
#include "hilog/log.h"

int main(int argc, char *const argv[])
{
    if (argc <= 1) {
        printf("appspawntools xxxx \n");
        return 0;
    }

    // calculate child process long name size
    uintptr_t start = reinterpret_cast<uintptr_t>(argv[0]);
    uintptr_t end = reinterpret_cast<uintptr_t>(strchr(argv[argc - 1], 0));
    if (end == nullptr) {
        printf("end result is error!!");
        return 0;
    }
    uintptr_t argvSize = end - start;

    std::string appName(argv[1]);
    std::string uid ((argc > 2) ? argv[2] : ""); // 2 uid index
    auto appspawnServer = std::make_shared<OHOS::AppSpawn::AppSpawnServer>("AppSpawn");
    if (appspawnServer != nullptr) {
        int ret = appspawnServer->AppColdStart(argv[0], argvSize, appName, uid);
        if (ret != 0) {
            printf("Cold start %s fail \n", appName.c_str());
        }
    }
    return 0;
}
