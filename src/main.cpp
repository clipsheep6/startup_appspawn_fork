/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
    if (argc > 0) {
        // calculate child process long name size
        uintptr_t start = reinterpret_cast<uintptr_t>(argv[0]);
        uintptr_t end = reinterpret_cast<uintptr_t>(strchr(argv[argc - 1], 0));
        uintptr_t argvSize = end - start;

#ifdef NWEB_SPAWN
        OHOS::AppSpawn::AppSpawnServer appspawnServer("/dev/unix/socket/NWebSpawn");
#else
        OHOS::AppSpawn::AppSpawnServer appspawnServer("AppSpawn");
#endif
        appspawnServer.ServerMain(argv[0], argvSize);
    }

    return 0;
}
