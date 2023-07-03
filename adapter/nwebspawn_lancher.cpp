/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "nwebspawn_lancher.h"
#include "appspawn_server.h"

#define FULL_CAP 0xFFFFFFFF
#define NWEB_UID 3081
#define NWEB_GID 3081

pid_t NwebSpawnLanch(){
    pid_t ret = fork();
    if (ret == 0) {
        setuid(NWEB_UID);
        setgid(NWEB_GID);
        struct  __user_cap_header_struct capHeader;
        capHeader.version = _LINUX_CAPABILITY_VERSION_3;
        capHeader.pid = 0;
        struct __user_cap_data_struct capData[2] = {};
        for (int j = 0; j < 2; ++j) {
            capData[j].effective = FULL_CAP;
            capData[j].permitted = FULL_CAP;
            capData[j].inheritable = FULL_CAP;
        }
        capset(&capHeader, capData);

        for (int i = 0; i <= CAP_LAST_CAP; ++i) {
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0);
        }
        setcon("u:r:nwebspawn:s0");
        APPSPAWN_LOGI("nwebspawn fork success");
    }
    return ret;
}