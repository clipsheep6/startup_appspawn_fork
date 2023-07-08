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
#define CAP_NUM 2


// static void SetCapability(unsigned int capsCnt, const unsigned int *caps)
// {
//     struct __user_cap_header_struct capHeader;
//     capHeader.version = _LINUX_CAPABILITY_VERSION_3;
//     capHeader.pid = 0;

//     struct __user_cap_data_struct capData[CAP_NUM];
//     for (unsigned int i = 0; i < capsCnt; ++i) {
//         capData[CAP_TO_INDEX(caps[i])].effective |= CAP_TO_MASK(caps[i]);
//         capData[CAP_TO_INDEX(caps[i])].permitted |= CAP_TO_MASK(caps[i]);
//         capData[CAP_TO_INDEX(caps[i])].inheritable |= CAP_TO_MASK(caps[i]);
//     }

//     if (capset(&capHeader, capData) != 0) {
//         APPSPAWN_LOGE("[nwebspawn] capset failed, err: %d.", errno);
//     }
//     for (unsigned int i = 0; i < capsCnt; ++i) {
//         if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, caps[i], 0, 0) != 0) {
//             APPSPAWN_LOGE("[nwebspawn] SetAmbientCapability failed, err: %d.", errno);
//         }
//     }
// }

pid_t NwebSpawnLanch(){
    pid_t ret = fork();
    if (ret == 0) {
        sleep(10);
        setcon("u:r:nwebspawn:s0");
        // unsigned int *caps = (unsigned int *)calloc(1, sizeof(unsigned int) * 37);
        // caps[0] = (unsigned int)0;
        // for(int i = 2; i < 38; ++i) {
        //     caps[i-1] = (unsigned int)i;
        // }
        // SetCapability(37, caps);
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
        setuid(NWEB_UID);
        setgid(NWEB_GID);
        APPSPAWN_LOGI("nwebspawn fork success");
    }
    return ret;
}