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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h> 
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#define FULL_CAP 0xFFFFFFFF
#define NWEB_UID 3081
#define NWEB_GID 3081
#define CAP_NUM 2
#define BITLEN32 32

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

static void SockCreateNweb(){
    APPSPAWN_LOGI("1");
    setsockcreatecon("u:r:nwebspawn:s0");
    APPSPAWN_LOGI("2");
    int fd = socket(AF_LOCAL,SOCK_STREAM,0);
    APPSPAWN_LOGI("3");
    struct sockaddr_un *addr;
    (void)memset_s(addr, sizeof(struct sockaddr_un), 0x0, sizeof(struct sockaddr_un));
    APPSPAWN_LOGI("4");
    addr->sun_family = AF_UNIX;
    size_t addr_len = sizeof(addr->sun_path);
    strcpy(addr->sun_path, "dev/unix/socket/NWebSpawn");
    bind(fd, (struct sockaddr *)addr, sizeof(*addr));
    APPSPAWN_LOGI("5");
    lchown(addr->sun_path, 3081, 3081);
    APPSPAWN_LOGI("6");
    fchmodat(AT_FDCWD, addr->sun_path, , AT_SYMLINK_NOFOLLOW);
    APPSPAWN_LOGI("7");
    char buf[16] = {0};
    sprintf_s(buf, sizeof(buf), "%s", fd);
    setenv("OHOS_SOCKET_NWebSpawn", buf , 1);
    APPSPAWN_LOGI("8");
    setsockcreatecon(NULL);
    APPSPAWN_LOGI("9");
}

pid_t NwebSpawnLanch(){
    pid_t ret = fork();
    if (ret == 0) {
        sleep(10);
        SockCreateNweb();
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
        const uint64_t inheriTable = 0x1fffffffff;
        const uint64_t permitted = 0x1fffffffff;
        const uint64_t effective = 0x1fffffffff;
        struct __user_cap_data_struct capData[2] = {};
        for (int j = 0; j < 2; ++j) {
            capData[0].inheritable = (__u32)(inheriTable);
            capData[1].inheritable = (__u32)(inheriTable >> BITLEN32);
            capData[0].permitted = (__u32)(permitted);
            capData[1].permitted = (__u32)(permitted >> BITLEN32);
            capData[0].effective = (__u32)(effective);
            capData[1].effective = (__u32)(effective >> BITLEN32);
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