 /*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <string.h>

#include "hnp_base.h"
#include "hnp_pack.h"
#include "hnp_installer.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int HnpShowHelp(int argc, char *argv[]);

typedef int (*HNP_CMD_PROCESS_FUNC)(int argc, char *argv[]);

typedef struct NativeManagerCmdInfo {
    char *cmd;                          // 操作类型
    HNP_CMD_PROCESS_FUNC process;       // 处理函数
} NativeManagerCmdInfo;

NativeManagerCmdInfo g_nativeManagerCmd[] = {
    {"help", HnpShowHelp},
    {"pack", HnpCmdPack},
    {"install", HnpCmdInstall},
    {"uninstall", HnpCmdUnInstall}
};

int HnpShowHelp(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    HNP_LOGI("\r\nusage:hnp <command> <args> [-cfg <link cfg file>][-name <native package name>]"
        "[-v <native package version>][-f]\r\n"
        "\r\nThese are common hnp commands used in various situations:\r\n"
        "\r\npack:    packet native software package to .hnp file"
        "\r\n         hnp pack [source path] [dst path] -name [software name] -v [software version]"
        "\r\n         hnp pack [source path] [dst path] -cfg [link config file]\r\n"
        "\r\ninstall:    install native software"
        "\r\n            hnp install [user id] [hnp package dir] <-f>\r\n"
        "\r\nuninstall:    uninstall native software"
        "\r\n              hnp uninstall [user id] [software name] [software version]\r\n"
        "\r\nfor example:\r\n"
        "\r\n    hnp pack /usr1/native_sample /usr1/output -name native_sample -v 1.1\r\n"
        "    hnp pack /usr1/native_sample /usr1/output -cfg /usr1/native_sample.cfg\r\n"
        "    hnp install /usr1/hnp 1000 -f\r\n"
        "    hnp uninstall 1000 native_sample 1.1\r\n");
        
    return 0;
}

static NativeManagerCmdInfo* HnpCmdCheck(const char *cmd)
{
    int i;
    int cmdNum = sizeof(g_nativeManagerCmd) / sizeof(NativeManagerCmdInfo);

    /* 查找匹配的操作类型 */
    for (i = 0; i < cmdNum; i++) {
        if (!strcmp(cmd, g_nativeManagerCmd[i].cmd)) {
            return &g_nativeManagerCmd[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    int ret;
    NativeManagerCmdInfo *cmdInfo = NULL;

    if (argc < 2) { /* 2:参数个数 */
        /* 显示帮助信息 */
        HnpShowHelp(argc, argv);
        return -1;
    }

    HNP_LOGI("native manager process start.");

    /* 检验用户命令，获取对应的处理函数 */
    cmdInfo = HnpCmdCheck(argv[1]);
    if (cmdInfo == NULL) {
        HNP_LOGE("invalid cmd!. cmd:%s", argv[1]);
        return -1;
    }

    /* 执行命令 */
    ret = cmdInfo->process(argc, argv);

    HNP_LOGI("native manager process exit. ret=%d ", ret);
    return ret;
}

#ifdef __cplusplus
}
#endif