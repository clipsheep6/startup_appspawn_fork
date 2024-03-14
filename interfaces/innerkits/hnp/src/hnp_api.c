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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

#include "hnp_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HNP_LOG printf

/* 启动hnp进程进行操作 */
static int StartHnpProcess(char *const argv[], char *const apcEnv[])
{
    pid_t pid;
    int ret;
    int status;
    int exitVal = -1;

    /* 创建子进程 */
    pid = vfork();
    if (pid < 0) {
        HNP_LOG("[HNP API] foek unsuccess!\r\n");
        return -1;
    } else if (pid == 0) {
        HNP_LOG("[HNP API] this is fork children!\r\n");
        ret = execve("./hnp", argv, apcEnv);
        if (ret < 0) {
            HNP_LOG("[HNP API] execve unsuccess!\r\n");
            _exit(123); /* 123:退出码 */
        }
        _exit(0);
    }

    HNP_LOG("[HNP API] this is fork father! chid=%d\r\n", pid);

    /* 父进程阻塞等待子进程退出 */
    waitpid(pid, &status, 0);
    /* 获取子进程退出码 */
    if (WIFEXITED(status)) {
        exitVal = WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        exitVal = WTERMSIG(status);
    }
    HNP_LOG("[HNP API] Child process exited with exitval=%d\r\n", exitVal);

    return exitVal;
}

int NativePackHnp(const char *hnpSrcPath, const char *hnpName, const char *hnpVersion,
    const char *hnpDstPath)
{
    char *argv[256] = {0};
    char *apcEnv[128 + 2] = {0};

    HNP_LOG("[HNP API] start native package pack! srcPath=%s, hnpName=%s, hnpVer=%s, "
        "hnpDstPath=%s\r\n", hnpSrcPath, hnpName, hnpVersion, hnpDstPath);
    
    /* 生成hnp进程打包参数 */
    argv[0] = "hnp"; /* 0:第1个参数 */
    argv[1] = "pack"; /* 1:第2个参数 */
    argv[2] = (char*)hnpSrcPath; /* 2:第3个参数 */
    argv[3] = (char*)hnpDstPath; /* 3:第4个参数 */
    argv[4] = "-name"; /* 4:第5个参数 */
    argv[5] = (char*)hnpName; /* 5:第6个参数 */
    argv[6] = "-v"; /* 6:第7个参数 */
    argv[7] = (char*)hnpVersion; /* 7:第8个参数 */

    return StartHnpProcess(argv, apcEnv);
}

int NativePackHnpWithCfg(const char *hnpSrcPath, const char *hnpCfgPath, const char *hnpDstPath)
{
    char *argv[256] = {0};
    char *apcEnv[128 + 2] = {0};

    HNP_LOG("[HNP API] start native package pack! srcPath=%s, hnpCfg=%s, hnpDstPath=%s\r\n",
        hnpSrcPath, hnpCfgPath, hnpDstPath);
    
    /* 生成hnp进程打包参数 */
    argv[0] = "hnp"; /* 0:第1个参数 */
    argv[1] = "pack"; /* 1:第2个参数 */
    argv[2] = (char*)hnpSrcPath; /* 2:第3个参数 */
    argv[3] = (char*)hnpDstPath; /* 3:第4个参数 */
    argv[4] = "-cfg"; /* 4:第5个参数 */
    argv[5] = (char*)hnpCfgPath; /* 5:第6个参数 */

    return StartHnpProcess(argv, apcEnv);
}

int NativeInstallHnp(const char *userId, const char *hnpPath, Bool isForce)
{
    HNP_LOG("[HNP API] native package install! userId=%s, hnpPath=%s, IsForce=%d\r\n",
        userId, hnpPath, isForce);
    return -1;
}

int NativeUnInstallHnp(const char *userId, const char *hnpName, const char *hnpVersion)
{
    HNP_LOG("[HNP API] native package uninstall! userId=%s, hnpName=%s, hnpVersion=%s\r\n",
        userId, hnpName, hnpVersion);
    return -1;
}

#ifdef __cplusplus
}
#endif