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
#include "app_spawn_stub.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/capability.h>

#include "beget_ext.h"
#include "securec.h"

HapContext_stub::HapContext_stub() {}
HapContext_stub::~HapContext_stub() {}
static int g_testHapDomainSetcontext = 0;
int HapContext_stub::HapDomainSetcontext(const std::string &apl, const std::string &packageName)
{
    if (g_testHapDomainSetcontext == 0) {
        return 0;
    } else if (g_testHapDomainSetcontext == 1) {
        sleep(2);
    }
    return g_testHapDomainSetcontext;
}
#ifdef __cplusplus
    extern "C" {
#endif
void SetHapDomainSetcontextResult(int result)
{
    g_testHapDomainSetcontext = result;
}

void *dlopen_stub( const char * pathname, int mode)
{
    static size_t index = 0;
    return &index;
}

bool InitEnvironmentParam_stub(const char *name)
{
    return true;
}

void *dlsym_stub(void *handle, const char *symbol)
{
    if (strcmp(symbol, "InitEnvironmentParam") == 0) {
        return (void *)InitEnvironmentParam_stub;
    }
    return nullptr;
}

int dlclose_stub(void *handle)
{
    return 0;
}

pid_t waitpid_stub(pid_t *pid, int *status, int opt)
{
    static int count = 0;
    static int statusCount = 0;
    *status = (statusCount % 2 == 0) ? 0x0e007f : 0;
    count++;
    printf("waitpid_stub %d\n", GetTestPid());
    if ((count % 2) == 1) {
        statusCount++;
        return GetTestPid();
    }
    return -1;
}

void DisallowInternet(void)
{
}

int bind_stub(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return 0;
}

int listen_stub(int fd, int backlog)
{
    return 0;
}

int lchown_stub( const char *pathname, uid_t owner, gid_t group )
{
    return 0;
}

int getsockopt_stub(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (optval == NULL) {
        return -1;
    }
    if (optname == SO_PEERCRED) {
        struct ucred *cred = (struct ucred *)optval;
        cred->uid = 0;
    }
    return 0;
}

int setgroups_stub(size_t size,const gid_t * list)
{
    return 0;
}

int setresuid_stub(uid_t ruid, uid_t euid, uid_t suid)
{
    return 0;
}

int setresgid_stub(gid_t rgid, gid_t egid, gid_t sgid)
{
    return 0;
}

int capset_stub(cap_user_header_t hdrp, const cap_user_data_t datap)
{
    return 0;
}

struct ForkArgs {
   int (*childFunc)(void *arg);
   void *args;
};

static void *ThreadFunc(void *arg)
{
    struct ForkArgs *forkArg = (struct ForkArgs *)arg;
    forkArg->childFunc(forkArg->args);
    free(forkArg);
    return nullptr;
}

static pid_t g_pid = 1000;
pid_t TestFork(int (*childFunc)(void *arg), void *args)
{
    static pthread_t thread = 0;
    struct ForkArgs *forkArg = (ForkArgs *)malloc(sizeof(struct ForkArgs));
    if (forkArg == nullptr) {
        return -1;
    }
    printf("ThreadFunc TestFork args %p forkArg %p\n", args, forkArg);
    forkArg->childFunc = childFunc;
    forkArg->args = args;
    int ret = pthread_create(&thread, nullptr, ThreadFunc, forkArg);
    if (ret != 0) {
        printf("Failed to create thread %d \n", errno);
        return -1;
    }
    g_pid++;
    return g_pid;
}

pid_t GetTestPid(void)
{
    return g_pid;
}

int clone_stub(int (*fn)(void *), void *stack, int flags, void *arg, ...
    /* pid_t *parent_tid, void *tls, pid_t *child_tid */ )
{
    static int testResult = 0;
    testResult++;
    return testResult == 1 ? TestFork(fn, arg) : -1;
}

void StartupLog_stub(InitLogLevel logLevel, uint32_t domain, const char *tag, const char *fmt, ...)
{
    char tmpFmt[1024] = {0};
    va_list vargs;
    va_start(vargs, fmt);
    if (vsnprintf_s(tmpFmt, sizeof(tmpFmt), sizeof(tmpFmt) - 1, fmt, vargs) == -1) {
        tmpFmt[sizeof(tmpFmt) - 2] = '\n'; // 2 add \n to tail
        tmpFmt[sizeof(tmpFmt) - 1] = '\0';
    }
    va_end(vargs);

    struct timespec curr;
    (void)clock_gettime(CLOCK_REALTIME, &curr);
    struct tm t;
    char dateTime[80] = {"00-00-00 00:00:00"}; // 80 data time
    if (localtime_r(&curr.tv_sec, &t) != NULL) {
        strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", &t);
    }
    (void)fprintf(stdout, "[%s.%ld][pid=%d %d][%s]%s \n", dateTime, curr.tv_nsec, getpid(), gettid(), tag, tmpFmt);
    (void)fflush(stdout);
}

bool SetSeccompPolicyWithName(const char *filterName)
{
    static int result = 0;
    result++;
    return (result % 3) == 0;
}

#ifdef __cplusplus
    }
#endif