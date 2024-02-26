/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "appspawn.h"
#include "appspawn_msg.h"
#include "appspawn_utils.h"
#include "securec.h"
#include "thread_manager.h"
#include "nlohmann/json.hpp"
#include "sandbox_utils.h"
#include "command_lexer.h"

#include "app_spawn_stub.h"

#define MAX_THREAD 10
#define MAX_SEND 200

typedef struct ThreadContext_ {
} ThreadContext;

namespace OHOS {
namespace AppSpawnModuleTest {
static const std::string g_defaultAppInfo = "{ \
        \"msg-type\": 0, \
        \"msg-flags\": [1, 2 ], \
        \"process-name\" : \"com.ohos.dlpmanager\", \
        \"dac-info\" : { \
                \"uid\" : 1001, \
                \"gid\" : 1001,\
                \"gid-table\" : [1001],\
                \"user-name\" : \"\" \
        },\
        \"access-token\" : {\
                \"accessTokenId\" : 22,\
                \"accessTokenIdEx\" : 100\
        },\
        \"permission\" : [\
                \"ohos.permission.READ_IMAGEVIDEO\",\
                \"ohos.permission.FILE_CROSS_APP\",\
                \"ohos.permission.ACTIVATE_THEME_PACKAGE\"\
        ],\
        \"internet-permission\" : {\
                \"set-allow-internet\" : 0,\
                \"allow-internet\" : 0\
        },\
        \"bundle-info\" : {\
                \"bundle-index\" : 0,\
                \"bundle-name\" : \"com.ohos.dlpmanager\" \
        },\
        \"owner-id\" : \"\",\
        \"render-cmd\" : \"\",\
        \"domain-info\" : {\
                \"hap-flags\" : 0,\
                \"apl\" : \"system_core\"\
        },\
        \"ext-info\" : [\
                {\
                        \"name\" : \"hiplist\",\
                        \"value\" : \"\"\
                }\
        ]\
    }";
class AppSpawnTestCommander : public ThreadContext {
public:
    AppSpawnTestCommander()
    {
        exit_ = 0;
        appSpawn_ = 1;
        coldStart_ = 0;
        maxClient = 0;
    }
    ~AppSpawnTestCommander() {}

    int ProcessArgs(int argc, char *const argv[]);
    int Run();

private:
    AppSpawnReqHandle CreateMsg();
    int StartSendMsg();
    int SendMsg();

    int BuildMsgFromJson (const nlohmann::json &appInfoConfig, AppSpawnReqHandle reqHandle, const char *processName);
    int GetBundleInfoFromJson(const nlohmann::json &appInfoConfig, AppBundleInfo &info);
    int GetDacInfoFromJson(const nlohmann::json &appInfoConfig, AppDacInfo &info);
    int GetInternetPermissionInfoFromJson(const nlohmann::json &appInfoConfig, AppInternetPermissionInfo &info);
    int GetAccessTokenFromJson(const nlohmann::json &appInfoConfig, AppSpawnMsgAccessToken &info);
    int GetOwnerIdFromJson(const nlohmann::json &appInfoConfig, AppOwnerId &info);
    int GetRenderCmdFromJson(const nlohmann::json &appInfoConfig, AppRenderCmd &info);
    int GetDomainInfoFromJson(const nlohmann::json &appInfoConfig, AppDomainInfo &info);

    static AppSpawnTestCommander *ConvertTo(const ThreadContext *context)
    {
        return const_cast<AppSpawnTestCommander *>(reinterpret_cast<const AppSpawnTestCommander *>(context));
    }
    static void TaskExecutorProc(ThreadTaskHandle handle, const ThreadContext *context);
    static void SendTaskFinish(ThreadTaskHandle handle, const ThreadContext *context);
    static void InputThread(ThreadTaskHandle handle, const ThreadContext *context);

    uint32_t exit_ : 1;
    uint32_t appSpawn_ : 1;
    uint32_t coldStart_ : 1;
    uint32_t maxClient { 1 };
    std::string testFileName_ {};
    uint32_t threadCount_  {0};
    AppSpawnClientHandle clientHandle_{nullptr};
    ThreadMgr threadMgr_{nullptr};
    ThreadTaskHandle inputHandle_{0};
};

int AppSpawnTestCommander::ProcessArgs(int argc, char *const argv[])
{
    for (int32_t i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) {  // test file
            i++;
            testFileName_ = argv[i];
        } else if (strcmp(argv[i], "--thread") == 0 && ((i + 1) < argc)) {  // use thread
            i++;
            threadCount_ = atoi(argv[i]);
            if (threadCount_ > MAX_THREAD) {
                threadCount_ = MAX_THREAD;
            }
        } else if (strcmp(argv[i], "--nwebspawn") == 0) {
            appSpawn_ = 0;
        }
    }
    return 0;
}

int AppSpawnTestCommander::GetBundleInfoFromJson(const nlohmann::json &appInfoConfig, AppBundleInfo &info)
{
    if (appInfoConfig.find("bundle-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("bundle-info");
    info.bundleIndex = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "bundle-index");
    std::string bundleName = AppSpawn::SandboxUtils::GetStringFromJson(config, "bundle-name");
    if (!bundleName.empty()) {
        return strcpy_s(info.bundleName, sizeof(info.bundleName), bundleName.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::GetDacInfoFromJson(const nlohmann::json &appInfoConfig, AppDacInfo &info)
{
    if (appInfoConfig.find("dac-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("dac-info");
    info.uid = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "uid");
    info.gid = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "gid");
    if (config.find("gid-table") != config.end()) {
        const auto vec = config.at("gid-table").get<std::vector<uint32_t>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            info.gidTable[info.gidCount++] = vec[j];
            if (info.gidCount >= APP_MAX_GIDS) {
                break;
            }
        }
    }
    std::string userName = AppSpawn::SandboxUtils::GetStringFromJson(config, "user-name");
    if (!userName.empty()) {
        return strcpy_s(info.userName, sizeof(info.userName), userName.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::GetInternetPermissionInfoFromJson(
    const nlohmann::json &appInfoConfig, AppInternetPermissionInfo &info)
{
    if (appInfoConfig.find("internet-permission") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("internet-permission");
    info.setAllowInternet = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "set-allow-internet");
    info.allowInternet = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "allow-internet");
    return 0;
}

int AppSpawnTestCommander::GetAccessTokenFromJson(const nlohmann::json &appInfoConfig, AppSpawnMsgAccessToken &info)
{
    if (appInfoConfig.find("access-token") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("access-token");
    info.accessTokenId = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "accessTokenId");
    info.accessTokenIdEx = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "accessTokenIdEx");
    return 0;
}

int AppSpawnTestCommander::GetOwnerIdFromJson(const nlohmann::json &appInfoConfig, AppOwnerId &info)
{
    std::string ownerId = AppSpawn::SandboxUtils::GetStringFromJson(appInfoConfig, "owner-id");
    if (!ownerId.empty()) {
        return strcpy_s(info.ownerId, sizeof(info.ownerId), ownerId.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::GetRenderCmdFromJson(const nlohmann::json &appInfoConfig, AppRenderCmd &info)
{
    std::string renderCmd = AppSpawn::SandboxUtils::GetStringFromJson(appInfoConfig, "render-cmd");
    if (!renderCmd.empty()) {
        return strcpy_s(info.renderCmd, sizeof(info.renderCmd), renderCmd.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::GetDomainInfoFromJson(const nlohmann::json &appInfoConfig, AppDomainInfo &info)
{
    if (appInfoConfig.find("domain-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("domain-info");
    info.hapFlags = AppSpawn::SandboxUtils::GetIntValueFromJson(config, "hap-flags");
    std::string apl = AppSpawn::SandboxUtils::GetStringFromJson(config, "apl");
    if (!apl.empty()) {
        return strcpy_s(info.apl, sizeof(info.apl), apl.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::BuildMsgFromJson (
    const nlohmann::json &appInfoConfig, AppSpawnReqHandle reqHandle, const char *processName)
{
    AppBundleInfo info = {};
    int ret = GetBundleInfoFromJson(appInfoConfig, info);
    ret = AppSpawnReqSetBundleInfo(clientHandle_, reqHandle, &info);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add bundle info req %{public}s", processName);

    AppDacInfo dacInfo = {};
    ret = GetDacInfoFromJson(appInfoConfig, dacInfo);
    ret = AppSpawnReqSetAppDacInfo(clientHandle_, reqHandle, &dacInfo);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add dac %{public}s", processName);

    AppSpawnMsgAccessToken token = {};
    ret = GetAccessTokenFromJson(appInfoConfig, token);
    ret = AppSpawnReqSetAppAccessToken(clientHandle_, reqHandle, &token);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add access token %{public}s", processName);

    std::vector<const char *> permissions = {};
    if (appInfoConfig.find("permission") != appInfoConfig.end()) {
        const auto vec = appInfoConfig.at("permission").get<std::vector<std::string>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            APPSPAWN_LOGV("permission %{public}s ", vec[j].c_str());
            permissions.push_back(vec[j].c_str());
        }
        ret = AppSpawnReqSetPermission(clientHandle_, reqHandle, permissions.data(), permissions.size());
        APPSPAWN_CHECK(ret == 0, return ret, "Failed to permission %{public}s", processName);
    }
    AppInternetPermissionInfo internetInfo = {};
    ret = GetInternetPermissionInfoFromJson(appInfoConfig, internetInfo);
    ret = AppSpawnReqSetAppInternetPermissionInfo(clientHandle_, reqHandle, &internetInfo);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to internet info %{public}s", processName);

    AppOwnerId ownerId = {};
    ret = GetOwnerIdFromJson(appInfoConfig, ownerId);
    ret = AppSpawnReqSetAppOwnerId(clientHandle_, reqHandle, &ownerId);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to ownerid %{public}s", processName);

    AppRenderCmd renderCmd = {};
    ret = GetRenderCmdFromJson(appInfoConfig, renderCmd);
    ret = AppSpawnReqSetAppRenderCmd(clientHandle_, reqHandle, &renderCmd);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to render cmd %{public}s", processName);

    AppDomainInfo domainInfo = {};
    ret = GetDomainInfoFromJson(appInfoConfig, domainInfo);
    ret = AppSpawnReqSetAppDomainInfo(clientHandle_, reqHandle, &domainInfo);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to domain info %{public}s", processName);
    return 0;
}

AppSpawnReqHandle AppSpawnTestCommander::CreateMsg()
{
    const char *name = appSpawn_ ? APPSPAWN_SERVER_NAME : NWEBSPAWN_SERVER_NAME;
    if (clientHandle_) {
        int ret = AppSpawnClientInit(name, &clientHandle_);
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to create client %{public}s", name);
    }
    nlohmann::json appInfoConfig;
    if (!testFileName_.empty()) {
        if (!AppSpawn::SandboxUtils::GetJsonObjFromJson(appInfoConfig, testFileName_)) {
            printf("Failed to load file %s, so use default info \n", testFileName_.c_str());
        }
    }
    if (appInfoConfig == nullptr) {
        appInfoConfig = nlohmann::json::parse(g_defaultAppInfo.c_str(), nullptr, false);
    }
    if (appInfoConfig == nullptr) {
        printf("Invalid app info \n");
        return INVALID_REQ_HANDLE;
    }
    std::string processName = AppSpawn::SandboxUtils::GetStringFromJson(appInfoConfig, "process-name");
    if (processName.empty()) {
        processName = "com.ohos.dlpmanager";
    }
    uint32_t msgType = AppSpawn::SandboxUtils::GetIntValueFromJson(appInfoConfig, "msg-type", MSG_APP_SPAWN);
    AppSpawnReqHandle reqHandle = 0;
    int ret = AppSpawnReqCreate(clientHandle_, msgType, processName.c_str(), &reqHandle);
    APPSPAWN_CHECK(ret == 0, return INVALID_REQ_HANDLE, "Failed to create req %{public}s", processName.c_str());

    if (appInfoConfig.find("msg-flags") != appInfoConfig.end()) {
        const auto vec = appInfoConfig.at("msg-flags").get<std::vector<uint32_t>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            (void)AppSpawnReqSetAppFlag(clientHandle_, reqHandle, vec[j]);
        }
    }
    ret = BuildMsgFromJson(appInfoConfig, reqHandle, processName.c_str());
    APPSPAWN_CHECK(ret == 0, AppSpawnReqDestroy(clientHandle_, reqHandle);
        return INVALID_REQ_HANDLE, "Failed to build req %{public}s", processName.c_str());
    return reqHandle;
}

int AppSpawnTestCommander::SendMsg()
{
    printf("Send msg to server %s \n", appSpawn_ ? APPSPAWN_SERVER_NAME : NWEBSPAWN_SERVER_NAME);
    AppSpawnReqHandle reqHandle = CreateMsg();
    AppSpawnResult result = {};
    int ret = AppSpawnClientSendMsg(clientHandle_, reqHandle, &result);
    printf("Process ret %d result: %d pid: %d \n", ret, result.result, result.pid);
    return 0;
}

int AppSpawnTestCommander::StartSendMsg()
{
    int ret = 0;
    printf("Start send msg thread count %d file name %s \n", threadCount_, testFileName_.c_str());
    if (threadCount_ == 0) {
        SendMsg();
    } else {
        ThreadTaskHandle taskHandle = 0;
        ret = ThreadMgrAddTask(threadMgr_, &taskHandle);
        APPSPAWN_CHECK(ret == 0, return 0, "Failed to add task ");
        for (uint32_t index = 0; index < threadCount_; index++) {
            ThreadMgrAddExecutor(threadMgr_, taskHandle, TaskExecutorProc, reinterpret_cast<ThreadContext *>(this));
        }
        TaskSyncExecute(threadMgr_, taskHandle);
    }
    return 0;
}

void AppSpawnTestCommander::TaskExecutorProc(ThreadTaskHandle handle, const ThreadContext *context)
{
    AppSpawnTestCommander *testCmder = AppSpawnTestCommander::ConvertTo(context);
    testCmder->SendMsg();
}

void AppSpawnTestCommander::SendTaskFinish(ThreadTaskHandle handle, const ThreadContext *context)
{
    APPSPAWN_LOGV("SendTaskFinish %{public}u \n", handle);
}

static const char *GetInputFileName(const char *buffer)
{
    const char *tmp = buffer;
    while (*tmp != '\0') {
        if (isspace(*tmp)) {
            tmp++;
        }
        return tmp;
    }
    return nullptr;
}

void AppSpawnTestCommander::InputThread(ThreadTaskHandle handle, const ThreadContext *context)
{
    AppSpawnTestCommander *testCmder = AppSpawnTestCommander::ConvertTo(context);
    char buf[256] = {0}; // 256 test buffer max len
    fd_set fds;
    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval timeout = {0, 200 * 1000};
        int ret = select(STDIN_FILENO + 1, &fds, 0, 0, &timeout);
        if (ret <= 0) {
            if (testCmder->exit_) {
                break;
            }
            continue;
        }
        int readLen = read(STDIN_FILENO, buf, sizeof(buf) - 1);
        if (readLen <= 1) {
            continue;
        }
        buf[readLen - 1] = 0;
        printf("Recv command: '%s' \n", buf);
        if (strncmp("quit", buf, strlen("quit")) == 0) {
            testCmder->exit_ = 1;
            break;
        }
         if (strncmp("send", buf, 4) == 0) { // 4 strlen("send")
            const char *str = GetInputFileName(buf + 4); // 4 strlen("send")
            if (str != nullptr) {
                testCmder->testFileName_ = str;
            } else {
                testCmder->testFileName_ = "";
            }
            testCmder->StartSendMsg();
        }
    }
}

int AppSpawnTestCommander::Run()
{
    const char *name = appSpawn_ ? APPSPAWN_SERVER_NAME : NWEBSPAWN_SERVER_NAME;
    int ret = AppSpawnClientInit(name, &clientHandle_);
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create client %{public}s", name);

    ret = CreateThreadMgr(5, &threadMgr_);  // 5 max thread
    APPSPAWN_CHECK(ret == 0, return -1, "Failed to create thread manager");

    ret = ThreadMgrAddTask(threadMgr_, &inputHandle_);
    APPSPAWN_CHECK(ret == 0, return 0, "Failed to add task for thread ");
    ThreadMgrAddExecutor(threadMgr_, inputHandle_, InputThread, this);
    TaskExecute(threadMgr_, inputHandle_, SendTaskFinish, this);

    StartSendMsg();

    APPSPAWN_LOGV("Finish send msg \n");
    while (!exit_) {
        pause();
    }
    ThreadMgrCancelTask(threadMgr_, inputHandle_);
    DestroyThreadMgr(threadMgr_);
    threadMgr_ = nullptr;
    inputHandle_ = 0;
    AppSpawnClientDestroy(clientHandle_);
    clientHandle_ = nullptr;
    return 0;
}
}  // namespace AppSpawnModuleTest
}  // namespace OHOS

int main(int argc, char *const argv[])
{
    if (argc <= 0) {
        return 0;
    }
    SetDumpFlags(true);
    OHOS::AppSpawnModuleTest::AppSpawnTestCommander commander;
    commander.ProcessArgs(argc, argv);
    commander.Run();
    return 0;
}