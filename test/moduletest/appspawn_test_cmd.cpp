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
#include "command_lexer.h"
#include "json_utils.h"
#include "nlohmann/json.hpp"
#include "securec.h"
#include "thread_manager.h"

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
    \"process-name\" : \"com.example.myapplication\", \
    \"dac-info\" : { \
            \"uid\" : 20010043, \
            \"gid\" : 20010043,\
            \"gid-table\" : [],\
            \"user-name\" : \"\" \
    },\
    \"access-token\" : {\
            \"accessTokenIdEx\" : 537854093\
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
            \"bundle-name\" : \"com.example.myapplication\" \
    },\
    \"owner-id\" : \"\",\
    \"render-cmd\" : \"1234567890\",\
    \"domain-info\" : {\
            \"hap-flags\" : 0,\
            \"apl\" : \"system_core\"\
    },\
    \"ext-info\" : [\
            {\
                    \"name\" : \"hiplist\",\
                    \"value\" : \"1333333333333345\"\
            } \
    ]\
}";

class AppSpawnTestCommander : public ThreadContext {
public:
    AppSpawnTestCommander()
    {
        exit_ = 0;
        appSpawn_ = 1;
    }
    ~AppSpawnTestCommander() {}

    int ProcessArgs(int argc, char *const argv[]);
    int Run();

private:
    int ProcessInputCmd(std::string &cmd);
    int CreateOtherMsg(AppSpawnReqMsgHandle &reqHandle, pid_t pid);
    int CreateMsg(AppSpawnReqMsgHandle &reqHandle);
    int StartSendMsg();
    int SendMsg();

    int AddExtTlv(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle);
    int BuildMsgFromJson(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle);
    int AddBundleInfoFromJson(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle);
    int GetDacInfoFromJson(const nlohmann::json &appInfoConfig, AppDacInfo &info);
    int GetInternetPermissionInfoFromJson(const nlohmann::json &appInfoConfig, AppSpawnMsgInternetInfo &info);
    int GetAccessTokenFromJson(const nlohmann::json &appInfoConfig, AppSpawnMsgAccessToken &info);
    int AddDomainInfoFromJson(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle);

    static AppSpawnTestCommander *ConvertTo(const ThreadContext *context)
    {
        return const_cast<AppSpawnTestCommander *>(reinterpret_cast<const AppSpawnTestCommander *>(context));
    }
    static void TaskExecutorProc(ThreadTaskHandle handle, const ThreadContext *context);
    static void SendTaskFinish(ThreadTaskHandle handle, const ThreadContext *context);
    static void InputThread(ThreadTaskHandle handle, const ThreadContext *context);

    uint32_t exit_ : 1;
    uint32_t appSpawn_ : 1;
    uint32_t msgType_;
    pid_t terminatePid_;
    std::string testFileName_{};
    std::string processName_ {};
    uint32_t threadCount_ {1};
    AppSpawnClientHandle clientHandle_{nullptr};
    ThreadMgr threadMgr_{nullptr};
    ThreadTaskHandle inputHandle_{0};
};

static const char *g_usage = "usage: AppSpawnTest <options> \n"
    "options list:\n"
    "  --help                   list available commands\n"
    "  --file xx                file path with app info\n"
    "  --thread xx              use multi-thread to send message\n"
    "  --type xx                send msg type \n"
    "  --pid xx                 render terminate pid\n"
    "  --mode nwebspawn         send message to nwebspawn service\n";

int AppSpawnTestCommander::ProcessArgs(int argc, char *const argv[])
{
    int sendMsg = 0;
    msgType_ = MAX_TYPE_INVALID;
    for (int32_t i = 0; i < argc; i++) {
        if (argv[i] == nullptr) {
            continue;
        }
        if (strcmp(argv[i], "--file") == 0 && ((i + 1) < argc)) {  // test file
            i++;
            testFileName_ = argv[i];
            sendMsg = 1;
        } else if (strcmp(argv[i], "--thread") == 0 && ((i + 1) < argc)) {  // use thread
            i++;
            threadCount_ = atoi(argv[i]);
            if (threadCount_ > MAX_THREAD) {
                threadCount_ = MAX_THREAD;
            }
            sendMsg = 1;
        } else if (strcmp(argv[i], "--mode") == 0 && ((i + 1) < argc)) {
            i++;
            appSpawn_ = strcmp(argv[i], "nwebspawn") == 0 ? 0 : 1;
            sendMsg = 1;
        } else if (strcmp(argv[i], "--type") == 0 && ((i + 1) < argc)) {
            i++;
            msgType_ = atoi(argv[i]);
            sendMsg = 1;
        } else if (strcmp(argv[i], "--pid") == 0 && ((i + 1) < argc)) {
            i++;
            msgType_ = MSG_GET_RENDER_TERMINATION_STATUS;
            terminatePid_ = atoi(argv[i]);
            sendMsg = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("%s\n", g_usage);
            return 1;
        } else if (strcmp(argv[i], "--send") == 0 || strcmp(argv[i], "send") == 0) {
            sendMsg = 1;
        }
    }
    if (sendMsg == 0) {
        printf("%s\n", g_usage);
        return 1;
    }
    return 0;
}

int AppSpawnTestCommander::AddBundleInfoFromJson(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle)
{
    if (appInfoConfig.find("bundle-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("bundle-info");
    uint32_t bundleIndex = AppSpawn::JsonUtils::GetIntValueFromJson(config, "bundle-index");
    std::string bundleName = AppSpawn::JsonUtils::GetStringFromJson(config, "bundle-name");
    int ret = AppSpawnReqMsgSetBundleInfo(reqHandle, bundleIndex, bundleName.c_str());
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add bundle info req %{public}s", bundleName.c_str());
    return 0;
}

int AppSpawnTestCommander::GetDacInfoFromJson(const nlohmann::json &appInfoConfig, AppDacInfo &info)
{
    if (appInfoConfig.find("dac-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("dac-info");
    info.uid = AppSpawn::JsonUtils::GetIntValueFromJson(config, "uid");
    info.gid = AppSpawn::JsonUtils::GetIntValueFromJson(config, "gid");
    if (config.find("gid-table") != config.end()) {
        const auto vec = config.at("gid-table").get<std::vector<uint32_t>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            info.gidTable[info.gidCount++] = vec[j];
            if (info.gidCount >= APP_MAX_GIDS) {
                break;
            }
        }
    }
    std::string userName = AppSpawn::JsonUtils::GetStringFromJson(config, "user-name");
    if (!userName.empty()) {
        return strcpy_s(info.userName, sizeof(info.userName), userName.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::GetInternetPermissionInfoFromJson(
    const nlohmann::json &appInfoConfig, AppSpawnMsgInternetInfo &info)
{
    if (appInfoConfig.find("internet-permission") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("internet-permission");
    info.setAllowInternet = AppSpawn::JsonUtils::GetIntValueFromJson(config, "set-allow-internet");
    info.allowInternet = AppSpawn::JsonUtils::GetIntValueFromJson(config, "allow-internet");
    return 0;
}

int AppSpawnTestCommander::GetAccessTokenFromJson(const nlohmann::json &appInfoConfig, AppSpawnMsgAccessToken &info)
{
    if (appInfoConfig.find("access-token") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("access-token");
    info.accessTokenIdEx = AppSpawn::JsonUtils::GetIntValueFromJson(config, "accessTokenIdEx");
    return 0;
}

int AppSpawnTestCommander::AddDomainInfoFromJson(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle)
{
    if (appInfoConfig.find("domain-info") == appInfoConfig.end()) {
        return -1;
    }
    nlohmann::json config = appInfoConfig.at("domain-info");
    uint32_t hapFlags = AppSpawn::JsonUtils::GetIntValueFromJson(config, "hap-flags");
    std::string apl = AppSpawn::JsonUtils::GetStringFromJson(config, "apl");
    int ret = AppSpawnReqMsgSetAppDomainInfo(reqHandle, hapFlags, apl.c_str());
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to domain info");
    return 0;
}

int AppSpawnTestCommander::AddExtTlv(const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle)
{
    if (appInfoConfig.find("ext-info") == appInfoConfig.end()) {
        return 0;
    }
    int ret = 0;
    uint32_t count = appInfoConfig.at("ext-info").size();
    for (unsigned int j = 0; j < count; j++) {
        nlohmann::json config = appInfoConfig.at("ext-info")[j];
        std::string name = AppSpawn::JsonUtils::GetStringFromJson(config, "name");
        std::string value = AppSpawn::JsonUtils::GetStringFromJson(config, "value");
        APPSPAWN_LOGV("ext-info %{public}s %{public}s", name.c_str(), value.c_str());
        ret = AppSpawnReqMsgAddStringInfo(reqHandle, name.c_str(), value.c_str());
        APPSPAWN_CHECK(ret == 0, return ret, "Failed to add ext name %{public}s", name.c_str());
    }
    ret = AppSpawnReqMsgAddStringInfo(reqHandle, "app-info", appInfoConfig.dump().c_str());
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add ext name app-info");
    // 添加一个二进制的扩展元素
    AppDacInfo dacInfo {};
    dacInfo.uid = 101;
    dacInfo.gid = 101;
    dacInfo.gidTable[0] = 101;
    dacInfo.gidCount = 1;
    (void)strcpy_s(dacInfo.userName, sizeof(dacInfo.userName), processName_.c_str());
    ret = AppSpawnReqMsgAddExtInfo(reqHandle, "app-dac-info", reinterpret_cast<uint8_t *>(&dacInfo), sizeof(dacInfo));
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add ext name app-info");
    return ret;
}

int AppSpawnTestCommander::BuildMsgFromJson (const nlohmann::json &appInfoConfig, AppSpawnReqMsgHandle reqHandle)
{
    int ret = AddBundleInfoFromJson(appInfoConfig, reqHandle);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add dac %{public}s", processName_.c_str());

    ret = AddDomainInfoFromJson(appInfoConfig, reqHandle);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add dac %{public}s", processName_.c_str());

    AppDacInfo dacInfo = {};
    ret = GetDacInfoFromJson(appInfoConfig, dacInfo);
    ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &dacInfo);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add dac %{public}s", processName_.c_str());

    AppSpawnMsgAccessToken token = {};
    ret = GetAccessTokenFromJson(appInfoConfig, token);
    ret = AppSpawnReqMsgSetAppAccessToken(reqHandle, token.accessTokenIdEx);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to add access token %{public}s", processName_.c_str());

    if (appInfoConfig.find("permission") != appInfoConfig.end()) {
        const auto vec = appInfoConfig.at("permission").get<std::vector<std::string>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            APPSPAWN_LOGV("permission %{public}s ", vec[j].c_str());
            ret = AppSpawnReqMsgAddPermission(reqHandle, vec[j].c_str());
            APPSPAWN_CHECK(ret == 0, return ret, "Failed to permission %{public}s", vec[j].c_str());
        }
    }
    AppSpawnMsgInternetInfo internetInfo = {};
    ret = GetInternetPermissionInfoFromJson(appInfoConfig, internetInfo);
    ret = AppSpawnReqMsgSetAppInternetPermissionInfo(reqHandle,
        internetInfo.allowInternet, internetInfo.setAllowInternet);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to internet info %{public}s", processName_.c_str());

    std::string ownerId = AppSpawn::JsonUtils::GetStringFromJson(appInfoConfig, "owner-id");
    if (!ownerId.empty()) {
        ret = AppSpawnReqMsgSetAppOwnerId(reqHandle, ownerId.c_str());
        APPSPAWN_CHECK(ret == 0, return ret, "Failed to ownerid %{public}s", processName_.c_str());
    }

    std::string renderCmd = AppSpawn::JsonUtils::GetStringFromJson(appInfoConfig, "render-cmd");
    if (!renderCmd.empty()) {
        ret = AppSpawnReqMsgAddExtInfo(reqHandle, MSG_EXT_NAME_RENDER_CMD,
            reinterpret_cast<uint8_t *>(const_cast<char *>(renderCmd.c_str())), renderCmd.size());
        APPSPAWN_CHECK(ret == 0, return -1, "Failed to add renderCmd %{public}s", renderCmd.c_str());
    }
    return AddExtTlv(appInfoConfig, reqHandle);
}

int AppSpawnTestCommander::CreateOtherMsg(AppSpawnReqMsgHandle &reqHandle, pid_t pid)
{
    if (msgType_ == MSG_GET_RENDER_TERMINATION_STATUS) {
        int ret = AppSpawnTerminateMsgCreate(pid, &reqHandle);
        APPSPAWN_CHECK(ret == 0, return ret,
            "Failed to termination message req %{public}s", processName_.c_str());
    }
    if (msgType_ == MSG_DUMP) {
        int ret = AppSpawnReqMsgCreate(msgType_, processName_.c_str(), &reqHandle);
        APPSPAWN_CHECK(ret == 0, return ret,
            "Failed to dump req %{public}s", processName_.c_str());
    }
    return 0;
}

int AppSpawnTestCommander::CreateMsg(AppSpawnReqMsgHandle &reqHandle)
{
    int ret = APPSPAWN_SYSTEM_ERROR;
    reqHandle = INVALID_REQ_HANDLE;
    nlohmann::json appInfoConfig;
    if (!testFileName_.empty()) {
        if (!AppSpawn::JsonUtils::GetJsonObjFromJson(appInfoConfig, testFileName_)) {
            printf("Failed to load file %s, so use default info \n", testFileName_.c_str());
        }
    }
    if (appInfoConfig == nullptr) {
        appInfoConfig = nlohmann::json::parse(g_defaultAppInfo.c_str(), nullptr, false);
    }
    if (appInfoConfig == nullptr) {
        printf("Invalid app info \n");
        return APPSPAWN_SYSTEM_ERROR;
    }
    processName_ = AppSpawn::JsonUtils::GetStringFromJson(appInfoConfig, "process-name");
    if (processName_.empty()) {
        processName_ = "com.example.myapplication";
    }
    if (msgType_ == MAX_TYPE_INVALID) {
        msgType_ = AppSpawn::JsonUtils::GetIntValueFromJson(appInfoConfig, "msg-type", MSG_APP_SPAWN);
    }
    if (msgType_ == MSG_DUMP) {
        return CreateOtherMsg(reqHandle, 0);
    } else if (msgType_ == MSG_GET_RENDER_TERMINATION_STATUS) {
        pid_t pid = AppSpawn::JsonUtils::GetIntValueFromJson(appInfoConfig, "pid");
        return CreateOtherMsg(reqHandle, pid);
    }
    ret = AppSpawnReqMsgCreate(msgType_, processName_.c_str(), &reqHandle);
    APPSPAWN_CHECK(ret == 0, return ret, "Failed to create req %{public}s", processName_.c_str());

    if (appInfoConfig.find("msg-flags") != appInfoConfig.end()) {
        const auto vec = appInfoConfig.at("msg-flags").get<std::vector<uint32_t>>();
        for (unsigned int j = 0; j < vec.size(); j++) {
            (void)AppSpawnReqMsgSetAppFlag(reqHandle, vec[j]);
        }
    }
    ret = BuildMsgFromJson(appInfoConfig, reqHandle);
    APPSPAWN_CHECK(ret == 0, AppSpawnReqMsgFree(reqHandle);
        return ret, "Failed to build req %{public}s", processName_.c_str());
    return ret;
}

int AppSpawnTestCommander::SendMsg()
{
    const char *server = appSpawn_ ? APPSPAWN_SERVER_NAME : NWEBSPAWN_SERVER_NAME;
    printf("Send msg to server '%s' \n", server);
    AppSpawnReqMsgHandle reqHandle = INVALID_REQ_HANDLE;
    int ret = 0;
    if (msgType_ == MSG_DUMP) {
        ret = CreateOtherMsg(reqHandle, 0);
    } else if (msgType_ == MSG_GET_RENDER_TERMINATION_STATUS) {
        ret = CreateOtherMsg(reqHandle, terminatePid_);
    } else {
        ret = CreateMsg(reqHandle);
    }
    AppSpawnResult result = {ret, 0};
    if (ret == 0) {
        ret = AppSpawnClientSendMsg(clientHandle_, reqHandle, &result);
    }
    if (msgType_ == MSG_APP_SPAWN || msgType_ == MSG_SPAWN_NATIVE_PROCESS) {
        if (result.result == 0) {
            printf("Spawn app %s success, pid %d \n", processName_.c_str(), result.pid);
        } else {
            printf("Spawn app %s fail, result 0x%x \n", processName_.c_str(), result.result);
        }
    } else if (msgType_ == MSG_GET_RENDER_TERMINATION_STATUS) {
        if (ret == 0) {
            printf("Terminate app %s success, pid %d status 0x%x \n", processName_.c_str(), result.pid, result.result);
        } else {
            printf("Terminate app %s fail, result 0x%x \n", processName_.c_str(), ret);
        }
    } else {
        printf("Dump server %s result %d \n", server, ret);
    }
    msgType_ = MAX_TYPE_INVALID;
    terminatePid_ = 0;
    printf("Please input cmd: \n");
    return 0;
}

int AppSpawnTestCommander::StartSendMsg()
{
    int ret = 0;
    printf("Start send msg thread count %d file name %s \n", threadCount_, testFileName_.c_str());
    if (threadCount_ == 1) {
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

int AppSpawnTestCommander::ProcessInputCmd(std::string &cmd)
{
    std::vector<std::string> args = AppSpawn::JsonUtils::split(cmd, " ");
    std::vector<char *> options;
    for (const auto &arg : args) {
        if (!arg.empty()) {
            options.push_back(const_cast<char *>(arg.c_str()));
        }
    }
    (void)ProcessArgs(options.size(), options.data());
    StartSendMsg();
    return 0;
}

void AppSpawnTestCommander::InputThread(ThreadTaskHandle handle, const ThreadContext *context)
{
    AppSpawnTestCommander *testCmder = AppSpawnTestCommander::ConvertTo(context);
    char buf[1024] = {0};  // 1024 test buffer max len
    fd_set fds;
    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        printf("Please input cmd: \n");
        int ret = select(STDIN_FILENO + 1, &fds, 0, 0, 0);
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
        if (strncmp("send", buf, 4) == 0) {               // 4 strlen("send")
            std::string cmd(buf);
            testCmder->ProcessInputCmd(cmd);
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
        usleep(200000);  // 200000 200ms
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
    SetDumpFlags(1);
    OHOS::AppSpawnModuleTest::AppSpawnTestCommander commander;
    int ret = commander.ProcessArgs(argc, argv);
    if (ret == 0) {
        commander.Run();
    }
    return 0;
}