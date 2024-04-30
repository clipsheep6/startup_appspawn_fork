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

#include <cerrno>
#include <cstdbool>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "appspawn_manager.h"
#include "appspawn_modulemgr.h"
#include "appspawn_permission.h"
#include "appspawn_sandbox.h"
#include "appspawn_server.h"
#include "appspawn_utils.h"
#include "cJSON.h"
#include "json_utils.h"
#include "securec.h"

#include "app_spawn_stub.h"
#include "app_spawn_test_helper.h"

namespace OHOS {
static AppSpawnTestHelper g_testHelper;

static const std::string g_commonConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"ON\" \
    }, \
    \"required\":{ \
        \"system-const\":{ \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/lib\", \
                \"sandbox-path\" : \"/lib\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"shared\", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"src-path\" : \"/lib1\", \
                \"sandbox-path\" : \"/lib1\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"rdonly\", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"src-path\" : \"/none\", \
                \"sandbox-path\" : \"/storage/cloud/epfs\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"epfs\", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"src-path\" : \"/storage/Users/<currentUserId>/appdata/el1\", \
                \"sandbox-path\" : \"/storage/Users/<currentUserId>/appdata/el1\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"dac_override\", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"src-path\" : \"/dev/fuse\", \
                \"sandbox-path\" : \"/mnt/data/fuse\", \
                \"category\": \"fuse\", \
                \"check-action-status\": \"true\" \
            }], \
            \"symbol-links\" : [], \
            \"mount-groups\": [\"test-always\"] \
        }, \
        \"app-variable\":{ \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/config\", \
                \"sandbox-path\" : \"/config\", \
                \"check-action-status\": \"false\", \
                \"app-apl-name\" : \"system\", \
                \"category\": \"shared\" \
            }], \
            \"symbol-links\" : [], \
            \"mount-groups\": [\"el5\"] \
        } \
    }, \
    \"name-groups\": [ \
        { \
            \"name\": \"user-public\", \
            \"type\": \"system-const\", \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/el2/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"/data/storage/el2/base\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"shared\" \
            }] \
        }, { \
            \"name\": \"el5\", \
            \"type\": \"app-variable\", \
            \"deps-mode\": \"not-exists\", \
            \"mount-paths-deps\": { \
                \"sandbox-path\": \"/data/storage/el5\", \
                \"src-path\": \"/data/app/el5/<currentUserId>\", \
                \"category\": \"shared\" \
            }, \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/el5/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"<deps-path>/base\" \
            }] \
        }, { \
            \"name\": \"el6\", \
            \"type\": \"app-variable\", \
            \"deps-mode\": \"not-exists\", \
            \"mount-paths-deps\": { \
                \"sandbox-path\": \"/data/storage/el6\", \
                \"src-path\": \"/data/app/el6/<currentUserId>\", \
                \"category\": \"shared\" \
            }, \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/el6/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"<deps-path>/base\" \
            }] \
        },{ \
            \"name\": \"test-always\", \
            \"type\": \"system-const\", \
            \"deps-mode\": \"always\", \
            \"mount-paths-deps\": { \
                \"sandbox-path\": \"/data/storage/e20\", \
                \"src-path\": \"/data/app/e20/<currentUserId>\", \
                \"category\": \"shared\" \
            }, \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/data/app/e20/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"<deps-path>/base\" \
            }] \
        } \
    ] \
}";

static const std::string g_packageNameConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"OFF\" \
    }, \
    \"conditional\":{ \
        \"package-name\": [{ \
            \"name\": \"test.example.ohos.com\", \
            \"sandbox-switch\": \"ON\", \
            \"sandbox-shared\" : \"true\", \
            \"sandbox-ns-flags\" : [ \"pid\", \"net\" ], \
            \"mount-paths\" : [{ \
                \"src-path\" : \"/config\", \
                \"sandbox-path\" : \"/config\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"shared\", \
                \"app-apl-name\" : \"system\" \
            }], \
            \"symbol-links\" : [{ \
                \"target-name\" : \"/system/etc\", \
                \"link-name\" : \"/etc\", \
                \"check-action-status\": \"false\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \" \
            }] \
        }, \
        { \
            \"name\": \"com.example.myapplication\", \
            \"sandbox-switch\": \"ON\", \
            \"sandbox-shared\" : \"true\", \
            \"mount-paths\" : [{ \
                    \"src-path\" : \"/mnt/data/<currentUserId>\", \
                    \"sandbox-path\" : \"/mnt/data\", \
                    \"category\": \"shared\", \
                    \"check-action-status\": \"true\" \
                }, { \
                    \"src-path\" : \"/dev/fuse\", \
                    \"sandbox-path\" : \"/mnt/data/fuse\", \
                    \"category\": \"fuse\", \
                    \"check-action-status\": \"true\" \
                }],\
            \"symbol-links\" : [] \
        }]\
    } \
}";

static const std::string g_permissionConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ] \
    }, \
    \"conditional\":{ \
        \"permission\": [{ \
                \"name\": \"ohos.permission.FILE_ACCESS_MANAGER\", \
                \"sandbox-switch\": \"ON\", \
                \"gids\": [\"file_manager\", \"user_data_rw\"], \
                \"sandbox-ns-flags\" : [ \"pid\", \"net\" ], \
                \"mount-paths\" : [{ \
                    \"src-path\" : \"/config--1\", \
                    \"sandbox-path\" : \"/data/app/el1/<currentUserId>/database/<PackageName_index>\", \
                    \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                    \"category\": \"shared\", \
                    \"app-apl-name\" : \"system\", \
                    \"check-action-status\": \"true\" \
                }], \
                \"symbol-links\" : [{ \
                        \"target-name\" : \"/system/etc\", \
                        \"link-name\" : \"/etc\", \
                        \"check-action-status\": \"false\", \
                        \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \" \
                    } \
                ] \
            }, \
            { \
                \"name\": \"ohos.permission.ACTIVATE_THEME_PACKAGE\", \
                \"sandbox-switch\": \"ON\", \
                \"gids\": [1006, 1008, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006 \
                , 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006\
                , 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006\
                , 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006, 1006 ], \
                \"sandbox-ns-flags\" : [ \"pid\", \"net\" ], \
                \"mount-paths\" : [{ \
                    \"src-path\" : \"/config--2\", \
                    \"sandbox-path\" : \"/data/app/el1/<currentUserId>/database/<PackageName_index>\", \
                    \"check-action-status\": \"false\" \
                }], \
                \"symbol-links\" : [] \
            }] \
        } \
    }";

static const std::string g_spawnFlagsConfig = "{ \
    \"global\": { \
        \"sandbox-root\": \"/mnt/sandbox/<currentUserId>/app-root\", \
        \"sandbox-ns-flags\": [ \"pid\", \"net\" ], \
        \"top-sandbox-switch\": \"OFF\" \
    }, \
    \"conditional\":{ \
        \"spawn-flag\": [{ \
            \"name\": \"START_FLAGS_BACKUP\", \
            \"mount-paths\": [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"check-action-status\": \"true\", \
                \"dest-mode\": \"S_IRUSR | S_IWOTH | S_IRWXU \", \
                \"category\": \"shared\", \
                \"app-apl-name\" : \"system\" \
            }, { \
                \"sandbox-path\": \"/data/storage/el1/backup\", \
                \"src-path\": \"/data/service/el1/<currentUserId>/backup/bundles/<PackageName>\" \
            }], \
            \"mount-groups\": [] \
        }, { \
            \"name\": \"DLP_MANAGER\", \
            \"mount-paths\": [{ \
                \"src-path\" : \"/data/app/el1/bundle/public/\", \
                \"sandbox-path\" : \"/data/bundles/\", \
                \"check-action-status\": \"true\" \
            }, { \
                \"src-path\" : \"/data/app/el1/<currentUserId>/database/<PackageName>\", \
                \"sandbox-path\" : \"/data/storage/el1/database\", \
                \"check-action-status\": \"true\" \
            }, { \
                \"src-path\" : \"/data/app/el1/<currentUserId>/base/<PackageName>\", \
                \"sandbox-path\" : \"/data/storage/el1/base\", \
                \"check-action-status\": \"true\" \
            }], \
            \"mount-groups\": [] \
        }] \
    }\
}";

AppSpawnTestHelper *GetAppSpawnTestHelper()
{
    return &g_testHelper;
}
}  // namespace OHOS
#ifdef __cplusplus
extern "C" {
#endif

AppSpawningCtx *TestCreateAppSpawningCtx()
{
    AppSpawnClientHandle clientHandle = nullptr;
    int ret = AppSpawnClientInit(APPSPAWN_SERVER_NAME, &clientHandle);
    APPSPAWN_CHECK(ret == 0, return nullptr, "Failed to create reqMgr");
    AppSpawnReqMsgHandle reqHandle = OHOS::g_testHelper.CreateMsg(clientHandle, MSG_APP_SPAWN, 0);
    APPSPAWN_CHECK(reqHandle != INVALID_REQ_HANDLE, return nullptr, "Failed to create req");
    return OHOS::g_testHelper.GetAppProperty(clientHandle, reqHandle);
}

SandboxContext *TestGetSandboxContext(const AppSpawningCtx *property, int nwebspawn)
{
    AppSpawnMsgFlags *msgFlags = (AppSpawnMsgFlags *)GetAppProperty(property, TLV_MSG_FLAGS);
    APPSPAWN_CHECK(msgFlags != NULL, return nullptr, "No msg flags in msg %{public}s", GetProcessName(property));

    SandboxContext *context = GetSandboxContext();
    APPSPAWN_CHECK(context != NULL, return nullptr, "Failed to get context");

    context->nwebspawn = nwebspawn;
    context->bundleName = GetBundleName(property);
    context->bundleHasWps = strstr(context->bundleName, "wps") != NULL;
    context->dlpBundle = strstr(context->bundleName, "com.ohos.dlpmanager") != NULL;
    context->appFullMountEnable = 0;
    context->dlpUiExtType = strstr(GetProcessName(property), "sys/commonUI") != NULL;

    context->sandboxSwitch = 1;
    context->sandboxShared = false;
    context->message = property->message;
    context->rootPath = strdup("/mnt/sandbox/100/app-root");
    return context;
}

int TestParseAppSandboxConfig(AppSpawnSandboxCfg *sandbox, const char *buffer)
{
    cJSON *config = cJSON_Parse(buffer);
    if (config == nullptr) {
        APPSPAWN_LOGE("Failed to parse config %{public}s", buffer);
        return -1;
    }
    int ret = 0;
    do {
        ret = ParseAppSandboxConfig(config, sandbox);
        APPSPAWN_CHECK_ONLY_EXPER(ret == 0, break);

        uint32_t depNodeCount = sandbox->depNodeCount;
        APPSPAWN_CHECK_ONLY_EXPER(depNodeCount > 0, break);

        sandbox->depGroupNodes = (SandboxNameGroupNode **)calloc(1, sizeof(SandboxNameGroupNode *) * depNodeCount);
        APPSPAWN_CHECK(sandbox->depGroupNodes != NULL, break, "Failed alloc memory ");
        sandbox->depNodeCount = 0;
        ListNode *node = sandbox->nameGroupsQueue.front.next;
        while (node != &sandbox->nameGroupsQueue.front) {
            SandboxNameGroupNode *groupNode = (SandboxNameGroupNode *)ListEntry(node, SandboxMountNode, node);
            if (groupNode->depNode) {
                sandbox->depGroupNodes[sandbox->depNodeCount++] = groupNode;
            }
            node = node->next;
        }
        APPSPAWN_LOGI("LoadAppSandboxConfig depNodeCount %{public}d", sandbox->depNodeCount);
    } while (0);
    cJSON_Delete(config);
    return ret;
}

const char *GetSandboxCommonCfg()
{
    return OHOS::g_commonConfig.c_str();
}
const char *GetSandboxPackageNameCfg()
{
    return OHOS::g_packageNameConfig.c_str();
}
const char *GetSandboxPermissionCfg()
{
    return OHOS::g_permissionConfig.c_str();
}
const char *GetSandboxspawnFlagsCfg()
{
    return OHOS::g_spawnFlagsConfig.c_str();
}
#ifdef __cplusplus
}
#endif

