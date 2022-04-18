*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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
#include "init_service.h"

#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "init.h"
#include "init_log.h"
#include "init_service_manager.h"
#include "securec.h"

void NotifyServiceChange(Service *service, int status)
{
    UNUSED(service);
    UNUSED(status);
}

int IsForbidden(const char *fieldStr)
{
    size_t fieldLen = strlen(fieldStr);
    size_t forbidStrLen = strlen(BIN_SH_NOT_ALLOWED);
    if (fieldLen == forbidStrLen) {
        if (strncmp(fieldStr, BIN_SH_NOT_ALLOWED, fieldLen) == 0) {
            return 1;
        }
        return 0;
    } else if (fieldLen > forbidStrLen) {
        // "/bin/shxxxx" is valid but "/bin/sh xxxx" is invalid
        if (strncmp(fieldStr, BIN_SH_NOT_ALLOWED, forbidStrLen) == 0) {
            if (fieldStr[forbidStrLen] == ' ') {
                return 1;
            }
        }
        return 0;
    } else {
        return 0;
    }
}

int SetImportantValue(Service *service, const char *attrName, int value, int flag)
{
    UNUSED(attrName);
    UNUSED(flag);
    INIT_ERROR_CHECK(service != NULL, return SERVICE_FAILURE, "Set service attr failed! null ptr.");
    if (value != 0) {
        service->attribute |= SERVICE_ATTR_IMPORTANT;
    }
    return SERVICE_SUCCESS;
}

int ServiceExec(const Service *service)
{
    INIT_ERROR_CHECK(service != NULL && service->pathArgs.count > 0,
        return SERVICE_FAILURE, "Exec service failed! null ptr.");
    INIT_LOGI("service->name is %s ", service->name);
    char sockEnvName[MAX_ENV_NAME] = {0};
    char sockEnvValue[MAX_ENV_NAME] = {0};
    if (service->socketCfg != NULL) {
        INIT_ERROR_CHECK(snprintf_s(sockEnvName, MAX_ENV_NAME, MAX_ENV_NAME - 1, "OHOS_SOCKET_%s",
            service->socketCfg->name) != -1,
            return SERVICE_FAILURE, "format socket env name failed!");
        INIT_ERROR_CHECK(snprintf_s(sockEnvValue, MAX_ENV_NAME, MAX_ENV_NAME - 1, "%d",
            service->socketCfg->sockFd) != -1,
            return SERVICE_FAILURE, "format socket env value failed!");
    }
    INIT_CHECK_ONLY_ELOG(setenv(sockEnvName, sockEnvValue, 1) == 0, "DoExport: set %s with %s failed: %d",
        sockEnvName, sockEnvValue, errno);
    if (execv(service->pathArgs.argv[0], service->pathArgs.argv) != 0) {
        INIT_LOGE("service %s execv failed! err %d.", service->name, errno);
        return errno;
    }
    return SERVICE_SUCCESS;
}

int SetAccessToken(const Service *service)
{
    return SERVICE_SUCCESS;
}

void GetAccessToken(void)
{
    return;
}
