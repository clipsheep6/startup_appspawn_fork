/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "appspawn_mount_permission.h"
#include "appspawn_server.h"

namespace OHOS {
namespace AppSpawn {

#define ARRAY_SIZE_X(a) (sizeof(a)/sizeof(a[0]))

const std::string AppspawnMountPermission::mountPermissionList[] ={
 {"ohos.permission.FILE_ACCESS_MANAGER"},
};


uint32_t AppspawnMountPermission::GetMountPermissionListSize(){
    return ARRAY_SIZE_X(AppspawnMountPermission::mountPermissionList);
}

uint32_t AppspawnMountPermission::GenPermissionCode(const std::string permissions[],int len)
{
    uint32_t result = 0;
    if (len <= 0){
        return result;
    }
    uint32_t flagIndex = 1;
    for (int index = 0; index < ARRAY_SIZE_X(AppspawnMountPermission::mountPermissionList); index++)
    {
        for (int j = 0; j < len; j++)
        {
            if (AppspawnMountPermission::mountPermissionList[index].compare(permissions[j]) == 0)
            {
                result |= flagIndex;
                break;
            }
        }
        flagIndex <<= 1;
    }
    return result;
}


bool AppspawnMountPermission::isMountPermission(uint32_t code, const std::string permission)
{
    for (int i = 0; i < ARRAY_SIZE_X(AppspawnMountPermission::mountPermissionList); i++)
    {
        if (AppspawnMountPermission::mountPermissionList[i].compare(permission) == 0)
        {
            return code&1;
        }
        code >>=1;
    }
    return false;
}
}
}