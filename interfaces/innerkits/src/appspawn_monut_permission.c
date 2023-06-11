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

#include "appspawn_monut_permission.h"
#include <string.h>

#define ARRAY_SIZE_X(a) (sizeof(a)/sizeof(a[0]))

uint32_t GenPermissionCode(const Permission permissions[],int len)
{
    uint32_t result = 0;
    if (len <= 0){
        return result;
    }
    uint32_t flagIndex = 1;
    for (int index = 0; index < ARRAY_SIZE_X(mountPermissionList); index++)
    {
        for (int j = 0; j < len; j++)
        {
            if (strcmp(permissions[j].name, mountPermissionList[index].name) == 0)
            {
                result |= flagIndex;
                break;
            }
        }
        flagIndex <<= 1;
    }
    return result;
}


bool isMonutPermission(uint32_t code, const char permission[])
{
    for (int i = 0; i < ARRAY_SIZE_X(mountPermissionList); i++)
    {
        if(strcmp(permission, mountPermissionList[i].name) == 0){
            return code&1;
        }
        code >>=1;
    }
    return false;
}