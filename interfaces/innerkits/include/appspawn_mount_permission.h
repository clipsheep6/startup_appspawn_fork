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

#ifndef APPSPAWN_MOUNT_PERMISSION_H
#define APPSPAWN_MOUNT_PERMISSION_H

#include <string>

namespace OHOS {
namespace AppSpawn {
class AppspawnMountPermission{
    public:
    static const std::string mountPermissionList[];

    static uint32_t GetMountPermissionListSize();
    
    static uint32_t GenPermissionCode(const std::string permissions[],int len);

    static bool isMountPermission(uint32_t code, const std::string permission);
};
}// AppSpawn
}//OHOS
#endif

