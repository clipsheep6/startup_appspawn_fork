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

#ifndef APPSPAWN_CLIENT_MOUNT_PERMISSION_H
#define APPSPAWN_CLIENT_MOUNT_PERMISSION_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TagSandboxQueue {
    struct ListNode front;
    uint32_t type;
} SandboxQueue;

typedef struct TagParseJsonContext {
    SandboxQueue permissionQueue;
    int32_t maxPermissionIndex;
} ParseJsonContext;

typedef struct {
    struct ListNode node;
} SandboxMountNode;

typedef struct TagPermissionNode {
    SandboxMountNode sandboxNode;
    uint32_t permissionIndex;
    char name[0];
} SandboxPermissionNode;

/**
 * @brief Get the permission index by permission name
 *
 * @param permission permission name
 * @return int32_t permission index, if not exit, return INVALID_PERMISSION_INDEX
 */
int32_t GetPermissionIndex(const char *permission);

/**
 * @brief Get the max permission Index
 *
 * @return int32_t max permission Index
 */
int32_t GetMaxPermissionIndex(void);

/**
 * @brief Get the permission name by index
 *
 * @param index permission index
 * @return const char* permission name
 */
const char *GetPermissionByIndex(int32_t index);

#ifdef __cplusplus
}
#endif
#endif  // APPSPAWN_CLIENT_MOUNT_PERMISSION_H
