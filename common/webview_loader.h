/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "stdbool.h"
#include "stdio.h"

#ifndef WEBVIEW_LOADER
#define WEBVIEW_LOADER
#ifdef __cplusplus
extern "C" {
#endif

void *gReservedAddress;
size_t gReservedSize;

bool CreateRelroFile(const char *lib, const char *relro, const char *ns_name,
                     const char *ns_path);

void *LoadWithRelroFile(const char *lib, const char *relro, const char *ns_name,
                        const char *ns_path);

#ifdef __cplusplus
}
#endif
#endif

