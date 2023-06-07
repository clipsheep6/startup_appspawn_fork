/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "init_hook.h"
#include "init_module_engine.h"
#include "plugin_adapter.h"

static int UDidCalc(const HOOK_INFO *hookInfo, void *cookie)
{
    PLUGIN_LOGI("Begin install udidmodule.");

    InitModuleMgrInstall("udidmodule");
    PLUGIN_LOGI("Begin uninstall udidmodule.");
    InitModuleMgrUnInstall("udidmodule");

    PLUGIN_LOGI("Uninstall udidmodule finished.");
    return 0;
}

MODULE_CONSTRUCTOR(void)
{
    InitAddPreCfgLoadHook(0, UDidCalc);
}