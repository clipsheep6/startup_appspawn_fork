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
#include "webview_loader.h"

int main(int argc, char *const argv[]) {
#ifdef webview_arm64
  CreateRelroFile(
      "libweb_engine.so", "/data/misc/shared_relro/libwebviewchromium64.relro",
      "nweb_ns", "/data/app/el1/bundle/public/com.ohos.nweb/libs/arm64");
#else
  CreateRelroFile(
      "libweb_engine.so", "/data/misc/shared_relro/libwebviewchromium32.relro",
      "nweb_ns", "/data/app/el1/bundle/public/com.ohos.nweb/libs/arm");
#endif
  return 0;
}
