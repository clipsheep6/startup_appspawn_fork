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

#include "webview_loader.h"

#include "beget_ext.h"
#include <dlfcn_ext.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef WEBLOADER_LABEL
#define WEBLOADER_LABEL "WEBLOADER"
#endif
#define WEBLOADER_DOMAIN (BASE_DOMAIN + 0x11)
#define WEBLOADER_LOGI(fmt, ...)                                               \
  STARTUP_LOGI(WEBLOADER_DOMAIN, WEBLOADER_LABEL, fmt, ##__VA_ARGS__)
#define WEBLOADER_LOGE(fmt, ...)                                               \
  STARTUP_LOGE(WEBLOADER_DOMAIN, WEBLOADER_LABEL, fmt, ##__VA_ARGS__)
#define WEBLOADER_LOGV(fmt, ...)                                               \
  STARTUP_LOGV(WEBLOADER_DOMAIN, WEBLOADER_LABEL, fmt, ##__VA_ARGS__)
#define WEBLOADER_LOGW(fmt, ...)                                               \
  STARTUP_LOGW(WEBLOADER_DOMAIN, WEBLOADER_LABEL, fmt, ##__VA_ARGS__)

void InitAddrAndSize() {
  char *vAddr_env = getenv("RELRO_MMAP_LIBWEBENGINE_ADDR");
  unsigned long int nwebAddr = strtoul(vAddr_env, NULL, 10);
  gReservedAddress = (void *)nwebAddr;
  char *vAddrSize = getenv("RELRO_MMAP_LIBWEBENGINE_SIZE");
  gReservedSize = strtoul(vAddrSize, NULL, 10);
  WEBLOADER_LOGE("InitAddrAndSize gReservedAddress=%p size=%d",
                 gReservedAddress, gReservedSize);
}

bool CreateRelroFile(const char *lib, const char *relro, const char *ns_name,
                     const char *ns_path) {
  InitAddrAndSize();
  if (unlink(relro) != 0 && errno != ENOENT) {
    WEBLOADER_LOGI("CreateRelroFile unlink failed");
  }

  static const char tmpsuffix[] = ".XXXXXX";
  char relro_tmp[strlen(relro) + sizeof(tmpsuffix)];
  strlcpy(relro_tmp, relro, sizeof(relro_tmp));
  strlcat(relro_tmp, tmpsuffix, sizeof(relro_tmp));
  WEBLOADER_LOGI("CreateRelroFile tmp:[%s]", relro_tmp);

  bool mk_file_ok = false;
  int try_time = 0;
  int tmp_fd = -1;
  while (!mk_file_ok && try_time < 15) {
    try_time++;
    tmp_fd = TEMP_FAILURE_RETRY(mkstemp(relro_tmp));
    if (tmp_fd == -1) {
      WEBLOADER_LOGE("CreateRelroFile mk file failed, try_time=[%d]", try_time);
      usleep(500 * 1000);
    } else {
      WEBLOADER_LOGI("CreateRelroFile mk file ok, try_time=[%d]", try_time);
      mk_file_ok = true;
    }
  }

  if (tmp_fd == -1) {
    int tmp_no = errno;
    WEBLOADER_LOGE("CreateRelroFile failed, error=[%s]", strerror(tmp_no));
    return false;
  }

  Dl_namespace dlns;
  dlns_init(&dlns, ns_name);
  dlns_create(&dlns, ns_path);

  dl_extinfo extinfo = {
      .flag = DL_EXT_WRITE_RELRO | DL_EXT_RESERVED_ADDRESS_RECURSIVE |
              DL_EXT_RESERVED_ADDRESS,
      .relro_fd = tmp_fd,
      .reserved_addr = gReservedAddress,
      .reserved_size = gReservedSize,
  };

  bool open_ok = false;
  try_time = 0;
  void *handle = NULL;
  while (!open_ok && try_time < 15) {
    try_time++;
    handle = dlopen_ns_ext(&dlns, lib, RTLD_NOW, &extinfo);
    if (handle == NULL) {
      WEBLOADER_LOGE("CreateRelroFile dlopen_ns_ext failed, try_time=[%d]",
                     try_time);
      usleep(500 * 1000);
    } else {
      WEBLOADER_LOGI("CreateRelroFile dlopen_ns_ext ok, try_time=[%d]",
                     try_time);
      open_ok = true;
    }
  }

  int close_result = close(tmp_fd);
  if (handle == NULL) {
    unlink(relro_tmp);
    int tmp_no = errno;
    WEBLOADER_LOGE("CreateRelroFile failed, error=[%s]", strerror(tmp_no));
    return false;
  }

  if (close_result != 0 || chmod(relro_tmp, S_IRUSR | S_IRGRP | S_IROTH) != 0 ||
      rename(relro_tmp, relro) != 0) {
    unlink(relro_tmp);
    int tmp_no = errno;
    WEBLOADER_LOGE("CreateRelroFile failed, error=[%s]", strerror(tmp_no));
    return false;
  }

  return true;
}

void *LoadWithRelroFile(const char *lib, const char *relro, const char *ns_name,
                        const char *ns_path) {
  InitAddrAndSize();
  Dl_namespace dlns;
  dlns_init(&dlns, ns_name);
  dlns_create(&dlns, ns_path);
  int relro_fd = TEMP_FAILURE_RETRY(open(relro, O_RDONLY));
  if (relro_fd == -1) {
    int tmp_no = errno;
    WEBLOADER_LOGE("LoadWithRelroFile failed, use dlopen_ns, error=[%s]",
                   strerror(tmp_no));
    return dlopen_ns(&dlns, lib, RTLD_NOW | RTLD_GLOBAL);
  }

  dl_extinfo extinfo = {
      .flag = DL_EXT_USE_RELRO | DL_EXT_RESERVED_ADDRESS_RECURSIVE |
              DL_EXT_RESERVED_ADDRESS,
      .relro_fd = relro_fd,
      .reserved_addr = gReservedAddress,
      .reserved_size = gReservedSize,
  };
  void *handle = dlopen_ns_ext(&dlns, lib, RTLD_NOW, &extinfo);
  close(relro_fd);
  if (handle == NULL) {
    int tmp_no = errno;
    WEBLOADER_LOGE("LoadWithRelroFile failed, use dlopen_ns, error=[%s]",
                   strerror(tmp_no));
    return dlopen_ns(&dlns, lib, RTLD_NOW | RTLD_GLOBAL);
  }

  return handle;
}
