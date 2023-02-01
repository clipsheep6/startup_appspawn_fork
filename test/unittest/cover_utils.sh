#!/bin/bash
# Copyright (c) 2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This Script used to push test data to devices
# Usage:
# ./prepare_testdata.sh path
# path is the rootdir of ohos projects.

function get_root_dir() {
    local cur_path=$(pwd)
    while [ "${cur_path}" != "" ]
    do
        cur_path=${cur_path%/*}
        if [ "${cur_path}" == "" ];then
            echo "[error] get code root dir fail"
            exit 1
        fi
        if [ "$(basename ${cur_path})" == "base" ]; then
            ohos_root=${cur_path%/*}
            return
        fi
    done
}

function hdc_shell_cmd() {
    # do nothing if there are not any arguments
    if [ $# -eq 0 ];then
        return;
    fi
    echo "Running command $@"
    hdc shell $@
}

function hdc_push_cmd() {
    # do nothing if there are not any arguments
    if [ $# -ne 2 ];then
        return;
    fi
    echo "Pushing resources to device"
    hdc file send $@
    sleep 0.2
}