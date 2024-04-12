#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2024 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import sys
from typing import List

sys.path.append(
    os.path.join(
        os.path.dirname(__file__),
        os.pardir,
        os.pardir,
        os.pardir,
        os.pardir,
        os.pardir,
        "build",
    )
)
from scripts.util import build_utils, file_utils  # noqa: E402


def merge(a: dict, b: dict, path: List[str] = []) -> dict:
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif isinstance(a[key], list) and isinstance(b[key], list):
                for item in b[key]:
                    if item not in a[key]:
                        a[key].append(item)
            elif a[key] != b[key]:
                raise Exception("Conflict at " + ".".join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a


class Parser(argparse.ArgumentParser):
    def __init__(self) -> None:
        super().__init__()
        self.add_argument(
            "sources",
            metavar="SOURCE_FILE",
            type=str,
            nargs="+",
            help="Sources JSON files",
        )
        self.add_argument(
            "--output",
            help="Result JSON filename",
            type=str,
            required=True,
        )
        self.add_argument(
            "--depfile",
            help="Path to depfile (refer to `gn help depfile`)",
            required=True,
        )

    class Options(argparse.Namespace):
        depfile: str
        output: str
        sources: List[str]

    def parse_args(self, args) -> Options:
        return super().parse_args(args, Parser.Options())


def merge_files(filenames: List[str], to_filename: str) -> None:
    dicts = [file_utils.read_json_file(filename) for filename in filenames]
    first = dicts[0]
    for other in dicts[1:]:
        first = merge(first, other)
    file_utils.write_json_file(output_file=to_filename, content=first)


def main(args: List[str]):
    parser = Parser()
    exargs = build_utils.expand_file_args(args)
    options = parser.parse_args(exargs)

    depfile_deps = options.sources
    merge_files(options.sources, options.output)
    build_utils.write_depfile(
        depfile_path=options.depfile,
        first_gn_output=options.output,
        inputs=depfile_deps,
        add_pydeps=False,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
