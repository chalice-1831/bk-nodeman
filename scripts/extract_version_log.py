# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-节点管理(BlueKing-BK-NODEMAN) available.
Copyright (C) 2017-2022 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

import sys
from datetime import datetime
from pathlib import Path

import yaml

# 这段代码主要用于从特定的 YAML 文件中提取版本日志，并将这些日志写入到一个 Markdown 文件中。这个过程主要分为三个步骤：提取日志、写入版本日志和创建版本日志文件。

# 首先，我们看一下 extract_logs 函数。这个函数接受两个参数：log_yaml 和 version_logs。log_yaml 是一个打开的文件对象，指向一个包含日志的 YAML 文件。version_logs 是一个字典，用于存储从 YAML 文件中提取的日志。函数首先使用 yaml.load 方法加载 YAML 文件的内容，然后删除 "i18n" 键（如果存在）。然后，函数遍历加载的日志，如果某个部分（section）的内容存在，就将这些内容添加到 version_logs 字典中对应的部分。最后，函数返回更新后的 version_logs 字典。

# 在主程序部分，首先从命令行参数中获取版本号。然后，创建一个空的 version_logs 字典用于存储提取的日志。然后，程序遍历 dev_log/{version} 目录下的所有 YAML 文件，对每个文件调用 extract_logs 函数提取日志。这个过程对 .yaml 和 .yml 两种文件都进行了。

# 提取完日志后，程序打开 docs/release.md 文件，并读取所有的行到 lines 列表中。然后，程序遍历 version_logs 字典，将每个部分的日志格式化为 Markdown 格式的文本，并添加到 logs_text 字符串中。

# 然后，程序将 logs_text 字符串插入到 lines 列表的第二个元素（即 lines[1]），并在前面添加版本号和一些 Markdown 格式的文本。然后，程序将 lines 列表的内容写回到 docs/release.md 文件中。

# 最后，程序创建一个新的 Markdown 文件，文件名包含版本号和当前日期。然后，将 logs_text 字符串写入到这个新的文件中。这样，就完成了从 YAML 文件提取版本日志并写入到 Markdown 文件的过程。

def extract_logs(log_yaml, version_logs):
    logs = yaml.load(log_yaml, Loader=yaml.FullLoader)
    logs.pop("i18n", None)

    for section, contents in logs.items():
        if contents:
            version_logs.setdefault(section, []).extend(contents)

    return version_logs


if __name__ == "__main__":

    version = sys.argv[1]

    version_logs = {}

    # extract version log
    for fpath in Path(f"dev_log/{version}").glob("*.yaml"):
        with open(fpath) as log_file:
            extract_logs(log_file, version_logs)

    for fpath in Path(f"dev_log/{version}").glob("*.yml"):
        with open(fpath) as log_file:
            extract_logs(log_file, version_logs)

    # write version log
    with open("docs/release.md") as f:
        lines = f.readlines()

    logs_text = ""
    for section, content in version_logs.items():
        logs_text = "{logs}\n- {section}".format(logs=logs_text, section=section)
        for line in content:
            logs_text = "{logs}\n  - {line}".format(logs=logs_text, line=line)

    lines[1] = "\n## {version}\n{logs}\n\n".format(version=version, logs=logs_text)

    # write version logs to release
    with open("docs/release.md", "w") as f:
        for line in lines:
            f.write(line)

    # create version log file
    with open(
        "release/V{version}_{date}.md".format(version=version, date=datetime.now().strftime("%Y%m%d")),
        "w",
    ) as f:
        # "#" 号开头会被git commit 当做注释
        # logs_text = logs_text.replace("- feature", "## feature")
        # logs_text = logs_text.replace("- improvement", "## improvement")
        # logs_text = logs_text.replace("- bugfix", "## bugfix")
        f.write(logs_text)
