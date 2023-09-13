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

from apps.backend.tests.agent import utils
from apps.node_man import constants, models

from . import test_agent


class FileSystemTestCase(utils.ProxyBaseTestCase, test_agent.FileSystemTestCase):
    pass


class BkRepoTestCase(FileSystemTestCase):
    pass


class AutoTypeStrategyCrontabTestCase(utils.AutoTypeStrategyMixin, FileSystemTestCase):
    pass


class AutoTypeStrategyDefaultTestCase(AutoTypeStrategyCrontabTestCase):
    AUTO_TYPE = constants.GseLinuxAutoType.RCLOCAL.value

    def setUp(self):
        super().setUp()
        models.GlobalSettings.objects.filter(key=models.GlobalSettings.KeyEnum.GSE2_LINUX_AUTO_TYPE.value).delete()


class AutoTypeStrategyDiffTestCase(AutoTypeStrategyCrontabTestCase):
    AUTO_TYPE_STRATEGY = {"gse_proxy": "crontab"}
    AUTO_TYPE = constants.GseLinuxAutoType.CRONTAB.value


class AutoTypeStrategyNotEffectTestCase(AutoTypeStrategyCrontabTestCase):
    AUTO_TYPE_STRATEGY = {"gse_agent": "crontab"}
    AUTO_TYPE = constants.GseLinuxAutoType.RCLOCAL.value
