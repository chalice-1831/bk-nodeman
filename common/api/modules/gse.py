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

from django.utils.translation import ugettext_lazy as _

from ..base import BaseApi, DataAPI
from ..domains import GSE_APIGATEWAY_ROOT


class _GseApi(BaseApi):
    MODULE = _("管控平台")
    SIMPLE_MODULE = "GSE"

    def __init__(self):
        self.operate_proc = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "operate_proc_v2/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="进程操作",
            api_name="operate_proc",
        )
        self.operate_proc_multi = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "operate_proc_multi/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="批量进程操作",
            api_name="operate_proc_multi",
        )
        self.get_proc_operate_result = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "get_proc_operate_result_v2/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="查询进程操作结果",
            api_name="get_proc_operate_result",
        )
        self.get_proc_status = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "get_proc_status_v2/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="查询进程状态信息",
            api_name="get_proc_status",
        )
        self.sync_proc_status = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "sync_proc_status/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="同步进程状态信息",
            api_name="sync_proc_status",
        )
        self.update_proc_info = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "update_proc_info/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="更新进程信息",
            api_name="update_proc_info",
        )
        self.get_agent_info = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "get_agent_info/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="获取Agent版本信息",
            api_name="get_agent_info",
        )
        self.get_agent_status = DataAPI(
            method="POST",
            url=GSE_APIGATEWAY_ROOT + "get_agent_status/",
            module=self.MODULE,
            simple_module=self.SIMPLE_MODULE,
            description="获取Agent状态",
            api_name="get_agent_status",
        )
