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

from __future__ import absolute_import, unicode_literals

import base64
import hashlib
import json
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Union

import six
from blueapps.account.decorators import login_exempt
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import EmptyPage, Paginator
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.translation import get_language
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from drf_yasg.utils import swagger_auto_schema
from rest_framework import mixins
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.backend import constants as backend_const
from apps.backend import exceptions
from apps.backend.constants import FilterFieldName
from apps.backend.plugin import serializers, tasks, tools
from apps.backend.plugin.handler import PluginHandler
from apps.backend.subscription.errors import (
    CreateSubscriptionTaskError,
    InstanceTaskIsRunning,
)
from apps.backend.subscription.handler import SubscriptionHandler
from apps.backend.subscription.tasks import run_subscription_task_and_create_instance
from apps.backend.subscription.tools import get_service_instances
from apps.core.files import core_files_constants
from apps.core.files.storage import get_storage
from apps.exceptions import AppBaseException, ValidationError
from apps.generic import APIViewSet
from apps.node_man import constants, models
from apps.node_man.exceptions import HostNotExists, ServiceInstanceNotFoundError
from pipeline.engine.exceptions import InvalidOperationException
from pipeline.service import task_service
from pipeline.service.pipeline_engine_adapter.adapter_api import STATE_MAP

LOG_PREFIX_RE = re.compile(r"(\[\d{4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}.*?\] )")
logger = logging.getLogger("app")


PLUGIN_VIEW_TAGS = ["backend_plugin"]


class PluginViewSet(APIViewSet, mixins.RetrieveModelMixin, mixins.ListModelMixin):
    """
    插件相关API
    """

    queryset = ""

    # permission_classes = (BackendBasePermission,)
    @swagger_auto_schema(
        operation_summary="创建注册任务",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(
        detail=False,
        methods=["POST"],
        url_path="create_register_task",
        serializer_class=serializers.PluginRegisterSerializer,
    )
    def create_plugin_register_task(self, request):
        """
        @api {POST} /plugin/create_register_task/ 创建注册任务
        @apiName create_register_task
        @apiGroup backend_plugin
        @apiParam {String} file_name 文件名
        @apiParam {Boolean} is_release 是否已发布
        @apiParam {Boolean} [is_template_load] 是否需要读取配置文件，缺省默认为`false`
        @apiParam {Boolean} [is_template_overwrite] 是否可以覆盖已经存在的配置文件，缺省默认为`false`
        @apiParam {List} [select_pkg_abs_paths] 指定注册包相对路径列表，缺省默认全部导入
        @apiParamExample {Json} 请求参数
        {
            "file_name": "bkunifylogbeat-7.1.28.tgz",
            "is_release": True,
            "select_pkg_abs_paths": ["bkunifylogbeat_linux_x86_64/bkunifylogbeat"]
        }
        @apiSuccessExample {json} 成功返回:
        {
            "job_id": 1
        }
        """
        params = self.validated_data
        file_name = params["file_name"]

        # 1. 判断是否存在需要注册的文件信息
        models_queryset = models.UploadPackage.objects.filter(file_name=file_name)
        if not models_queryset.exists():
            raise exceptions.FileNotExistError(_("找不到请求发布的文件，请确认后重试"))

        # 2. 创建一个新的task,返回任务ID
        job = models.Job.objects.create(
            created_by=params["bk_username"],
            from_system=settings.APP_CODE,
            job_type=constants.JobType.PACKING_PLUGIN,
            # TODO 打包任务是否也用一次性订阅的方式下发
            subscription_id=-1,
            status=constants.JobStatusType.RUNNING,
        )
        # 这个新的任务，应该是指派到自己机器上的打包任务
        tasks.package_task.delay(job.id, params)
        logger.info(
            "create job-> {job_id} to unpack file-> {file_name} plugin".format(job_id=job.id, file_name=file_name)
        )

        return Response({"job_id": job.id})

    @swagger_auto_schema(
        operation_summary="查询插件注册任务",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(
        detail=False,
        methods=["GET"],
        url_path="query_register_task",
        serializer_class=serializers.PluginRegisterTaskSerializer,
    )
    def query_plugin_register_task(self, request):
        """
        @api {GET} /plugin/query_register_task/ 查询插件注册任务
        @apiName query_register_task
        @apiGroup backend_plugin
        @apiParam {Int} job_id 任务ID
        @apiParamExample {Json} 请求参数
        {
            "job_id": 1
        }
        @apiSuccessExample {json} 成功返回:
        {
            "is_finish": False,
            "status": "RUNNING",
            "message": "~",
        }
        """
        params = self.validated_data
        job_id = params["job_id"]

        # 寻找这个任务对应的job_task
        try:
            job = models.Job.objects.get(id=job_id)

        except models.Job.DoesNotExist:
            logger.error("user try to query job->[%s] but is not exists." % job_id)
            raise exceptions.JobNotExistError(_("找不到请求的任务，请确认后重试"))

        return Response(
            {
                "is_finish": job.status in [constants.JobStatusType.SUCCESS, constants.JobStatusType.FAILED],
                "status": job.status,
                "message": job.global_params.get("err_msg"),
            }
        )

    @swagger_auto_schema(
        operation_summary="查询插件信息",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["GET"], serializer_class=serializers.PluginInfoSerializer)
    def info(self, request):
        """
        @api {GET} /plugin/info/ 查询插件信息
        @apiName query_plugin_info
        @apiGroup backend_plugin
        """
        package_infos = PluginHandler.fetch_package_infos(
            project=self.validated_data["name"],
            pkg_version=self.validated_data.get("version"),
            os_type=self.validated_data.get("os"),
            cpu_arch=self.validated_data.get("cpu_arch"),
        )

        for package_info in package_infos:
            # 历史遗留原因，创建人 & app_code 采用回填的方式返回
            package_info.update(
                creator=self.validated_data["bk_username"],
                source_app_code=self.validated_data["bk_app_code"],
            )

        return Response(package_infos)

    @swagger_auto_schema(
        operation_summary="发布插件包",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.ReleasePluginSerializer)
    def release(self, request):
        """
        @api {POST} /plugin/release/ 发布（上线）插件包
        @apiName release_package
        @apiGroup backend_plugin
        @apiParam {Int[]} [id] 插件包id列表，`id`和（`name`, `version`）至少有一个
        @apiParam {String} [name] 插件包名称
        @apiParam {String} [version] 版本号
        @apiParam {String} [cpu_arch] CPU类型，`x86` `x86_64` `powerpc`
        @apiParam {String} [os] 系统类型，`linux` `windows` `aix`
        @apiParam {String[]} [md5_list] md5列表
        @apiParamExample {Json} 请求参数
        {
        }
        @apiSuccessExample {json} 返回上线的插件包id列表:
        [1, 2, 4]
        """
        params = self.validated_data
        operator = params.pop("bk_username")
        params.pop("bk_app_code")

        try:
            if "id" in params:
                plugin_packages = models.GsePluginDesc.list_packages(
                    md5_list=params["md5_list"], package_ids=params["id"]
                )
            else:
                plugin_packages = models.GsePluginDesc.list_packages(
                    md5_list=params.pop("md5_list"), query_params=params
                )
        except ValueError as e:
            raise ValidationError(e)

        # 检查当前插件包是否启用，没有启用不允许上下线
        not_ready_pkgs = plugin_packages.filter(is_ready=False)
        if not_ready_pkgs.exists():
            raise exceptions.PackageStatusOpError(
                _("ID{ids}的插件包未启用，无法执行更改状态操作").format(ids=[pkg.id for pkg in not_ready_pkgs])
            )
        # 更新状态及操作人
        plugin_packages.update(is_release_version=True, creator=operator)
        return Response([package.id for package in plugin_packages])

    @swagger_auto_schema(
        operation_summary="插件包状态类操作",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.PkgStatusOperationSerializer)
    def package_status_operation(self, request):
        """
        @api {POST} /plugin/package_status_operation/ 插件包状态类操作
        @apiName package_status_operation
        @apiGroup backend_plugin
        @apiParam {String} operation 状态操作 `release`-`上线`，`offline`-`下线` `ready`-`启用`，`stop`-`停用`
        @apiParam {Int[]} [id] 插件包id列表，`id`和（`name`, `version`）至少有一个
        @apiParam {String} [name] 插件包名称
        @apiParam {String} [version] 版本号
        @apiParam {String} [cpu_arch] CPU类型，`x86` `x86_64` `powerpc`
        @apiParam {String} [os] 系统类型，`linux` `windows` `aix`
        @apiParam {String[]} [md5_list] md5列表
        @apiParamExample {Json} 请求参数
        {
        }
        @apiSuccessExample {json} 返回操作成功的插件包id列表:
        [1, 2, 4]
        """
        params = self.validated_data
        status_field_map = {
            constants.PkgStatusOpType.release: {"is_release_version": True, "is_ready": True},
            constants.PkgStatusOpType.offline: {"is_release_version": False, "is_ready": True},
            constants.PkgStatusOpType.stop: {"is_ready": False},
        }
        operator = params.pop("bk_username")
        params.pop("bk_app_code")
        operation = params.pop("operation")
        md5_list = params.pop("md5_list")
        try:
            if "id" in params:
                plugin_packages = models.GsePluginDesc.list_packages(md5_list=md5_list, package_ids=params["id"])
            else:
                plugin_packages = models.GsePluginDesc.list_packages(md5_list=md5_list, query_params=params)
        except ValueError as e:
            raise ValidationError(e)
        # 更新状态及操作人
        plugin_packages.update(**status_field_map[operation], creator=operator)
        return Response([package.id for package in plugin_packages])

    @swagger_auto_schema(
        operation_summary="删除插件",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.DeletePluginSerializer)
    def delete(self, request):
        """
        @api {POST} /plugin/delete/ 删除插件
        @apiName delete_plugin
        @apiGroup backend_plugin
        """
        # TODO: 完成采集配置后需要添加检测逻辑
        params = self.validated_data
        params.pop("bk_username")
        params.pop("bk_app_code")
        name = params["name"]

        models.GsePluginDesc.objects.filter(name=name).delete()
        packages = models.Packages.objects.filter(project=name)
        for package in packages:
            file_path = os.path.join(package.pkg_path, package.pkg_name)
            if os.path.exists(file_path):
                os.remove(file_path)

        packages.delete()
        models.ProcControl.objects.filter(project=name).delete()
        plugin_templates = models.PluginConfigTemplate.objects.filter(plugin_name=name)
        models.PluginConfigInstance.objects.filter(
            plugin_config_template__in=[template.id for template in plugin_templates]
        ).delete()

        return Response()

    @swagger_auto_schema(
        operation_summary="创建配置模板",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.CreatePluginConfigTemplateSerializer)
    def create_config_template(self, request):
        """
        @api {POST} /plugin/create_config_template/ 创建配置模板,未指定则创建全部平台类型
        @apiName create_plugin_config_template
        @apiGroup backend_plugin
        """
        params = self.validated_data
        bk_username = params.pop("bk_username")
        bk_app_code = params.pop("bk_app_code")

        created_template_ids = []
        template_os_list = [params["os"]] if params.get("os") else [os_type for os_type in constants.OS_TUPLE]
        template_cpu_arch_list = (
            [params["cpu_arch"]] if params.get("cpu_arch") else [cpu_arch for cpu_arch in constants.CPU_TUPLE]
        )

        for os_type in template_os_list:
            for cpu_arch in template_cpu_arch_list:
                plugin, created = models.PluginConfigTemplate.objects.update_or_create(
                    plugin_name=params["plugin_name"],
                    plugin_version=params["plugin_version"],
                    name=params["name"],
                    version=params["version"],
                    os=os_type.lower(),
                    cpu_arch=cpu_arch.lower(),
                    defaults=dict(
                        plugin_name=params["plugin_name"],
                        plugin_version=params["plugin_version"],
                        name=params["name"],
                        version=params["version"],
                        format=params["format"],
                        content=params["content"],
                        file_path=params["file_path"],
                        is_release_version=params["is_release_version"],
                        os=os_type.lower(),
                        cpu_arch=cpu_arch.lower(),
                        creator=bk_username,
                        source_app_code=bk_app_code,
                    ),
                )
                created_template_ids.append(plugin.id)
        params["ids"] = created_template_ids

        return Response(params)

    @swagger_auto_schema(
        operation_summary="发布配置模板",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.ReleasePluginConfigTemplateSerializer)
    def release_config_template(self, request):
        """
        @api {POST} /plugin/release_config_template/ 发布配置模板
        @apiName release_plugin_config_template
        @apiGroup backend_plugin
        """
        params = self.validated_data
        bk_username = params.pop("bk_username")
        bk_app_code = params.pop("bk_app_code")

        if "id" in params:
            plugin_templates = models.PluginConfigTemplate.objects.filter(id__in=params["id"])
        else:
            plugin_templates = models.PluginConfigTemplate.objects.filter(**params)

        # 更改发布状态
        plugin_templates.update(is_release_version=True)

        result = []
        for template in plugin_templates:
            result.append(
                dict(
                    id=template.id,
                    plugin_name=template.plugin_name,
                    plugin_version=template.plugin_version,
                    name=template.name,
                    version=template.version,
                    format=template.format,
                    file_path=template.file_path,
                    is_release_version=template.is_release_version,
                    creator=bk_username,
                    content=template.content,
                    source_app_code=bk_app_code,
                )
            )

        return Response(result)

    @swagger_auto_schema(
        operation_summary="渲染配置模板",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.RenderPluginConfigTemplateSerializer)
    def render_config_template(self, request):
        """
        @api {POST} /plugin/render_config_template/ 渲染配置模板
        @apiName render_plugin_config_template
        @apiGroup backend_plugin
        """
        params = self.validated_data
        bk_username = params.pop("bk_username")
        bk_app_code = params.pop("bk_app_code")
        data = params.pop("data")

        try:
            if "id" in params:
                plugin_template = models.PluginConfigTemplate.objects.get(id=params["id"])
            else:
                plugin_template = models.PluginConfigTemplate.objects.get(**tools.add_default_platform(params))
        except models.PluginConfigTemplate.DoesNotExist:
            raise ValidationError("plugin template not found")

        instance = plugin_template.create_instance(data, bk_username, bk_app_code)

        return Response(
            dict(
                id=instance.id,
                md5=instance.data_md5,
                creator=instance.creator,
                source_app_code=instance.source_app_code,
            )
        )

    @swagger_auto_schema(
        operation_summary="查询配置模板",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["GET"], serializer_class=serializers.PluginConfigTemplateInfoSerializer)
    def query_config_template(self, request):
        """
        @api {GET} /plugin/query_config_template/ 查询配置模板
        @apiName query_plugin_config_template
        @apiGroup backend_plugin
        """
        params = self.validated_data
        params.pop("bk_username")
        params.pop("bk_app_code")

        if "id" in params:
            plugin_templates = models.PluginConfigTemplate.objects.filter(id=params["id"])
        else:
            plugin_templates = models.PluginConfigTemplate.objects.filter(**tools.add_default_platform(params))

        result = []
        for template in plugin_templates:
            result.append(
                dict(
                    id=template.id,
                    plugin_name=template.plugin_name,
                    plugin_version=template.plugin_version,
                    name=template.name,
                    version=template.version,
                    format=template.format,
                    path=template.file_path,
                    is_release_version=template.is_release_version,
                    creator=template.creator,
                    content=base64.b64encode(template.content),
                    source_app_code=template.source_app_code,
                )
            )

        return Response(result)

    @swagger_auto_schema(
        operation_summary="查询配置模板实例",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["GET"], serializer_class=serializers.PluginConfigInstanceInfoSerializer)
    def query_config_instance(self, request):
        """
        @api {GET} /plugin/query_config_instance/ 查询配置模板实例
        @apiName query_plugin_config_instance
        @apiGroup backend_plugin
        """
        params = self.validated_data
        params.pop("bk_username")
        params.pop("bk_app_code")

        if "id" in params:
            plugin_instances = models.PluginConfigInstance.objects.filter(id=params["id"])
        else:
            plugin_templates = models.PluginConfigTemplate.objects.filter(**tools.add_default_platform(params))
            plugin_instances = models.PluginConfigInstance.objects.filter(
                plugin_config_template__in=[template.id for template in plugin_templates]
            )

        result = []

        for instance in plugin_instances:
            base64_content = base64.b64encode(instance.content)
            md5_client = hashlib.md5()
            md5_client.update(instance.content)
            md5 = md5_client.hexdigest()

            result.append(
                dict(
                    id=instance.id,
                    content=base64_content,
                    md5=md5,
                    creator=instance.creator,
                    source_app_code=instance.source_app_code,
                )
            )

        return Response(result)

    @swagger_auto_schema(
        operation_summary="开始调试",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.PluginStartDebugSerializer)
    def start_debug(self, request):
        """
        @api {POST} /plugin/start_debug/ 开始调试
        @apiName start_debug
        @apiGroup backend_plugin
        """
        params = self.validated_data
        object_type: str = params["object_type"]
        node_type: str = params["node_type"]

        host_info: Optional[Dict[str, Union[int, str]]] = params.get("host_info")
        instance_info: Optional[Dict[str, Union[int, str]]] = params.get("instance_info")

        if host_info:
            if host_info.get("bk_host_id"):
                query_host_params: Dict[str, Union[str, int]] = {
                    "bk_biz_id": host_info["bk_biz_id"],
                    "bk_host_id": host_info["bk_host_id"],
                }
            else:
                # 仅支持静态寻址的主机使用 管控区域 + IP
                query_host_params: Dict[str, Union[str, int]] = {
                    "bk_biz_id": host_info["bk_biz_id"],
                    "inner_ip": host_info["ip"],
                    "bk_cloud_id": host_info["bk_cloud_id"],
                    "bk_addressing": constants.CmdbAddressingType.STATIC.value,
                }
            bk_biz_id: int = host_info["bk_biz_id"]
            node: Dict[str, Union[int, str]] = host_info
        else:
            bk_biz_id: int = instance_info["bk_biz_id"]
            service_instance_id: Optional[int] = instance_info["id"]
            service_instance_result: List[Dict[str, Any]] = get_service_instances(
                bk_biz_id=instance_info["bk_biz_id"],
                filter_id_list=[service_instance_id],
                filter_field_name=FilterFieldName.SERVICE_INSTANCE_IDS,
                ignore_exception=False,
            )
            try:
                bk_host_id: int = service_instance_result[0]["bk_host_id"]
            except Exception:
                raise ServiceInstanceNotFoundError(id=service_instance_id)
            query_host_params: Dict[str, int] = {"bk_biz_id": bk_biz_id, "bk_host_id": bk_host_id}
            node: Dict[str, int] = {"id": service_instance_id}

        try:
            host: models.Host = models.Host.objects.get(**query_host_params)
        except models.Host.DoesNotExist:
            raise HostNotExists("host does not exist")

        plugin_id: Optional[int] = params.get("plugin_id")
        if plugin_id:
            try:
                package: Optional[int] = models.Packages.objects.get(id=plugin_id)
            except models.Packages.DoesNotExist:
                raise exceptions.PluginNotExistError()
        else:
            os_type: str = host.os_type.lower()
            cpu_arch: str = host.cpu_arch
            try:
                package: models.Packages = models.Packages.objects.get(
                    project=params["plugin_name"], version=params["version"], os=os_type, cpu_arch=cpu_arch
                )
            except models.Packages.DoesNotExist:
                raise exceptions.PluginNotExistError(
                    plugin_name=params["plugin_name"], os_type=os_type, cpu_arch=cpu_arch
                )

        if not package.is_ready:
            raise ValidationError("plugin is not ready")

        configs: Dict[str, Any] = models.PluginConfigInstance.objects.in_bulk(params["config_ids"])

        # 渲染配置文件
        step_config_templates: List[Dict[str, str]] = []
        step_params_context = {}
        for config_id in params["config_ids"]:
            config = configs.get(config_id)
            if not config:
                raise ValidationError("config {} does not exist".format(config_id))
            config_template = config.template
            if config_template.plugin_name != package.project:
                raise ValidationError("config {} does not belong to plugin {}".format(config_id, package.project))

            step_config_templates.append({"version": config_template.version, "name": config_template.name})
            step_params_context.update(json.loads(config.render_data))

        with transaction.atomic():
            subscription: models.Subscription = models.Subscription.objects.create(
                bk_biz_id=bk_biz_id,
                object_type=object_type,
                node_type=node_type,
                nodes=[node],
                enable=False,
                is_main=params.get("is_main", False),
                creator=request.user.username,
                category=models.Subscription.CategoryType.DEBUG,
            )

            # 创建订阅步骤
            models.SubscriptionStep.objects.create(
                subscription_id=subscription.id,
                step_id=package.project,
                type="PLUGIN",
                config={
                    "config_templates": step_config_templates,
                    "plugin_version": package.version,
                    "plugin_name": package.project,
                    "job_type": "DEBUG_PLUGIN",
                },
                params={"context": step_params_context},
            )
            subscription_task: models.SubscriptionTask = models.SubscriptionTask.objects.create(
                subscription_id=subscription.id, scope=subscription.scope, actions={}
            )

            if subscription.is_running():
                raise InstanceTaskIsRunning()
            run_subscription_task_and_create_instance.delay(subscription, subscription_task, language=get_language())
            if subscription_task.err_msg:
                raise CreateSubscriptionTaskError(err_msg=subscription_task.err_msg)

        return Response({"task_id": subscription_task.id})

    @swagger_auto_schema(
        operation_summary="停止调试",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"])
    def stop_debug(self, request):
        """
        @api {POST} /plugin/stop_debug/ 停止调试
        @apiName stop_debug
        @apiGroup backend_plugin
        """
        task_id = request.data["task_id"]

        try:
            task = models.SubscriptionTask.objects.get(pk=task_id)
            subscription = models.Subscription.objects.get(pk=task.subscription_id)
            step = models.SubscriptionStep.objects.get(subscription_id=task.subscription_id)
            pipeline_id = task.pipeline_id
            status = task_service.get_state(pipeline_id)
            is_finished = status["state"] == STATE_MAP["FINISHED"]
            is_running = status["state"] == STATE_MAP["RUNNING"]
        except (ObjectDoesNotExist, InvalidOperationException):
            # 不存在的直接跳过
            return Response()

        # 结束则忽略，只撤销正在运行的队列
        if is_finished:
            logger.info(f"plugin debug task has been finished, task_id: {task_id}")

        if is_running:
            revoke_result = task_service.revoke_pipeline(pipeline_id)
            if revoke_result.result:
                logger.info(f"plugin debug task has been revoked, pipeline id: {pipeline_id}")
            else:
                logger.error(f"plugin debug task revoke failed, pipeline id: {pipeline_id}")

            config = step.config
            config["job_type"] = backend_const.ActionNameType.STOP_DEBUG_PLUGIN
            step.config = config
            step.save()
            run_subscription_task_and_create_instance.delay(subscription, task, language=get_language())
        return Response()

    @swagger_auto_schema(
        operation_summary="查询调试结果",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["GET"])
    def query_debug(self, request):
        """
        @api {GET} /plugin/query_debug/ 查询调试结果
        @apiName query_debug
        @apiGroup backend_plugin
        """
        task_id = int(request.query_params["task_id"])
        task = models.SubscriptionTask.objects.get(pk=task_id)
        subscription_handler = SubscriptionHandler(subscription_id=task.subscription_id)
        if not subscription_handler.check_task_ready([task.id]):
            return Response({"status": constants.JobStatusType.PENDING, "step": "preparing", "message": _("调试任务准备中")})

        task_result = subscription_handler.task_result(task_id_list=[task_id], need_detail=True)
        try:
            steps = task_result[0]["steps"][0]["target_hosts"][0]["sub_steps"]
        except (IndexError, KeyError, TypeError):
            raise AppBaseException("查询调试结果错误")
        log_content = []
        status = constants.JobStatusType.RUNNING
        step_name = ""
        for step in steps:
            log_content.append(_(" 开始{name} ").format(name=step["node_name"]).center(30, "*"))
            # debug 的日志，由于监控需要解析日志内容，因此这里把 [1900-01-01 00:00:00 INFO] 这些时间去掉
            cleaned_log = re.sub(LOG_PREFIX_RE, "", step["log"])
            log_content.append(cleaned_log)
            status = step["status"]
            step_name = step["step_code"]
            if status in (constants.JobStatusType.PENDING, constants.JobStatusType.RUNNING):
                # PENDING 状态也转为 RUNNING
                status = constants.JobStatusType.RUNNING
                break

        return Response({"status": status, "step": step_name, "message": "\n".join(log_content)})

    @swagger_auto_schema(
        operation_summary="触发插件打包导出",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.ExportSerializer)
    def create_export_task(self, request):
        """
        @api {POST} /plugin/create_export_task/ 触发插件打包导出
        @apiName create_export_plugin_task
        @apiGroup backend_plugin
        @apiParam {Object} query_params 插件信息，version, project, os[可选], cpu_arch[可选]
        @apiParam {String} category 插件类别
        @apiParam {String} creator 创建者
        @apiParam {String} bk_app_code
        @apiParamExample {Json} 请求参数
        {
            "category": "gse_plugin",
            "query_params": {
                "project": "test_plugin",
                "version": "1.0.0"
            },
            "creator": "test_person",
            "bk_app_code": "bk_test_app"
        }
        @apiSuccessExample {json} 成功返回:
        {
            "job_id": 1
        }
        """

        params = self.validated_data

        if "os" in params["query_params"]:
            params["query_params"]["os_type"] = params["query_params"].pop("os")

        record = models.DownloadRecord.create_record(
            category=params["category"],
            query_params=params["query_params"],
            creator=params["bk_username"],
            source_app_code=params["bk_app_code"],
        )
        logger.info(
            "user -> {username} request to export from system -> {bk_app_code} success created "
            "record -> {record_id}.".format(
                username=params["bk_username"], bk_app_code=params["bk_app_code"], record_id=record.id
            )
        )

        tasks.export_plugin.delay(record.id)
        logger.info("record-> {record_id} now is active to celery".format(record_id=record.id))

        return Response({"job_id": record.id})

    @swagger_auto_schema(
        operation_summary="获取一个导出任务结果",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["GET"])
    def query_export_task(self, request):
        """
        @api {GET} /plugin/query_export_task/ 获取一个导出任务结果
        @apiName query_export_plugin_task
        @apiGroup backend_plugin
        @apiParam {Int} job_id 任务ID
        @apiParamExample {Json} 请求参数
        {
            "job_id": 1
        }
        @apiSuccessExample {json} 成功返回:
        {
            "is_finish": True,
            "is_failed": False,
            "download_url": "http://127.0.0.1//backend/export/download/",
            "error_message": "haha"
        }
        """
        # 及时如果拿到None的job_id，也可以通过DB查询进行防御
        job_id = request.GET.get("job_id")

        try:
            record = models.DownloadRecord.objects.get(id=job_id)
        except models.DownloadRecord.DoesNotExist:
            logger.error("record-> {record_id} not exists, something go wrong?".format(record_id=job_id))
            raise ValueError(_("请求任务不存在，请确认后重试"))

        if record.is_failed or not record.file_path:
            download_url = ""
        else:
            # TODO: 此处后续需要提供一个统一的 storage.tmp_url(name) 方法，用于插件包的临时下载
            if settings.STORAGE_TYPE in core_files_constants.StorageType.list_cos_member_values():
                download_url = get_storage().url(record.file_path)
            else:
                download_url = "?".join([settings.BKAPP_NODEMAN_DOWNLOAD_API, record.download_params])

        response_data = {
            "is_finish": record.is_finish,
            "is_failed": record.is_failed,
            "download_url": download_url,
            "error_message": record.error_message,
        }

        logger.info(
            "export record -> {record_id} response_data -> {response_data}".format(
                record_id=job_id, response_data=response_data
            )
        )
        return Response(response_data)

    @swagger_auto_schema(
        operation_summary="解析插件包",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.PluginParseSerializer)
    def parse(self, request):
        """
        @api {POST} /plugin/parse/ 解析插件包
        @apiName plugin_parse
        @apiGroup backend_plugin
        @apiParam {String} file_name 文件名
        @apiParam {String} [is_update] 是否为更新校验，默认为`False`
        @apiParamExample {Json} 请求参数
        {
            "file_name": "basereport-10.1.12.tgz"
        }
        @apiSuccessExample {json} 成功返回:
        [
            {
                "result": True,
                "message": "新增插件",
                "pkg_abs_path": "basereport_linux_x86_64/basereport",
                "pkg_name": "basereport-10.1.12",
                "project": "basereport",
                "version": "10.1.12",
                "category": "官方插件",
                "config_templates": [
                    {"name": "child1.conf", "version": "1.0", "is_main": false},
                    {"name": "child2.conf", "version": "1.1", "is_main": false},
                    {"name": "basereport-main.config", "version": "0.1", "is_main": true}
                ],
                "os": "x86_64",
                "cpu_arch": "linux",
                "description": "高性能日志采集"
            },
            {
                "result": False,
                "message": "缺少project.yaml文件",
                "pkg_abs_path": "external_bkmonitorbeat_windows_x32/bkmonitorbeat",
                "pkg_name": None,
                "project": None,
                "version": None,
                "category": None,
                "config_templates": [],
                "os": "x32",
                "cpu_arch": "windows",
                "description": None
            },
        ]
        """
        params = self.validated_data
        upload_package_obj = (
            models.UploadPackage.objects.filter(file_name=params["file_name"]).order_by("-upload_time").first()
        )
        if upload_package_obj is None:
            raise exceptions.FileNotExistError(_("找不到请求发布的文件，请确认后重试"))

        # 获取插件中各个插件包的路径信息
        package_infos = tools.list_package_infos(file_path=upload_package_obj.file_path)
        # 解析插件包
        pkg_parse_results = []
        for package_info in package_infos:
            pkg_parse_result = tools.parse_package(
                pkg_absolute_path=package_info["pkg_absolute_path"],
                package_os=package_info["package_os"],
                cpu_arch=package_info["cpu_arch"],
                is_update=params["is_update"],
            )
            pkg_parse_result.update(
                {
                    "pkg_abs_path": package_info["pkg_relative_path"],
                    # parse_package 对 category 执行校验并返回错误信息，此处category不一定是合法值，所以使用get填充释义
                    "category": constants.CATEGORY_DICT.get(pkg_parse_result["category"]),
                }
            )
            pkg_parse_results.append(pkg_parse_result)

        # 清理临时解压目录
        plugin_tmp_dirs = set([package_info["plugin_tmp_dir"] for package_info in package_infos])
        for plugin_tmp_dir in plugin_tmp_dirs:
            shutil.rmtree(plugin_tmp_dir)
        return Response(pkg_parse_results)

    @swagger_auto_schema(
        operation_summary="查询插件列表",
        tags=PLUGIN_VIEW_TAGS,
    )
    def list(self, request, *args, **kwargs):
        """
        @api {GET} /plugin/ 插件列表
        @apiName list_plugin
        @apiGroup backend_plugin
        @apiParam {String} [search] 插件别名&名称模糊搜索
        @apiParam {Boolean} [simple_all] 返回全部数据（概要信息，`id`, `description`, `name`），默认`False`
        @apiParam {Int} [page] 当前页数，默认`1`
        @apiParam {Int} [pagesize] 分页大小，默认`10`
        @apiParam {object} [sort] 排序
        @apiParam {String=["name", "category", "creator", "scenario", "description"]} [sort.head] 排序字段
        @apiParam {String=["ASC", "DEC"]} [sort.sort_type] 排序类型
        @apiParamExample {Json} 请求参数
        {
        }
        @apiSuccessExample {json} 成功返回:
        {
            "total": 2,
            "list": [
                {
                    "id": 1,
                    "description": "系统基础信息采集",
                    "name": "basereport",
                    "category": "官方插件",
                    "source_app_code": "bk_nodeman",
                    "scenario": "CMDB上的实时数据，蓝鲸监控里的主机监控，包含CPU，内存，磁盘等",
                    "deploy_type": "整包部署"
                },
                {
                    "id": 2,
                    "description": "监控采集器",
                    "name": "bkmonitorbeat",
                    "category": "第三方插件",
                    "source_app_code": "bk_monitor",
                    "scenario": "蓝鲸监控采集器，支持多种协议及多任务的采集，提供多种运行模式和热加载机制",
                    "deploy_type": "Agent自动部署"
                }
            ]
        }
        """
        self.serializer_class = serializers.PluginListSerializer
        query_params = self.validated_data
        gse_plugin_desc_qs = models.GsePluginDesc.objects.filter(category=constants.CategoryType.official).order_by(
            "-is_ready"
        )
        if "search" in query_params:
            gse_plugin_desc_qs = gse_plugin_desc_qs.filter(
                Q(description__contains=query_params["search"])
                | Q(name__contains=query_params["search"])
                | Q(description_en__contains=query_params["search"])
            )

        if "sort" in query_params:
            sort_head = query_params["sort"]["head"]
            if query_params["sort"]["sort_type"] == constants.SortType.DEC:
                gse_plugin_desc_qs = gse_plugin_desc_qs.order_by(f"-{sort_head}")
            else:
                gse_plugin_desc_qs = gse_plugin_desc_qs.order_by(sort_head)

        locale_fields = tools.locale_fields()
        # 返回插件概要信息
        if query_params["simple_all"]:
            ret_plugins = list(gse_plugin_desc_qs.values("id", locale_fields["description"], "name", "is_ready"))
            for ret_plugin in ret_plugins:
                ret_plugin["description"] = ret_plugin[locale_fields["description"]]
            return Response({"total": len(ret_plugins), "list": ret_plugins})

        plugins = list(
            gse_plugin_desc_qs.values(
                "id",
                locale_fields["description"],
                locale_fields["scenario"],
                "name",
                "category",
                "source_app_code",
                "deploy_type",
                "is_ready",
            )
        )

        try:
            # 分页
            paginator = Paginator(plugins, query_params["pagesize"])
            ret_plugins = paginator.page(query_params["page"]).object_list
            for ret_plugin in ret_plugins:
                ret_plugin["scenario"] = ret_plugin[locale_fields["scenario"]]
                ret_plugin["description"] = ret_plugin[locale_fields["description"]]
        except EmptyPage:
            return Response({"total": len(plugins), "list": []})

        return Response({"total": len(plugins), "list": ret_plugins})

    @swagger_auto_schema(
        operation_summary="插件详情",
        tags=PLUGIN_VIEW_TAGS,
    )
    def retrieve(self, request, *args, **kwargs):
        """
        @api {GET} /plugin/{{pk}}/ 插件详情
        @apiName retrieve_plugin
        @apiGroup backend_plugin
        @apiParamExample {Json} 请求参数
        {
        }
        @apiSuccessExample {json} 成功返回:
        {
            "id": 1,
            "description": "系统基础信息采集",
            "name": "basereport",
            "category": "官方插件",
            "source_app_code": "bk_nodeman",
            "scenario": "CMDB上的实时数据，蓝鲸监控里的主机监控，包含CPU，内存，磁盘等",
            "deploy_type": "整包部署",
            "plugin_packages": [
                {
                    "id": 1,
                    "pkg_name": "basereport-10.1.12.tgz",
                    "module": "gse_plugin",
                    "project": "basereport",
                    "version": "10.1.12",
                    "config_templates": [
                        {"id": 1, "name": "basereport.conf", "version": "10.1", "is_main": true}
                    ],
                    "os": "linux",
                    "cpu_arch": "x86_64",
                    "support_os_cpu": "linux_x86_64",
                    "pkg_mtime": "2019-11-25 21:58:30",
                    "creator": "test_person",
                    "is_ready": True
                },
                {
                    "id": 2,
                    "pkg_name": "bkmonitorbeat-1.7.1.tgz",
                    "module": "gse_plugin",
                    "project": "bkmonitorbeat",
                    "version": "1.7.1",
                    "config_templates": [
                        {"id": 1, "name": "child1.conf", "version": "1.0", "is_main": false},
                        {"id": 2, "name": "child2.conf", "version": "1.1", "is_main": false},
                        {"id": 3, "name": "bkmonitorbeat.conf", "version": "0.1", "is_main": true}
                    ],
                    "os": "windows",
                    "cpu_arch": "x86",
                    "support_os_cpu": "windows_x86",
                    "pkg_mtime": "2019-11-25 21:58:30",
                    "creator": "test_person",
                    "is_ready": True
                }
            ]
        }
        """
        return Response(PluginHandler.retrieve(kwargs["pk"]))

    @swagger_auto_schema(
        operation_summary="插件状态类操作",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.PluginStatusOperationSerializer)
    def plugin_status_operation(self, request):
        """
        @api {POST} /plugin/plugin_status_operation/ 插件状态类操作
        @apiName plugin_status_operation
        @apiGroup backend_plugin
        @apiParam {String} operation 状态操作 `ready`-`启用`，`stop`-`停用`
        @apiParam {Int[]} id 插件id列表
        @apiParamExample {Json} 请求参数
        {
            "operation": "stop",
            "id": [1, 2]
        }
        @apiSuccessExample {json} 返回操作成功的插件id列表:
        [1, 2]
        """
        params = self.validated_data
        status_field_map = {
            constants.PluginStatusOpType.ready: {"is_ready": True},
            constants.PluginStatusOpType.stop: {"is_ready": False},
        }
        update_plugins = models.GsePluginDesc.objects.filter(id__in=params["id"])
        update_plugins.update(**status_field_map[params["operation"]])
        return Response([plugin.id for plugin in update_plugins])

    @swagger_auto_schema(
        operation_summary="查询插件包历史",
        methods=["GET"],
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=True, methods=["GET", "POST"], serializer_class=serializers.PluginQueryHistorySerializer)
    def history(self, request, pk):
        """
        @api {GET} /plugin/{{pk}}/history/ 插件包历史
        @apiName plugin_history
        @apiGroup backend_plugin
        @apiParam {String} [os] 系统类型，`windows` `linux` `aix`
        @apiParam {String} [cpu_arch] cpu位数，`x86` `x86_64` `powerpc`
        @apiParam {Int[]} [pkg_ids] 插件包id列表
        @apiParamExample {Json} 请求参数
        {
        }
        @apiSuccessExample {json} 成功返回:
        [
            {
                "id": 1,
                "pkg_name": "basereport-1.0.tgz",
                "project": "basereport",
                "version": "1.0",
                "pkg_size": 4391830,
                "md5": "35bf230be9f3c1b878ef7665be34e14e",
                "config_templates": [
                    {"name": "bkunifylogbeat.conf", "version": "1.0", "is_main": false},
                    {"name": "bkunifylogbeat1.conf", "version": "1.1", "is_main": false},
                    {"name": "bkunifylogbeat-main.config", "version": "0.1", "is_main": true}
                ],
                "pkg_mtime": "2019-11-25 21:58:30",
                "creator": "test_person",
                "is_ready": True,
                "is_release_version": True
            },
            {
                "id": 2,
                "pkg_name": "basereport-1.1.tgz",
                "module": "gse_plugin"
                "project": "basereport",
                "version": "1.1",
                "os": "linux",
                "cpu_arch": "x86"
                "md5": "35bf230be9f3c1b878ef7665be34e14e",
                "pkg_size": 4391830,
                "config_templates": [
                    {"id": 1, "name": "child1.conf", "version": "1.0", "is_main": false},
                    {"id": 2, "name": "child2.conf", "version": "2.0", "is_main": false},
                    {"id": 3, "name": "bkunifylogbeat-main.config", "version": "0.2", "is_main": true}
                ],
                "pkg_mtime": "2019-11-25 22:01:30",
                "creator": "test_person",
                "is_ready": True,
                // 最新上传的包
                "is_newest": True,
                "is_release_version": True
            },
        ]
        """
        params = self.validated_data
        params.pop("bk_username")
        params.pop("bk_app_code")

        return Response(
            PluginHandler.history(
                plugin_id=pk,
                pkg_ids=self.validated_data.get("pkg_ids"),
                os_type=self.validated_data.get("os"),
                cpu_arch=self.validated_data.get("cpu_arch"),
            )
        )

    @swagger_auto_schema(
        operation_summary="上传文件接口",
        tags=PLUGIN_VIEW_TAGS,
    )
    @action(detail=False, methods=["POST"], serializer_class=serializers.CosUploadSerializer)
    def upload(self, request, *args, **kwargs):
        """
        @api {POST} /plugin/upload/ 上传文件接口
        @apiName upload
        @apiGroup backend_plugin
        @apiParam {String} module 模块名称
        @apiParam {String} md5 上传端计算的文件md5
        @apiParam {String} file_name 上传端提供的文件名
        @apiParam {String} download_url 文件下载url，download_url & file_path 其中一个必填
        @apiParam {String} file_path 文件保存路径，download_url & file_path 其中一个必填
        @apiParamExample {Json} 请求参数
        {
          "bk_app_code": "bk_nodeman",
          "bk_app_secret": "xxx",
          "bk_username": "xxx",
          "md5": "e86c07536ada151dd85ca533874e8883",
          "filename": "bkmonitorbeat-2.0.48.tgz",
          "download_url": "http://xxxx/bkmonitorbeat-2.0.48.tgz"
        }
        @apiSuccessExample {json} 成功返回:
        {
            "id": 1,
            "name": "bkmonitorbeat-2.0.48.tgz",
            "pkg_size": "2333"
        }
        """
        params = self.validated_data

        upload_result = PluginHandler.upload(
            md5=params["md5"],
            origin_file_name=params["file_name"],
            module=params["module"],
            operator=params["bk_username"],
            app_code=params["bk_app_code"],
            file_path=params.get("file_path"),
            download_url=params.get("download_url"),
        )
        return Response(upload_result)


@csrf_exempt
@login_exempt
def upload_package(request):
    """
    @api {POST} /package/upload/ 上传文件接口
    @apiName upload_file
    @apiGroup backend_plugin
    @apiParam {String} module 模块名称
    @apiParam {String} md5 前端计算的MD5
    @apiParam {String} file_name 文件名称
    @apiParam {String} file_local_path Nginx上传路径
    @apiParam {String} file_local_md5 Nginx上传MD5
    @apiParamExample {Json} 请求参数
    {
        "module": "gse_plugin",
        "md5": "354659a3d1d40d380db314ed53355fe5",
        "file_name": "bkunifylogbeat-7.1.20.tgz",
        "file_local_path": "/tmp/0/9/"
        "file_local_md5": "354659a3d1d40d380db314ed53355fe5",
    }
    @apiSuccessExample {json} 成功返回:
    {
        "result": True,
        "message": "",
        "code": "00",
        "data": {
            "id": 21,  # 包上传记录ID
            "name": "test-0.01.tgz",  # 包名
            "pkg_size": "23412434",  # 单位byte
        },
    }
    """
    # 1. 获取上传的参数 & nginx的上传信息
    ser = serializers.NginxUploadSerializer(data=request.POST)
    if not ser.is_valid():
        logger.error("failed to valid request data for->[%s] maybe something go wrong?" % ser.errors)
        raise ValidationError(_("请求参数异常 [{err}]，请确认后重试").format(err=ser.errors))

    # 2. 判断哈希及参数是否符合预期
    file_local_md5 = ser.data["file_local_md5"]
    file_name = ser.data["file_name"]
    md5 = ser.data["md5"]

    if file_local_md5 != md5:
        logger.error("failed to valid file md5 local->[{}] user->[{}] maybe network error".format(file_local_md5, md5))
        raise ValidationError(_("上传文件MD5校验失败，请确认重试"))

    # 3. 创建上传的记录
    record = models.UploadPackage.create_record(
        module=ser.data["module"],
        file_path=ser.data["file_local_path"],
        md5=md5,
        operator=ser.data["bk_username"],
        source_app_code=ser.data["bk_app_code"],
        file_name=file_name,
    )
    logger.info(
        "user->[%s] from app->[%s] upload file->[%s] success."
        % (record.creator, record.source_app_code, record.file_path)
    )
    return JsonResponse(
        {
            "result": True,
            "message": "",
            "code": "00",
            "data": {
                "id": record.id,  # 包文件的ID
                "name": record.file_name,  # 包名
                "pkg_size": record.file_size,  # 单位byte
            },
        }
    )


@csrf_exempt
@login_exempt
def export_download(request):
    """
    @api {GET} /export/download/ 下载导出的内容,此处不做实际的文件读取，将由nginx负责处理
    @apiName download_content
    @apiGroup backend_plugin
    """

    # 及时如果拿到None的job_id，也可以通过DB查询进行防御
    job_id = request.GET.get("job_id")
    key = request.GET.get("key")

    try:
        record = models.DownloadRecord.objects.get(id=job_id)

    except models.DownloadRecord.DoesNotExist:
        logger.error("record->[%s] not exists, something go wrong?" % job_id)
        raise ValueError(_("请求任务不存在，请确认后重试"))

    if not record.download_key == key:
        logger.error(
            "try to download record->[%s] but request_key->[%s] is not match target_key->[%s]"
            % (job_id, key, record.download_key)
        )
        return HttpResponseForbidden(_("下载安全校验失败"))

    filename = os.path.basename(record.file_path)
    response = JsonResponse({"result": True, "message": "", "code": "00", "data": None})
    # 增加实际的下载文件名字准备
    request_str = six.moves.urllib.parse.urlencode({"real_name": os.path.basename(record.file_path).encode("utf8")})
    uri = os.path.join("/protect_download", filename)

    redirect_url = "?".join([uri, request_str])
    response["X-Accel-Redirect"] = redirect_url

    return response
