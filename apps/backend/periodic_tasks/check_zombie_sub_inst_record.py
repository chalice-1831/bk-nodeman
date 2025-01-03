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

import logging
from datetime import timedelta

from celery import current_app
from django.db.models import Value
from django.db.models.functions import Concat
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.backend.subscription.constants import (
    CHECK_ZOMBIE_SUB_INST_RECORD_INTERVAL,
    ZOMBIE_SUB_INST_RECORD_COUNT,
)
from apps.node_man import constants, models
from apps.utils.time_handler import strftime_local

logger = logging.getLogger("celery")

# 实例最长运行时间，即认定为僵尸任务的最短执行时间
MAX_RUNNING_TIME_OF_TASK = 30 * 60


@current_app.task(
    run_every=CHECK_ZOMBIE_SUB_INST_RECORD_INTERVAL,
    queue="backend",  # 这个是用来在代码调用中指定队列的，例如： update_subscription_instances.delay()
    options={"queue": "backend"},  # 这个是用来celery beat调度指定队列的
)
def check_zombie_sub_inst_record():
    """
    检查并强制失败长时间运行的instance_record
    检查范围为过去一个小时持续半个小时以上的运行时间的实例：- (2 * MAX_RUNNING_TIME_OF_TASK, - MAX_RUNNING_TIME_OF_TASK)
    :return:
    """

    query_kwargs = {
        "update_time__range": (
            timezone.now() - timedelta(seconds=2 * MAX_RUNNING_TIME_OF_TASK),
            timezone.now() - timedelta(seconds=MAX_RUNNING_TIME_OF_TASK),
        ),
        "status__in": [constants.JobStatusType.PENDING, constants.JobStatusType.RUNNING],
    }
    base_update_kwargs = {"status": constants.JobStatusType.FAILED, "update_time": timezone.now()}
    # 先count确认是否需要update，如果count数量小于100传主键 update，否则继续沿用现在的方式
    subscription_instance_record_qs = models.SubscriptionInstanceRecord.objects.filter(**query_kwargs)
    if not subscription_instance_record_qs.exists():
        logger.info("no zombie_sub_inst_record skipped")
        return
    if subscription_instance_record_qs.count() < ZOMBIE_SUB_INST_RECORD_COUNT:
        forced_failed_inst_record_ids = set(subscription_instance_record_qs.values_list("id", flat=True))
        forced_failed_inst_num = models.SubscriptionInstanceRecord.objects.filter(
            id__in=forced_failed_inst_record_ids
        ).update(**base_update_kwargs)
    else:
        forced_failed_inst_num = models.SubscriptionInstanceRecord.objects.filter(**query_kwargs).update(
            **base_update_kwargs
        )

    forced_failed_status_detail_num = models.SubscriptionInstanceStatusDetail.objects.filter(**query_kwargs).update(
        **base_update_kwargs,
        log=Concat(
            "log", Value(_("\n[{time_str} ERROR] 任务长时间处在执行状态，已强制失败").format(time_str=strftime_local(timezone.now())))
        ),
    )

    logger.info(
        f"periodic_task -> check_zombie_sub_inst_record, number_of_forced_failed_inst -> {forced_failed_inst_num}, "
        f"forced_failed_status_detail_num -> {forced_failed_status_detail_num}"
    )
