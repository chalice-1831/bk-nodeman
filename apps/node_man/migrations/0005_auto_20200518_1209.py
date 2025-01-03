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
# Generated by Django 2.2.8 on 2020-05-18 04:09

from django.db import migrations, models


def migrate_servers(apps, schema_editor):
    # 初始化默认接入点
    AccessPoint = apps.get_model("node_man", "AccessPoint")
    for ap in AccessPoint.objects.all():
        ap.btfileserver = ap.taskserver
        ap.dataserver = ap.taskserver
        ap.save()


class Migration(migrations.Migration):
    dependencies = [
        ("node_man", "0004_auto_20200509_1438"),
    ]

    operations = [
        migrations.RenameField(
            model_name="accesspoint",
            old_name="servers",
            new_name="taskserver",
        ),
        migrations.AlterField(
            model_name="accesspoint",
            name="taskserver",
            field=models.JSONField(default=dict, verbose_name="GSE 任务服务器列表"),
        ),
        migrations.AddField(
            model_name="accesspoint",
            name="btfileserver",
            field=models.JSONField(default=dict, verbose_name="GSE BT文件服务器列表"),
        ),
        migrations.AddField(
            model_name="accesspoint",
            name="dataserver",
            field=models.JSONField(default=dict, verbose_name="GSE 数据服务器列表"),
        ),
        migrations.AddField(
            model_name="accesspoint",
            name="nginx_path",
            field=models.TextField(blank=True, null=True, verbose_name="Nginx路径"),
        ),
        migrations.AddField(
            model_name="pluginconfigtemplate",
            name="is_main",
            field=models.BooleanField(default=False, verbose_name="是否主配置"),
        ),
        migrations.RunPython(migrate_servers),
    ]
