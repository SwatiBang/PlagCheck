# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-04-15 22:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('plagarismChecker', '0002_auto_20170415_1458'),
    ]

    operations = [
        migrations.AlterField(
            model_name='filemap',
            name='actual_file_name',
            field=models.CharField(max_length=80, verbose_name='name'),
        ),
    ]