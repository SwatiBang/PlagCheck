# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-04-08 21:51
from __future__ import unicode_literals

from django.db import migrations, models
import plagarismChecker.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0008_alter_user_username_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='VogonUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(max_length=255, unique=True)),
                ('email', models.EmailField(max_length=255, verbose_name=b'email address')),
                ('affiliation', models.CharField(blank=True, max_length=255, null=True)),
                ('location', models.CharField(blank=True, max_length=255, null=True)),
                ('link', models.URLField(blank=True, max_length=500, null=True)),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('conceptpower_uri', models.URLField(blank=True, max_length=500, null=True)),
                ('imagefile', models.URLField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='VogonGroup',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=80, unique=True, verbose_name='name')),
                ('permissions', models.ManyToManyField(blank=True, to='auth.Permission', verbose_name='permissions')),
            ],
            options={
                'verbose_name': 'group',
                'verbose_name_plural': 'groups',
            },
            managers=[
                ('objects', plagarismChecker.models.GroupManager()),
            ],
        ),
    ]