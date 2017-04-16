from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.contrib.contenttypes.models import ContentType
from django.template import RequestContext, loader
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.core.urlresolvers import reverse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.files import File
from django.core.serializers import serialize
from django.core.cache import caches
from tasks import extract_text_file, extract_pdf_file, tokenize
from django.contrib.auth import logout

from django.contrib.auth import login,authenticate
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from os.path import expanduser

from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect, csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.generic.edit import FormView

from rest_framework import status
from rest_framework.response import Response
from rest_framework.settings import api_settings
from django.db import models
from django.db.models.query import QuerySet

from rest_framework import viewsets, exceptions, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.decorators import detail_route, list_route
from rest_framework.pagination import LimitOffsetPagination, PageNumberPagination


from django.conf import settings

from django.forms import formset_factory

from django.core.serializers import serialize
from django.db.models import Q, Count
from django.utils.safestring import mark_safe
from django.core.files import File
from django.contrib.auth.models import Group
from django.db import models
from django.db.models.query import QuerySet


from models import *
from forms import *
from serializers import *
import hmac
import hashlib
from itertools import chain, combinations, groupby
from collections import OrderedDict, defaultdict, Counter
import requests
import re
from urlnorm import norm
from itertools import chain
import pytz
import uuid
import copy
import datetime
import os
from urlparse import urlparse
import urllib
import glob

import json
import time
from django.shortcuts import render
from hashlib import sha1
import base64
import logging
import random, string

def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))

# TODO: Can we replace this with the built-in Django JsonResponse?
def json_response(func):
    def decorator(request, *args, **kwargs):
        objects = func(request, *args, **kwargs)

        try:
            data = json.dumps(objects)
        except:
            if not hasattr(objects, '__iter__'):
                data = serialize("json", [objects])[1:-1]
            else:
                data = serialize("json", objects)
        return HttpResponse(data, "application/json")
    return decorator


def logout_view(request):
    logout(request)


def basepath(request):
    """
    Generate the base path (domain + path) for the site.

    TODO: Do we need this anymore?

    Parameters
    ----------
    request : :class:`django.http.request.HttpRequest`

    Returns
    -------
    str
    """
    if request.is_secure():
        scheme = 'https://'
    else:
        scheme = 'http://'
    return scheme + request.get_host() + settings.SUBPATH


@csrf_protect
def register(request):
    """
    Provide new user registration view.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                form.cleaned_data['username'],
                form.cleaned_data['email'],
                password=form.cleaned_data['password1'],
                full_name=form.cleaned_data['full_name'],
            )

            # TODO: Do we need this anymore?
            public, _ = Group.objects.get_or_create(name='Public')
            user.groups.add(public)
            user.save()    # TODO: redundant?

            new_user = authenticate(username=form.cleaned_data['username'],
                                    password=form.cleaned_data['password1'])
            # Logs in the new User.
            login(request, new_user)
            return HttpResponseRedirect(reverse('dashboard'))
    else:
        form = RegistrationForm()

    return render(request, 'registration/register.html', {'form': form})


@login_required
@csrf_exempt
def user_settings(request):
    """
    User profile settings.
    Parameters
    ----------
    request : `django.http.requests.HttpRequest`
    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """

    if request.method == 'POST':
        form = UserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            #return HttpResponseRedirect(reverse('user_details', args=[request.user.id]))
    else:
        form = UserChangeForm(instance=request.user)
        # Assign default image in the preview if no profile image is selected for the user.

    template = loader.get_template('annotations/settings.html')
    ##context = RequestContext(request, {
    context = {
        'user': request.user,
        'full_name' : request.user.full_name,
        'email' : request.user.email,
        'subpath': settings.SUBPATH,
    }
    return HttpResponse(template.render(context))


@login_required
def dashboard(request):
    """
    Provides the user's personalized dashboard.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """

    template = loader.get_template('annotations/dashboard.html')

    recent_texts = ""
    added_texts = ""

    projects_owned = ""
    projects_contributed = ""

    context = {
        'title': 'Dashboard',
        'user': request.user,
    }
    return HttpResponse(template.render(context, request))


def list_user(request):
    """
    List all the users of  web.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """

    template = loader.get_template('annotations/contributors.html')

    search_term = request.GET.get('search_term')
    sort = request.GET.get('sort', 'username')
    queryset = User.objects.exclude(id = -1).order_by(sort)

    if search_term:
        queryset = queryset.filter(Q(full_name__icontains=search_term) |
                                   Q(username__icontains=search_term))

    paginator = Paginator(queryset, 10)

    page = request.GET.get('page')
    try:
        users = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        users = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        users = paginator.page(paginator.num_pages)

    context = {
        'search_term' : search_term,
        'sort_column' : sort,
        'user_list': users,
        'user': request.user,
        'title': 'Contributors'
    }
    return HttpResponse(template.render(context))




### REST API class-based views.
#
# TODO: move these CBVs into their own module.
#


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticatedOrReadOnly, )




class StandardResultsSetPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000




@login_required
def test(request):
    """
    Upload a file and save the text instance.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """

    if request.method == 'POST':
        form = UploadTestForm(request.POST, request.FILES)
        if form.is_valid():
            text = handle_test_upload(request, form)
            return HttpResponse(json.dumps(text), content_type="application/json")
    else:
        form = UploadTestForm()

    template = loader.get_template('annotations/test.html')
    context = {
        'user': request.user,
        'form': form,
        'subpath': settings.SUBPATH,
    }
    return HttpResponse(template.render(context, request))



@login_required
def upload_file(request):
    """
    Upload a file and save the text instance.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """

    project_id = request.GET.get('project', None)

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
        	# template = loader.get_template('annotations/chart.html')
        	# context ={'user': request.user,'similarity': 70,'subpath': settings.SUBPATH,}
        	# return HttpResponse(template.render(context, request))
            text = handle_file_upload(request, form)
            return HttpResponse(json.dumps(text), content_type="application/json")
    else:
        form = UploadFileForm()

    template = loader.get_template('annotations/upload_file.html')
    context = {
        'user': request.user,
        'form': form,
        'subpath': settings.SUBPATH,
    }
    return HttpResponse(template.render(context, request))

def handle_test_upload(request, form):
    """
    Handle the uploaded file and route it to corresponding handlers

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`
    form : `django.forms.Form`
        The form with uploaded content

    """

    file_name1 = randomword(10)
    file_name2 = randomword(10)
    uploaded_file = request.FILES['filetoupload']
    uploaded_file1 = request.FILES['filetoupload1']
    with open(file_name1, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    with open(file_name2, 'wb+') as destination:
        for chunk in uploaded_file1.chunks():
            destination.write(chunk)
    user = request.user
    file_content = None

    result = printCompare(file_name1,file_name2, uploaded_file.name,uploaded_file1.name)

    return result


def handle_file_upload(request, form):
    """
    Handle the uploaded file and route it to corresponding handlers

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`
    form : `django.forms.Form`
        The form with uploaded content

    """
    import ntpath
    uploaded_file = request.FILES['filetoupload']

    file_name = randomword(10)
    
    file_map = FileMap()
    file_map.actual_file_name = uploaded_file.name
    file_map.random_file_name = file_name

    file_map.save()

    dir = expanduser("~")
    dir = os.path.join(dir,"filedb/")
    file_name = dir + file_name

    with open(file_name, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
	destination.close()

    text_title = form.cleaned_data['title']
    user = request.user
    file_content = None

    if uploaded_file.content_type == 'text/plain':
        file_content = extract_text_file(uploaded_file)
    elif uploaded_file.content_type == 'application/pdf':
        file_content = extract_pdf_file(uploaded_file)

    file_list = glob.glob(dir+"*")
    result = {}
    print file_list
    for file in file_list:
        cur_file_name = FileMap.objects.filter(random_file_name=ntpath.basename(file))
        print file_name, file
        if ntpath.basename(file_name) != ntpath.basename(file):
	        if cur_file_name is not None and cur_file_name[0].actual_file_name is not None:
	        	result[cur_file_name[0].actual_file_name] = printDiff(file,file_name)
	        else:
	        	result[file] = printDiff(file,file_name)
	        print cur_file_name
    
    final_result = {}
    cur_file_name = FileMap.objects.filter(random_file_name=ntpath.basename(file_name))
    f_name = cur_file_name[0].actual_file_name
    final_result[f_name.encode('ascii','ignore')] = result
    return final_result


def deep_check(d1, d2):
    diff = 0
    # Find non-dicts that are only in compto
    for item in d1.items():
        if d2.has_key(item[0]):
            d2[item[0]] = d2[item[0]] - 1
            if d2[item[0]] == 0:
                del d2[item[0]]
        else:
            diff = diff + 1

    return diff;

def parseFile(filename):
    with open(filename,'r') as f:
        d = {}
        q1 = []
        first=""
        second=""
        third=""

        count = 0
        for line in f:
            for word in line.split():
                word = word.strip('.')
                word = word.strip()
                word = word.strip(',')
                if len(word) > 2:
                    count = count + 1
                    if count > 3:
                       q1.pop()

                    q1.insert(0,word)
                    triplet = ""

                    for t in q1:
                        triplet = triplet + ":" + t

                    if d.has_key(triplet):
                        d[triplet] = d[triplet] + 1
                    else:
                        d[triplet] = 1
    return d;

def printCompare(filename1, filename2, actual_name1, actual_name2):
    d1 = parseFile(filename1)
    d2 = parseFile(filename2)

    f1 = filename1
    f2 = filename2

    len2 = len(d2)
    diff1 = deep_check(d1,d2)
    diff2 =  len(d2)

    perD1 = (diff1 * 100)/len(d1)
    perD2 = (diff2 * 100)/len2

    result = {}
    result[actual_name1] = "Your upload  is " + str(100 - perD1) + " percentage present in " + actual_name2
    result[actual_name2] = actual_name2 + " is " + str(100 - perD2) + " percentage similar to " + actual_name1

    return result

def printDiff(filename1, filename2):


    d1 = parseFile(filename1)
    d2 = parseFile(filename2)

    f1 = filename1
    f2 = filename2

    len2 = len(d2)
    diff1 = deep_check(d1,d2)
    diff2 =  len(d2)

    perD1 = (diff1 * 100)/len(d1)
    perD2 = (diff2 * 100)/len2

    result = (100 - perD1) 

    return result
