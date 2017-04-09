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
from django.contrib.auth import logout

from django.contrib.auth import login,authenticate
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required

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

import json
import time
from django.shortcuts import render
from hashlib import sha1
import base64
import logging


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


def home(request):
    """

    Provides a landing page containing information about the application
    for user who are not authenticated

    LoggedIn users are redirected to the dashboard view
    ----------
    request : HTTPRequest
        The request for application landing page.
    Returns
    ----------
    :template:
        Renders landing page for non-loggedin user and
        dashboard view for loggedin users.
    """
    template = loader.get_template('annotations/home.html')
    user_count = 0
    text_count = 0
    appellation_count = 0
    relation_count = 0
    context =  {
        'user_count': user_count,
        'text_count': text_count,
        'relation_count': relation_count,
        'appellation_count': appellation_count,
        'recent_combination': 0,
        'title': 'Build the epistemic web'
    }
    return HttpResponse(template.render(context, request))




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
            user = VogonUser.objects.create_user(
                form.cleaned_data['username'],
                form.cleaned_data['email'],
                password=form.cleaned_data['password1'],
                full_name=form.cleaned_data['full_name'],
                affiliation=form.cleaned_data['affiliation'],
                location=form.cleaned_data['location'],
                link=form.cleaned_data['link'],
            )

            # TODO: Do we need this anymore?
            public, _ = Group.objects.get_or_create(name='Public')
            user.groups.add(public)
            user.save()    # TODO: redundant?

            new_user = authenticate(username=form.cleaned_data['username'],
                                    password=form.cleaned_data['password1'])
            # Logs in the new VogonUser.
            login(request, new_user)
            return HttpResponseRedirect(reverse('dashboard'))
    else:
        form = RegistrationForm()

    return render(request, 'registration/register.html', {'form': form})




@login_required
def user_projects(request):
    """
    Shows a list of the current (logged-in) uers's projects.
    """
    fields = [
        'id',
        'name',
        'created',
        'ownedBy__id',
        'ownedBy__username',
        'description',
        'num_texts',
        'num_relations',
    ]
    qs = TextCollection.objects.filter(ownedBy=request.user.id)
    qs = qs.annotate(num_texts=Count('texts'),
                     num_relations=Count('texts__relationsets'))
    qs = qs.values(*fields)

    template = loader.get_template('annotations/project_user.html')
    context = RequestContext(request, {
        'user': request.user,
        'title': 'Projects',
        'projects': qs,
    })
    return HttpResponse(template.render(context))


def view_project(request, project_id):
    """
    Shows details about a specific project owned by the current user.
    """

    project = get_object_or_404(TextCollection, pk=project_id)
    template = loader.get_template('annotations/project_details.html')

    order_by = request.GET.get('order_by', 'title')
    texts = project.texts.all().order_by(order_by).values('id', 'title', 'created')
    paginator = Paginator(texts, 15)

    page = request.GET.get('page')
    try:
        texts = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        texts = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        texts = paginator.page(paginator.num_pages)


    context = RequestContext(request, {
        'user': request.user,
        'title': project.name,
        'project': project,
        'texts': texts,
    })

    return HttpResponse(template.render(context))


def create_project(request):

    return


@login_required
def edit_project(request, project_id):
    """
    Allow the owner of a project to edit it.
    """
    template = loader.get_template('annotations/project_change.html')
    project = get_object_or_404(TextCollection, pk=project_id)
    if project.ownedBy.id != request.user.id:
        raise PermissionDenied("Whoops, you're not supposed to be here!")

    if request.method == 'POST':
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse('view_project', args=(project.id,)))
        else:
            print form.errors
    else:
        form = ProjectForm(instance=project)

    context = RequestContext(request, {
        'user': request.user,
        'title': 'Editing project: %s' % project.name,
        'project': project,
        'form': form,
        'page_title': 'Edit project'
    })
    return HttpResponse(template.render(context))


@login_required
def create_project(request):
    """
    Create a new project owned by the current (logged-in) user.
    """
    template = loader.get_template('annotations/project_change.html')

    if request.method == 'POST':
        form = ProjectForm(request.POST)
        if form.is_valid():
            project = form.save(commit=False)
            project.ownedBy = request.user
            project.save()
            return HttpResponseRedirect(reverse('view_project', args=(project.id,)))
        else:
            print form.errors
    else:
        form = ProjectForm()

    context = RequestContext(request, {
        'user': request.user,
        'title': 'Create a new project',
        'form': form,
        'page_title': 'Create a new project'
    })
    return HttpResponse(template.render(context))


def list_projects(request):
    """
    All known projects.
    """

    fields = [
        'id',
        'name',
        'created',
        'ownedBy__id',
        'ownedBy__username',
        'description',
        'num_texts',
        'num_relations',
    ]
    qs = TextCollection.objects.all()
    qs = qs.annotate(num_texts=Count('texts'),
                     num_relations=Count('texts__relationsets'))
    qs = qs.values(*fields)

    template = loader.get_template('annotations/project_list.html')
    context = RequestContext(request, {
        'user': request.user,
        'title': 'Projects',
        'projects': qs,
    })
    return HttpResponse(template.render(context))


def user_recent_texts(user):
    """
    Return a list of :class:`.Text`\s recently annotated by a
    :class:`.VogonUser`\.

    TODO: Do we need this anymore?

    Parameters
    ----------
    user : :class:`.VogonUser`

    Returns
    -------
    list
    """
    by_appellations = user.appellation_set.all().order_by('-created').values_list('occursIn_id', 'occursIn__title', 'created')
    by_relations = user.relation_set.all().order_by('-created').values_list('occursIn_id', 'occursIn__title', 'created')
    # by_relations = Text.objects.filter(relation__createdBy__pk=user.id).values_list('id', 'title')
    # by_appellations = Text.objects.filter(appellation__createdBy__pk=user.id).values_list('id', 'title')
    results_sorted = sorted(chain([tuple(t) for t in by_relations], [tuple(t) for t in by_appellations]), key=lambda t: t[2])[::-1]
    results_unique = list(set([(t[0], t[1]) for t in results_sorted]))
    return results_unique


@login_required
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
            return HttpResponseRedirect(reverse('user_details', args=[request.user.id]))
    else:
        form = UserChangeForm(instance=request.user)
        # Assign default image in the preview if no profile image is selected for the user.
        if request.user.imagefile == "" or request.user.imagefile is None:
            request.user.imagefile=settings.DEFAULT_USER_IMAGE

    template = loader.get_template('annotations/settings.html')
    context = RequestContext(request, {
        'user': request.user,
        'full_name' : request.user.full_name,
        'email' : request.user.email,
        'affiliation' : request.user.affiliation,
        'location' : request.user.location,
        'link' : request.user.link,
        'preview' : request.user.imagefile,
        'form': form,
        'subpath': settings.SUBPATH,
    })
    return HttpResponse(template.render(context))


def about(request):
    """
    Provides information about Vogon-Web

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """
    template = loader.get_template('annotations/about.html')
    context ={
        'title': 'About VogonWeb'
    }
    return HttpResponse(template.render(context, request))

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
        'recent_texts': "",
        'added_texts': "",
        'projects_owned': "",
        'projects_contributed': "",
        'appellationCount': 0,
        'relation_count': 0,
    }
    return HttpResponse(template.render(context, request))


def list_user(request):
    """
    List all the users of Vogon web.

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
    queryset = VogonUser.objects.exclude(id = -1).order_by(sort)

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




def recent_activity(request):
    """
    Provides summary of activities performed on the system.
    Currently on text addition, Appellation additions are shown.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
    """
    template = loader.get_template('annotations/recent_activity.html')
    recent_texts = Text.objects.annotate(hour=DateTime("added", "hour", pytz.timezone("UTC"))).values("hour", "addedBy__username").annotate(created_count=Count('id')).order_by("-hour", "addedBy")

    context = {
        'recent_texts': recent_texts,
        'recent_combination': _get_recent_annotations()
    }
    return HttpResponse(template.render(context))




# TODO: move this out of views.py and into an exceptions module.
def custom_403_handler(request):
    """
    Default 403 Handler. This method gets invoked if a PermissionDenied
    Exception is raised.

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`

    Returns
    ----------
    :class:`django.http.response.HttpResponse`
        Status 403.
    """
    template = loader.get_template('annotations/forbidden_error_page.html')
    context_data = {
        'userid': request.user.id,
        'error_message': "Whoops, you're not supposed to be here!"
    }
    context = RequestContext(request, context_data)
    return HttpResponse(template.render(context), status=403)


### REST API class-based views.
#
# TODO: move these CBVs into their own module.
#


class UserViewSet(viewsets.ModelViewSet):
    queryset = VogonUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticatedOrReadOnly, )




class StandardResultsSetPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000




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


def handle_file_upload(request, form):
    """
    Handle the uploaded file and route it to corresponding handlers

    Parameters
    ----------
    request : `django.http.requests.HttpRequest`
    form : `django.forms.Form`
        The form with uploaded content

    """
    uploaded_file = request.FILES['filetoupload']
    uploaded_file1 = request.FILES['filetoupload1']
    with open('name.txt', 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    with open('name1.txt', 'wb+') as destination:
        for chunk in uploaded_file1.chunks():
            destination.write(chunk)
    print uploaded_file1
    uri = form.cleaned_data['uri']
    text_title = form.cleaned_data['title']
    is_public = form.cleaned_data['ispublic']
    user = request.user
    file_content = None

    result = printDiff('name.txt','name1.txt')
    # if uploaded_file.content_type == 'text/plain':
    #     file_content = extract_text_file(uploaded_file)
    # elif uploaded_file.content_type == 'application/pdf':
    #     file_content = extract_pdf_file(uploaded_file)

    # Save the content if the above extractors extracted something
    if file_content != None:
        tokenized_content = tokenize(file_content)
        return save_text_instance(tokenized_content, text_title, date_created, is_public, user, uri)
    return result




def user_details(request, userid, *args, **kwargs):
    """
    Provides users with their own profile view and public profile view of other users in case they are loggedIn.
    Provides users with public profile page in case they are not loggedIn
    ----------
    request : HTTPRequest
        The request for fetching user details
    userid : int
        The userid of user who's data  needs to be fetched
    args : list
        List of arguments to view
    kwargs : dict
        dict of arugments to view
    Returns
    ----------
    :HTTPResponse:
        Renders an user details view based on user's authentication status.
    """
    user = get_object_or_404(VogonUser, pk=userid)
    if request.user.is_authenticated() and request.user.id == int(userid) and request.GET.get('mode', '') == 'edit':
        return HttpResponseRedirect(reverse('settings'))
    else:
        textCount = Text.objects.filter(addedBy=user).count()
        textAnnotated = Text.objects.filter(appellation__createdBy=user).distinct().count()
        relation_count = user.relation_set.count()
        appellation_count = user.appellation_set.count()
        start_date = datetime.datetime.now() + datetime.timedelta(-60)

        # Count annotations for user by date.
        relations_by_user = Relation.objects.filter(createdBy = user, created__gt = start_date)\
            .extra({'date' : 'date(created)'}).values('date').annotate(count = Count('created'))

        appelations_by_user = Appellation.objects.filter(createdBy = user, created__gt = start_date)\
            .extra({'date' : 'date(created)'}).values('date').annotate(count = Count('created'))

        annotation_by_user = list(relations_by_user)
        annotation_by_user.extend(list(appelations_by_user))

        result = dict()
        weeks_last_date_map = dict()
        d7 = datetime.timedelta( days = 7)
        current_week = datetime.datetime.now() + d7

        # Find out the weeks and their last date in the past 90 days.
        while start_date <= current_week:
            result[(Week(start_date.isocalendar()[0], start_date.isocalendar()[1]).saturday()).strftime('%m-%d-%y')] = 0
            start_date += d7
        time_format = '%Y-%m-%d'

        # Count annotations for each week.
        for count_per_day in annotation_by_user:
            if(isinstance(count_per_day['date'], unicode)):
                date = datetime.datetime.strptime(count_per_day['date'], time_format)
            else:
                date = count_per_day['date']
            result[(Week(date.isocalendar()[0], date.isocalendar()[1]).saturday()).strftime('%m-%d-%y')] += count_per_day['count']
        annotation_per_week = list()

        # Sort the date and format the data in the format required by d3.js.
        keys = (result.keys())
        keys.sort()
        for key in keys:
            new_format = dict()
            new_format["date"] = key
            new_format["count"] = result[key]
            annotation_per_week.append(new_format)
        annotation_per_week = str(annotation_per_week).replace("'", "\"")

        projects = user.collections.all()

        template = loader.get_template('annotations/user_details_public.html')
        context = RequestContext(request, {
            'detail_user': user,
            'textCount': textCount,
            'relation_count': relation_count,
            'appellation_count': appellation_count,
            'text_count': textAnnotated,
            'default_user_image' : settings.DEFAULT_USER_IMAGE,
            'annotation_per_week' : annotation_per_week,
            'recent_activity': _get_recent_annotations(user=user),
            'projects': projects,
        })
    return HttpResponse(template.render(context))



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

    result ={}
    result['str1'] = f1 + " is " + str(100 - perD1) + " percentage similar to " + f2
    result['str2'] = f2 + " is " + str(100 - perD2) + " percentage similar to " + f1

    return result
