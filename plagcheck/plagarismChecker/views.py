from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.template import RequestContext, loader
from django.core.urlresolvers import reverse
from django.contrib.auth import logout
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from os.path import expanduser
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect, csrf_exempt
from django.conf import settings
from django.core.serializers import serialize
from django.contrib.auth.models import Group
from forms import *
from serializers import *
import os
import glob
import json
from django.shortcuts import render
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
            public, _ = Group.objects.get_or_create(name='Public')
            user.groups.add(public)
            user.save()

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
    else:
        form = UserChangeForm(instance=request.user)
        # Assign default image in the preview if no profile image is selected for the user.

    template = loader.get_template('annotations/settings.html')
    context = {
        'user': request.user,
        'full_name': request.user.full_name,
        'email': request.user.email,
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

    context = {
        'title': 'Dashboard',
        'user': request.user,
    }
    return HttpResponse(template.render(context, request))

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
    result = printCompare(file_name1, file_name2, uploaded_file.name, uploaded_file1.name)

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
    dir = os.path.join(dir, "filedb/")
    file_name = dir + file_name

    with open(file_name, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
        destination.close()

    file_list = glob.glob(dir + "*")
    result = {}
    print file_list
    for file in file_list:
        cur_file_name = FileMap.objects.filter(random_file_name=ntpath.basename(file))
        print file_name, file
        if ntpath.basename(file_name) != ntpath.basename(file):
            if cur_file_name is not None and cur_file_name[0].actual_file_name is not None:
                result[cur_file_name[0].actual_file_name] = printDiff(file, file_name)
            else:
                result[file] = printDiff(file, file_name)
            print cur_file_name

    final_result = {}
    cur_file_name = FileMap.objects.filter(random_file_name=ntpath.basename(file_name))
    f_name = cur_file_name[0].actual_file_name
    final_result[f_name.encode('ascii', 'ignore')] = result
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
    with open(filename, 'r') as f:
        d = {}
        q1 = []
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

                    q1.insert(0, word)
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
    len2 = len(d2)
    diff1 = deep_check(d1, d2)
    diff2 = len(d2)

    perD1 = (diff1 * 100) / len(d1)
    perD2 = (diff2 * 100) / len2

    result = {}
    result[actual_name1] = "Your upload  is " + str(100 - perD1) + " percentage present in " + actual_name2
    result[actual_name2] = actual_name2 + " is " + str(100 - perD2) + " percentage similar to " + actual_name1

    return result


def printDiff(filename1, filename2):
    d1 = parseFile(filename1)
    d2 = parseFile(filename2)

    len2 = len(d2)
    diff1 = deep_check(d1, d2)
    diff2 = len(d2)

    perD1 = (diff1 * 100) / len(d1)
    perD2 = (diff2 * 100) / len2

    result = (100 - perD1)

    return result
