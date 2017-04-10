"""plagcheck URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

"""vogon URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url, handler403
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static

from django.contrib.auth import views as auth_views


from plagarismChecker import views

#Error Handlers
handler403 = 'plagarismChecker.views.custom_403_handler'

urlpatterns = [
    url(r'^$', views.home),
    url(r'^about/$', views.about, name='about'),
    url(r'^accounts/profile/', views.dashboard, name='dashboard'),
    url(r'^accounts/projects/', views.user_projects, name='user_projects'),
    url(r'^accounts/settings/$', views.user_settings, name='settings'),
    url(r'^accounts/register/$', views.register, name='register'),
    url(r'^accounts/login/$', auth_views.login, name='login'),
    url(r'^accounts/logout/$', auth_views.logout, name="logout"),
    url(r'^activity/$', views.recent_activity),
    url(r'^accounts/', include('django.contrib.auth.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^users/$', views.list_user, name = 'users'),
    url(r'^users/(?P<userid>[0-9]+)/$', views.user_details, name="user_details"),
    url(r'^upload/$', views.upload_file, name="file_upload"),
    url(r'^test/$', views.test, name="test"),
] 

