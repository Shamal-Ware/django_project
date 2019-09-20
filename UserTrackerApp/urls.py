from django.urls import path
from django.conf.urls import  url
from django.contrib.auth.views import LoginView , LogoutView
from  .views import *

urlpatterns = [
    path('', LogoutView.as_view(template_name="login.html")),
    url(r'^user/$', LogoutView.as_view(template_name="user_registration.html")),
    url(r'^login/$', Login),
    url(r'^save_user',save_user_detail),
    url(r'logout/',Logout)
]


