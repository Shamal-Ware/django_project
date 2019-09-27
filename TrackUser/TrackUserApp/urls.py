from django.urls import path
from django.conf.urls import  url
from django.contrib.auth.views import LoginView , LogoutView
from  .views import *

urlpatterns = [
    path('', LogoutView.as_view(template_name="login.html")),
    url(r'^adduser/$', register_user),
    url(r'^login/$', login_user),
    url(r'logout/',logout_user),
    url(r'modifyuser/',modify_user),
    url(r'deleteuser/', delete_user),
    url(r'viewuser/', view_user),
    url(r'deleteuserdata/', delete_user_data),
    url(r'modifyuserdata/',modify_user_detail),
    url(r'^users/',user_detail_list.as_view()), # phase 2 implementation
    url(r'^logs/$',loglist.as_view()), # phase 2 implementation
    url(r'^logs/user/$',user_log_entry.as_view()), # phase 2 implementation
    url(r'^logs/replay$',log_entry.as_view()), # phase 2 implementation,
]


