from django.shortcuts import render

# Create your views here.
from django.http import *
from django.shortcuts import render_to_response,redirect, render
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .form import *
from .models import *
import hashlib
from TrackUser.logger import log

# Create your views here.
def login_user(request):
    logout(request)
    username = password = ''
    log.info("inside login")
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        log.info("username : %s",username)
        log.info("password : %s",password)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                current_user = request.user
                print(current_user)
                return render(request,'user_registration.html')
    return render(request, 'login.html')


@login_required( login_url='/login/')
def register_user(request):
    return render(request, 'user_registration.html')

@login_required( login_url='/login/')
def save_user_detail(request):
    print("Inside save user details")
    username = request.POST['username']
    print("username",username)
    password = request.POST['password']
    confirm_password = request.POST['confirmpassword']
    email = request.POST['email']
    mobile = request.POST['mobile']
    print("request.POST",request.POST)
    if username!="" and password!="" and confirm_password!="" and email!="" and mobile !="":
        if password == confirm_password:
            p=user_detail(username=username,password=password,email_address=email,phonenumber=mobile)
            p.save()
            print("data saved in database")
            print(p)
            return render(request, 'user_registration.html', {'msg': "user registered successfully."})
        else:
            return render(request, 'user_registration.html', {'msg': "password and confirm password is not matching."})
    else:
        return render(request,'user_registration.html',{'msg':"Please enter all the details"})

@login_required( login_url='/login/')
def get_user_details(request):
    user_data = user_detail.objects.all()
    print(user_data)
    Users = {}
    all_user_data = []
    for data in user_data:
        user = {}
        user['uname'] = data.username
        user['passw'] = data.password
        user['email'] = data.email_address
        user['mobile'] = data.phonenumber
        all_user_data.append(user)
    Users['userdata'] = all_user_data
    return Users

@login_required( login_url='/login/')
def modify_user(request):
    Users = get_user_details(request)
    current_user = {}
    active_user = request.user.username
    print("active_user",active_user)
    current_user['cur_user'] = active_user
    Users['current_user'] = current_user
    print("Users",Users)
    return render(request, 'modifyuser.html',Users)

@login_required( login_url='/login/')
def modify_user_detail(request):
    print("Inside modify user details")
    username = request.POST['username1']
    print("username",username)
    Users = get_user_details(request)
    current_user = {}
    active_user = request.user.username
    print("active_user", active_user)
    current_user['cur_user'] = active_user
    Users['current_user'] = current_user
    if username!="No user registered":
        password = request.POST['password']
        confirm_password = request.POST['confirmpassword']
        email = request.POST['email']
        mobile = request.POST['mobile']
        print("request.POST", request.POST)
        if username != "" and password != "" and confirm_password != "" and email != "" and mobile != "":
            if password == confirm_password:
                user = user_detail.objects.get(username=username)
                user.username=username
                user.password=password
                user.email_address=email
                user.phonenumber=mobile
                #p = user_detail(username=username, password=password, email_address=email, phonenumber=mobile)
                user.save()
                print("data saved in database")
                print(user)
                Users = get_user_details(request)
                Users['msg']="user data modified successfully."
                return render(request, 'modifyuser.html',Users)
            else:
                Users['msg'] = "password and confirm password is not matching."
                return render(request, 'modifyuser.html',Users)
        else:
            Users['msg'] = "Please enter all the details"
            return render(request, 'modifyuser.html',Users)
    else:
        Users['msg'] = "There is no user registered to modify"
        return render(request, 'modifyuser.html',Users)

@login_required( login_url='/login/')
def delete_user(request):
    Users = get_user_details(request)
    return render(request, 'deleteuser.html',Users)

@login_required( login_url='/login/')
def delete_user_data(request):
    print("Inside delete user details")
    username = request.POST['username1']
    Users = get_user_details(request)
    current_user = {}
    active_user = request.user.username
    print("active_user", active_user)
    current_user['cur_user'] = active_user
    Users['current_user'] = current_user
    print("Users",Users)
    print("username",username)
    if username != "No user registered":
        if username!=active_user:
            user = user_detail.objects.get(username=username)
            user.delete()
            Users = get_user_details(request)
            Users['msg'] = "user data deleted successfully."
            return render(request, 'deleteuser.html', Users)
        else:
            Users['msg'] = "Currently active user. Can't delete the user"
            return render(request, 'deleteuser.html', Users)
    else:
        Users['msg'] = "There is no user registered to delete"
        return render(request, 'deleteuser.html', Users)

@login_required( login_url='/login/')
def view_user(request):
    Users = get_user_details(request)
    return render(request, 'viewuser.html',Users)

@login_required( login_url='/login/')
def logout_user(request):
    logout(request)
    return render(request, 'login.html')


