from django.http import *
from django.shortcuts import render_to_response,redirect, render
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .form import *
from .models import *

# Create your views here.
def Login(request):
    logout(request)
    username = password = ''
    print("inside login")
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        print(username)
        print(password)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return render(request,'user_registration.html')
    return render(request, 'login.html')


def save_user_detail(request):
    print("Inside save user details")
    username = request.POST['username']
    print("username",username)
    password = request.POST['password']
    confirm_password = request.POST['confirmpassword']
    email = request.POST['email']
    mobile = request.POST['mobile']
    print("request.POST",request.POST)
    #p = UserFormData(username,password,confirm_password,email,mobile)
    p=user_detail(username=username,password=password,confirm_password=confirm_password,email_address=email,phonenumber=mobile)
    p.save()
    print("data saved in database")
    print(p)
    return render(request,'user_registration.html',{'msg':"user registered successfully."})


def Logout(request):
    logout(request)


