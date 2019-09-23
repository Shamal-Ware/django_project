from django.shortcuts import render
# Create your views here.
from django.http import *
from django.shortcuts import render_to_response,redirect, render
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .form import *
from .models import *
from TrackUser.logger import log
from django.contrib.auth.models import User
import re
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializer import *


# Create your views here.
# function used to login the user
def login_user(request):
    try:
        logout(request)
        username = password = ''
        log.info("inside login")
        if request.POST:
            username = request.POST['username']
            password = request.POST['password']
            log.info("username : %s", username)
            log.info("password : %s", password)
            if username!="" and password!="":
                user = authenticate(username=username, password=password)
                log.info("user : %s", user)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        log.info("User has logged in : %s",username )
                        return render(request, 'user_registration.html')
                else:
                    message = {'msg': "user is not having login permission"}
                    log.info("User is not having login permissions : %s", username)
            if username != "" and password == "":
                message = {'msg': "Please enter the password."}
                log.info("User did not enter the password : %s", username)
            if username == "" and password != "":
                message = {'msg': "Please enter the user name."}
                log.info("Please the user name")
            if username == "" and password == "":
                message = {'msg': "Please enter the user name and password."}
                log.info("Please enter the user name and password.")
        else:
            message = {'msg': "Please enter the user name and password to login."}
            log.info("Please enter the user name and password to login.")
        return render(request, 'login.html',message)
    except Exception as err:
        log.error("Error while login : %s" , err)

# function used to render user registration page
@login_required( login_url='/login/')
def register_user(request):
    try:
        if request.POST:
            log.info("Inside save user details")
            username = request.POST['username']
            log.info("username : %s", username)
            password = request.POST['password']
            log.info("password : %s", password)
            confirm_password = request.POST['confirmpassword']
            log.info("confirm_password : %s", confirm_password)
            email = request.POST['email']
            log.info("email : %s", email)
            mobile = request.POST['mobile']
            log.info("mobile : %s", mobile)
            if username != "" and password != "" and confirm_password != "" and email != "" and mobile != "":
                user_data = user_detail.objects.all()
                log.info("user_data : %s", user_data)
                for data in user_data:
                    if data.username == username:
                        log.info("A user with that username already exists. : %s", username)

                        return render(request, 'user_registration.html',
                                      {'msg': "A user with that username already exists."})
                    else:
                        continue
                if password == confirm_password:
                    regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
                    if re.search(regex, email):
                        pattern = re.compile("(0/91)?[6-9][0-9]{9}")
                        if pattern.match(mobile):
                            user = authenticate(request, username=username, password=password)
                            user = user_detail(username=username, password=password, email_address=email,
                                            phonenumber=mobile)
                            if user is not None:
                                user.is_staff = True
                                user.save()
                            log.info("user registered successfully.")
                            return render(request, 'user_registration.html', {'msg': "user registered successfully."})
                        else:
                            log.info("Please enter valid mobile number.")
                            return render(request, 'user_registration.html',
                                          {'msg': "Please enter valid mobile number."})
                    else:
                        log.info("Please enter valid email id.")
                        return render(request, 'user_registration.html', {'msg': "Please enter valid email id."})
                else:
                    log.info("password and confirm password is not matching.")
                    return render(request, 'user_registration.html',
                                  {'msg': "password and confirm password is not matching."})
            else:
                log.info("Please enter all the details.")
                return render(request, 'user_registration.html', {'msg': "Please enter all the details"})
        else:
            return render(request, 'user_registration.html')
    except Exception as err:
        log.error("Error while loading user registration page : %s",err)

# function is used to fetch all user details from the database
def get_user_details(request):
    Users = {}
    try:
        user_data = user_detail.objects.all()
        log.info("user_data : %s",user_data)
        all_user_data = []
        for data in user_data:
            user = {}
            user['uname'] = data.username
            user['passw'] = data.password
            user['email'] = data.email_address
            user['mobile'] = data.phonenumber
            all_user_data.append(user)
        Users['userdata'] = all_user_data
    except Exception as err:
        log.error("Error while fething the data from database : %s", err)
    return Users


# function used to display modify user page
@login_required( login_url='/login/')
def modify_user(request):
   try:
       Users = get_user_details(request)
       current_user = {}
       active_user = request.user.username
       log.info("active_user : %s", active_user)
       superusers = User.objects.filter(is_superuser=True)
       for uname in superusers:
           log.info("super user name : %s", uname.username)
           if active_user == uname.username:
               current_user['cur_user'] = "super_user"
               break
           else:
               current_user['cur_user'] = active_user
       Users['current_user'] = current_user
       log.info("All users rgisterer in system : %s", Users)
       return render(request, 'modifyuser.html', Users)
   except Exception as err:
       log.error("Error to fetch modify user page : %s", err)

# function is used to modify the user data and save into the database
@login_required( login_url='/login/')
def modify_user_detail(request):
    try:
        username = request.POST['username1']
        log.info("modify data username : %s", username)
        Users = get_user_details(request)
        current_user = {}
        active_user = request.user.username
        log.info("active_user : %s", active_user)
        superusers = User.objects.filter(is_superuser=True)
        for uname in superusers:
            log.info("super user name : %s", uname.username)
            if active_user == uname.username:
                current_user['cur_user'] = "super_user"
                break
            else:
                current_user['cur_user'] = active_user
        Users['current_user'] = current_user
        if username != "No user registered":
            password = request.POST['password']
            confirm_password = request.POST['confirmpassword']
            email = request.POST['email']
            mobile = request.POST['mobile']
            print("request.POST", request.POST)
            if username != "" and password != "" and confirm_password != "" and email != "" and mobile != "":
                if password == confirm_password:
                    user = user_detail.objects.get(username=username)
                    user.username = username
                    user.password = password
                    user.email_address = email
                    user.phonenumber = mobile
                    user.save()
                    Users = get_user_details(request)
                    Users['current_user'] = current_user
                    log.info("Users data after modification : %s", Users)
                    log.info("user data modified successfully.")
                    Users['msg'] = "user data modified successfully."
                    return render(request, 'modifyuser.html', Users)
                else:
                    log.info("password and confirm password is not matching.")
                    Users['msg'] = "password and confirm password is not matching."
                    return render(request, 'modifyuser.html', Users)
            else:
                log.info("Please enter all the details")
                Users['msg'] = "Please enter all the details"
                return render(request, 'modifyuser.html', Users)
        else:
            log.info("There is no user registered to modify")
            Users['msg'] = "There is no user registered to modify"
            return render(request, 'modifyuser.html', Users)
    except Exception as err:
        log.error("Error while modifying the details : %s" , err)

# function is used to render the delete user page
@login_required( login_url='/login/')
def delete_user(request):
    try:
        Users = get_user_details(request)
        return render(request, 'deleteuser.html', Users)
    except Exception as err:
        log.error("Error while fetching delete user page : %s", err)

# function is used to delete the user data.
@login_required( login_url='/login/')
def delete_user_data(request):
    try:
        username = request.POST['username1']
        Users = get_user_details(request)
        current_user = {}
        active_user = request.user.username
        log.info("active_user : %s", active_user)
        current_user['cur_user'] = active_user
        Users['current_user'] = current_user
        log.info("users registered : %s", Users)
        log.info("username to be deleted : %s", username)
        if username != "No user registered":
            if username != active_user:
                user = user_detail.objects.get(username=username)
                user.delete()
                Users = get_user_details(request)
                log.info("user data deleted successfully.")
                Users['msg'] = "user data deleted successfully."
                log.info("User name after deleting the user : %s",Users)
                return render(request, 'deleteuser.html', Users)
            else:
                log.info("Currently active user. Can't delete the user")
                Users['msg'] = "Currently active user. Can't delete the user"
                return render(request, 'deleteuser.html', Users)
        else:
            log.info("There is no user registered to delete")
            Users['msg'] = "There is no user registered to delete"
            return render(request, 'deleteuser.html', Users)
    except Exception as err:
        log.error("Wrror while deliting the data : %s",err)

# function used to view the user details registered into system.
@login_required( login_url='/login/')
def view_user(request):
    try:
        Users = get_user_details(request)
        return render(request, 'viewuser.html', Users)
    except Exception as err:
        log.error("Error while loading view user page : %s", err)

# function is used to logout the user
@login_required( login_url='/login/')
def logout_user(request):
    try:
        active_user = request.user.username
        log.info("logout request is received from the user : %s",active_user)
        logout(request)
        return render(request, 'login.html')
    except Exception as err:
        log.error("Error while logging out the user : %s" ,err)


# Phase 2 implementation
class user_detail_list(APIView):
    def get(self,request):
        userid= self.request.query_params.get('id')
        print("userid", userid)
        if userid == None:
            user_details = user_detail.objects.all()
            print("user_details", user_details)
        else:
            user_details = user_detail.objects.filter(id=userid)
            print("user_details",user_details)
        serializer= user_detailSerializer(user_details,many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer=user_detailSerializer(data=request.data)
        print("request.data",request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
