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
import os
import json
from TrackUser.settings import BASE_DIR

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
                        superusers = User.objects.filter(is_superuser=True)
                        for uname in superusers:
                            log.info("super user name : %s", uname.username)
                            if username==uname.username:
                                log.info("super user has been logged in : %s", username)
                                return render(request, 'user_registration.html')
                            else:
                                log.info("End user has been logged in : %s", username)
                                return redirect('/modifyuser/')
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
        registered = False
        if request.POST:
            log.info("Inside save user details")
            username = request.POST['username']
            log.info("username : %s", username)
            password = request.POST['password']
            log.info("password : %s", password)
            email = request.POST['email']
            log.info("email : %s", email)
            mobile = request.POST['phonenumber']
            log.info("mobile : %s", mobile)
            if username != "" and password != "" and  email != "" and mobile != "":
                user_data = user_detail.objects.all()
                log.info("user_data : %s", user_data)
                for data in user_data:
                    if data == username:
                        log.info("A user with that username already exists. : %s", username)

                        return render(request, 'user_registration.html',
                                      {'msg': "A user with that username already exists."})
                    else:
                        continue
                regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
                if re.search(regex, email):
                    pattern = re.compile("(0/91)?[6-9][0-9]{9}")
                    if pattern.match(mobile):
                        user_form = UserForm(data=request.POST)
                        log.info("user registration data : %s",request.POST)
                        profile_form = UserProfileInfoForm(data=request.POST)
                        if user_form.is_valid() and profile_form.is_valid():
                            user = user_form.save()
                            user.set_password(user.password)
                            user.save()
                            profile = profile_form.save(commit=False)
                            profile.user = user
                            profile.save()
                            registered = True
                            log.info("user registered successfully.")
                            return render(request, 'user_registration.html',
                                          {'msg': "user registered successfully."})
                        else:
                            if user_form.errors!="":
                                errordata=user_form.errors['username']
                                log.error("error while registering user : %s",errordata)
                                message = {'msg': errordata}
                            log.info("user is not registered.")
                            return render(request, 'user_registration.html',message)
                    else:
                        log.info("Please enter valid mobile number.")
                        return render(request, 'user_registration.html',
                                      {'msg': "Please enter valid mobile number."})
                else:
                    log.info("Please enter valid email id.")
                    return render(request, 'user_registration.html', {'msg': "Please enter valid email id."})
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
            user['uname'] = data.user.username
            user['passw'] = data.user.password
            user['email'] = data.user.email
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
        username = request.POST['username']
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
            email = request.POST['email']
            mobile = request.POST['phonenumber']
            log.info("user data to modify : %s", request.POST)
            if username != "" and email != "" and mobile != "":
                userdata = user_detail.objects.get(user__username=username)
                users = userdata.user
                if password != "":
                    users.password = password
                users.email = email
                userdata.phonenumber = mobile
                userdata.save()
                users.save()
                Users = get_user_details(request)
                log.info("user data after modification : %s",Users)
                Users['current_user'] = current_user
                log.info("Users data after modification : %s", Users)
                log.info("user data modified successfully.")
                Users['msg'] = "user data modified successfully."
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
        username = request.POST['username']
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
                userdata = user_detail.objects.get(user__username=username)
                users=userdata.user
                users.delete()
                userdata.delete()
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
    # This function  return all the user records as well as particular user recode by user id
    def get(self,request):
        try:
            userid = self.request.query_params.get('id')
            log.info("userid : %s", userid)
            if userid == None:
                user_details = user_detail.objects.all()
                log.info("user_details : %s", user_details)
                serializer = user_detailSerializer(user_details, many=True)
            else:
                user_details = user_detail.objects.get(id=userid)
                log.info("user_details : %s", user_details)
                serializer = user_detailSerializer(user_details)
            return Response(serializer.data)
        except Exception as err:
            log.error("ERROR : %s ",err)
            log.error("Error while getting user details. User does not exist with the current user id.")
            data = {'message': 'User does not exist with the current id.'}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

    def post(self,request):
        try:
            serializer  = user_detailSerializer(data=request.data)
            log.info("create user data :%s", request.data)
            user_details = {}
            user_details['username'] = request.data['username']
            user_details['password'] = request.data['password']
            user_details['email'] = request.data['email']
            if serializer.is_valid(raise_exception=True):
                serializer.save(user=user_details)
                serializer.save(phonenumber=request.data['phonenumber'])
                log.info("User has been registered into system")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                log.debug("Entered user input is not in correct format")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as err:
            log.error("ERROR : %s", err)
            log.error("error while creating new user using REST : %s",err.args[0])
            log.error("Unable to register the user in system.")
            data = {'message': str(err.args[0])}
            return Response(data, status=status.HTTP_404_NOT_FOUND)


    def patch(self,request):
        try:
            userid = self.request.query_params.get('id')
            log.info("userid to update data : %s", userid)
            if userid == None:
                log.debug("Please provide user id in url to update the record.")
                data = {'message': 'Please provide user id in url to update the record.'}
                return Response(data, status=status.HTTP_400_BAD_REQUEST)
            else:
                user_data = user_detail.objects.get(id=userid)
                log.info("user_details : %s", user_data)
                log.info("create user data :%s", request.data)
                user_details = {}
                if 'username' in request.data.keys():
                    user_details['username'] = request.data['username']
                if'password'  in request.data.keys():
                    user_details['password'] = request.data['password']
                if 'email' in request.data.keys():
                    user_details['email'] = request.data['email']
                    log.info("user_details to modify user data: %s",user_details)
                serializer = user_detailSerializer(user_data, data=request.data,
                                                   partial=True)  # set partial=True to update a data partially
                if serializer.is_valid():
                    if len(user_details)>0:
                        serializer.save(user=user_details)
                    if 'phonenumber' in request.data.keys():
                        serializer.save(phonenumber=request.data['phonenumber'])
                    log.info("User details has been modified for user : %s" ,userid)
                    return Response(serializer.data, status=status.HTTP_201_CREATED, )
                log.debug("Entered user input is not in correct format")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as err:
            log.error("ERROR : %s", err)
            log.error("Error while performing partial update of data using REST : %s",err.args[0])
            log.error("User does not exist with the current id.")
            data = {'message': str(err.args[0])}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

    def delete(self,request):
        try:
            userid = self.request.query_params.get('id')
            log.info("userid to delete the record : %s", userid)
            if userid == None:
                log.debug("Please provide user id in url to delete the record.")
                data = {'message': 'Please provide user id in url to delete the record.'}
                return Response(data, status=status.HTTP_400_BAD_REQUEST)
            else:
                user_data = user_detail.objects.get(id=userid)
                users = user_data.user
                users.delete()
                log.info("user_details : %s", user_data)
                user_data.delete()
                log.info("User has been deleted from the system.")
                data = {'message': 'User has been deleted from the system.'}
                return Response(data,status=status.HTTP_200_OK)
        except Exception as err:
            log.error("ERROR : %s",err)
            log.error("User does not exist with the current id.")
            data={'message':'User does not exist with the current id.'}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

# Phase 2 implementation
class loglist(APIView):
    def get(self,request):
        try:
            data={}
            log_entry_list=[]
            log.info("Getting all log entries")
            with open(os.path.join(BASE_DIR, 'djangoproject.log')) as logfile:
                for line in logfile:
                    log_entry_list.append(line.strip())
            data['logdata']=log_entry_list
            return Response(data, status=status.HTTP_200_OK)
        except Exception as err:
            log.error("ERROR : %s ", err)

# Phase 2 implementation
class user_log_entry(APIView):
    def get(self,request):
        try:
            data = {}
            log_entry_list = []
            log.info("Getting particular user log entries")
            userid = self.request.query_params.get('id')
            log.info("userid to get logs for user : %s", userid)
            if userid == None:
                log.debug("Please provide user id in url to get the logs.")
                data = {'message': 'Please provide user id in url to get the logs.'}
                return Response(data, status=status.HTTP_400_BAD_REQUEST)
            else:
                user_data = user_detail.objects.get(id=userid)
                username=user_data.user.username
                log.info("user name for getting logs : %s",username )
                with open(os.path.join(BASE_DIR, 'djangoproject.log')) as logfile:
                    for line in logfile:
                        if username in line:
                            log_entry_list.append(line.strip())
                if len(log_entry_list)==0:
                    log.info("There is no data present in log file")
                    data={'message' : "There is no data present in log file"}
                else:
                    data['logdata'] = log_entry_list
                    log.info("Log entries has been displayed to user.")
                return Response(data, status=status.HTTP_200_OK)
        except Exception as err:
            log.error("ERROR : %s ",err)
            log.error("User does not exist with the current id to get log entries.")
            data = {'message': 'User does not exist with the current id.'}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

# Phase 2 implementation
class log_entry(APIView):
    def post(self,request):
        try:
            log_entry_list = []
            logdata = request.data
            log.info("log data to store into logfile : %s", logdata)
            with open(os.path.join(BASE_DIR, 'djangoproject.log')) as logfile:
                for line in logfile:
                    log_entry_list.append(line.strip())
            log_entry_list.extend(logdata['logs'])
            with open(os.path.join(BASE_DIR, 'djangoproject.log'), 'w') as logfile:
                for data in log_entry_list:
                    logfile.write(data)
                    logfile.write("\n")
            data = {'message': 'Data has been written into log file.'}
            log.info("Data has been written into log file.")
            return Response(data, status=status.HTTP_200_OK)
        except Exception as err:
            log.error("ERROR : %s", err)
            log.error("Input data format is not correct. Unable to post data into log file.")
            data = {'message': 'Input data format is not correct. Unable to post data into log file.'}
            return Response(data, status=status.HTTP_400_BAD_REQUEST)