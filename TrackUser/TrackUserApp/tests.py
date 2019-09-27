from django.test import TestCase

# Create your tests here.
data={
    "username": "testuser7",
    "password": "test@123",
    "email": "test@gmail.com",
    "phonenumber": 9999999999
}
user_details={}
userdata={}
userdata['username']=data['username']
userdata['password']=data['password']
userdata['email']=data['email']
user_details['user'] = userdata
user_details['phonenumber'] = data['phonenumber']
print("user_details",user_details)