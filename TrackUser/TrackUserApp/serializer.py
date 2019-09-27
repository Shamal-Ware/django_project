# This file is added for phase 2 implementation

from rest_framework import serializers
from .models import user_detail
from django.contrib.auth.models import User
from TrackUser.logger import log

class user_serializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=('username','password','email')


class user_detailSerializer(serializers.ModelSerializer):

    user=user_serializer(read_only=True)
    class Meta:
        model=user_detail
        fields = ('user','phonenumber','id')

    def create(self, validated_data):
        try:
            log.info("validated_data : %s", validated_data)
            profile_data = validated_data.pop('phonenumber')
            userdata = validated_data.pop('user')
            username = userdata["username"]
            password = userdata["password"]
            email = userdata["email"]
            user = User.objects.create(username=username, password=password, email=email)
            user.save()
            log.info("User is created : %s",username)
            user_details=user_detail.objects.create(user=user, phonenumber=profile_data)
            user_details.save()
            log.info("mobile nmber is allocated to the user : %s",username)
            return user_details
        except Exception as err:
            log.error("Error while generating user detail: %s ",err)
            raise serializers.ValidationError(err)

    def update(self, user_data, validated_data):
        try:
            log.info("validated_data : %s", validated_data)
            log.info("user data to update : %s", user_data)
            if 'phonenumber' in validated_data.keys():
                user_data.phonenumber = validated_data['phonenumber']
            if 'user' in validated_data.keys():
                users = user_data.user
                if 'username' in validated_data['user'].keys():
                    users.username = validated_data['user']['username']
                if 'password' in validated_data['user'].keys():
                    users.password = validated_data['user']['password']
                if 'email' in validated_data['user'].keys():
                    users.email = validated_data['user']['email']
                users.save()
            user_data.save()
            user_data = user_detail.objects.get(id=user_data.id)
            log.info("User data after modification : %s",user_data)
            return user_data
        except Exception as err:
            log.error("Error while generating user detail: : %s", err)
            raise serializers.ValidationError(err)

