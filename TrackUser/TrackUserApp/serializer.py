# This file is added for phase 2 implementation

from rest_framework import serializers
from .models import user_detail

class user_detailSerializer(serializers.ModelSerializer):
    class Meta:
        model=user_detail
        fields = '__all__'