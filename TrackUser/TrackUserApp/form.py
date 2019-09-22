from django import forms
from django.forms import ModelForm
from .models import user_detail

class UserFormData(forms.ModelForm):

    class Meta:
        model = user_detail
        fields=['username','password','email_address','phonenumber']