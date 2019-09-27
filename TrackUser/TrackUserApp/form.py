from django import forms
from django.forms import ModelForm
from .models import user_detail
from django.contrib.auth.models import User

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    class Meta():
        model = User
        fields = ('username', 'password', 'email')

class UserProfileInfoForm(forms.ModelForm):
    class Meta():
        model = user_detail
        fields = ('phonenumber',)