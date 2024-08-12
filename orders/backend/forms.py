from django import forms
from .models import User
from django.contrib.auth.forms import UserChangeForm

class LoginForm(forms.Form):
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileForm(UserChangeForm):

    username = forms.CharField(max_length=150, required=False)
    email = forms.EmailField(required=False)
    company = forms.CharField(max_length=150, required=False)
    position = forms.CharField(max_length=150, required=False)
    type = forms.CharField(max_length=150, required=False)
    photo = forms.ImageField(required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'company', 'position', 'type', 'photo']
