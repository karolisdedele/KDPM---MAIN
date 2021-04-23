from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import StoredPasswords, CustomUser


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(max_length=200, help_text='Required')

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2')


class CustomUserChangeForm(UserChangeForm):
    def __init__(self, *args, **kwargs):
        super(CustomUserChangeForm, self).__init__(*args, **kwargs)
        del self.fields['password']

    class Meta:
        model = CustomUser
        fields = ('username', 'email')


class PasswordForm(ModelForm):
    class Meta:
        model = StoredPasswords
        fields = ['account']
