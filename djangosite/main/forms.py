from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm


class RegisterForm(UserCreationForm):
    # username = forms.CharField(label="Username (also shown on leaderboard)", max_length=16, required=True)
    # password1 = forms.CharField(label="Password", max_length=32, required=True, widget=forms.PasswordInput())
    # password2 = forms.CharField(label="Confirm password", max_length=32, required=True, widget=forms.PasswordInput())

    accept_informed_consent = forms.BooleanField(
        required=True, initial=False, widget=forms.CheckboxInput()
    )

    class Meta:
        model = User
        fields = ["username", "password1", "password2", "email"]
