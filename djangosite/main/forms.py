from typing import Optional

from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm, UsernameField
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


class RegisterForm(UserCreationForm):
    code = forms.CharField(
        label="Registration Code",
        max_length=32,
        required=True,
        widget=forms.TextInput(),
    )

    informed_consent = forms.ChoiceField(
        choices={"false": False, "true": True},
        required=True,
        widget=forms.RadioSelect(),
    )

    @property
    def accept_informed_consent(self) -> bool:
        return self.cleaned_data.get("informed_consent") == "true"

    def clean_code(self) -> Optional[str]:
        code = self.cleaned_data.get("code")

        if (
            code is None
            or not isinstance(code, str)
            or (
                getattr(settings, "REGISTRATION_PASSWORD", None) is not None
                and code != getattr(settings, "REGISTRATION_PASSWORD", None)
            )
        ):
            self._update_errors(ValidationError({"code": "Invalid registration code."}))
            return None
        return code

    class Meta:
        model = User
        fields = [
            "username",
            "password1",
            "password2",
            "email",
            # "accept_informed_consent",
            "informed_consent",
            "code",
        ]
        field_classes = {"username": UsernameField}
