from typing import Any

from django.conf import settings


def platform_settings(request) -> dict[str, Any | bool]:  # noqa: ANN001, ARG001
    return {
        "REGISTRATION_ALLOWED": getattr(settings, "REGISTRATION_ALLOWED", False),
        "REGISTRATION_PASSWORD": getattr(settings, "REGISTRATION_PASSWORD", None),
    }
