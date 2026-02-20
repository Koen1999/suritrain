from datetime import date

from django.apps import AppConfig
from django.utils.timezone import localdate, localtime


class MainConfig(AppConfig):
    name = "main"
    startup_date: date

    def ready(self) -> None:
        self.startup_date = localdate()
        self.startup_time = localtime()
