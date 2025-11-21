from django.apps import AppConfig
from django.utils.timezone import localdate, localtime
from datetime import date


class MainConfig(AppConfig):
    name = "main"
    startup_date: date

    def ready(self):
        self.startup_date = localdate()
        self.startup_time = localtime()
