import os

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Stops workers for the TestService in the background."

    def handle(self, *args, **options):
        os.system("killall -9 starttestserviceworker")

        return
