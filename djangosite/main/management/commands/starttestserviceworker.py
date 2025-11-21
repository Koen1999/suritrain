from django.core.management.base import BaseCommand

from ...service import TestService


class Command(BaseCommand):
    help = "Starts workers for the TestService in the background."

    def handle(self, *args, **options):
        TestService.start_loop()

        return
