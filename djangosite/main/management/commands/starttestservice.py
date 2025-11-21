import logging

from django.core.management.base import BaseCommand

from ...service import TestService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Starts workers for the TestService in the background."

    def handle(self, *args, **options):

        TestService.start()

        return
