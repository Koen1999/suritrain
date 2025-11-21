import logging
import time

from django.core.management.base import BaseCommand

from ...models import Result, Submission
from ...service import TestService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Stops workers for the TestService in the background and restarts the test service."

    def handle(self, *args, **options):
        TestService.stop()

        time.sleep(5)

        Result.objects.all().delete()
        Submission.objects.all().update(tested=False)

        return
