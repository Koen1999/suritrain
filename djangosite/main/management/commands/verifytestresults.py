import logging

from django.core.management.base import BaseCommand

from ...models import Scenario, Submission

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Detect incompletely tested submissions and retest them."

    def handle(self, *args, **options):
        # Find submissions marked as tested but with incomplete results
        incomplete = False
        for scenario in Scenario.objects.all():
            test_count = scenario.tests.count()
            submissions = Submission.objects.filter(
                scenario=scenario, tested=True
            ).all()
            for submission in submissions:
                result_count = submission.results.count()
                if result_count != test_count:
                    incomplete = True
                    logger.info(
                        "Detected incomplete results for submission %s. Deleting results and marking submission as untested.",
                        submission.pk,
                    )
                    submission.results.delete()
                    submission.tested = False
                    submission.save()

        if incomplete:
            logger.warning("Incomplete test results detected and marked for retesting.")
        else:
            logger.info("No incomplete test results detected.")

        return
