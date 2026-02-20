import logging
import os
import string

from django.contrib.auth.models import Group, User
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand

ALPHABET = string.ascii_letters + string.digits

LEADERBOARD_GROUP: str = "Leaderboard - SOC"

LECTURE_URL_SAMPLE_SOLUTIONS = (
    "ANONYMIZED"
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Processes the intake form by sending emails to fill in the outtake form."

    def handle(self, *args, **options) -> None:  # noqa: ANN002, ANN003, ARG002
        existing_users = User.objects.filter(
            groups__name=LEADERBOARD_GROUP,
        )
        if not existing_users:
            logger.error("No users found in the intake form that have passed intake.")
            return

        # Prepare group object
        group_hidden, _ = Group.objects.get_or_create(name="Leaderboard - Hidden")

        # Set password for user
        for user in existing_users:
            logger.info("Reminding user %s with email %s", user.username, user.email)

            user.groups.add(group_hidden)

            # Send email
            message = EmailMessage(
                "Suricata CTF - Outtake",
                """Dear CTF participant ({}),

Thank you for participating in the Suricata CTF. We hope you had a great time!

We have adjusted the CTF platform to show you your score including results from hidden tests on the leaderboard.
The platform will remain available for a while, so if you want to try and further perfect your rules and scores, feel free to take up this challenge.

If you would like to see sample solutions to the various scenarios, we have prepared some examples for you, which you can review here: {}

If you have any questions or issues, please do not hesitate to contact us.

Kind regards,
ANONYMIZED
""".format(  # noqa: E501
                    user.username,
                    LECTURE_URL_SAMPLE_SOLUTIONS,
                ),
                os.environ.get("DEFAULT_FROM_EMAIL"),
                [user.email],
                bcc=["ANONYMIZED"],
            )

            message.send(
                fail_silently=False,
            )

        return
