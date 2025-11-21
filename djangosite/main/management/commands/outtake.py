import logging
import os
import string

import pandas
from django.contrib.auth.models import Group, User
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand

ALPHABET = string.ascii_letters + string.digits

INTAKE_FORM_PATH = "ANONYMIZED"

OUTTAKE_FORM_URL = "ANONYMIZED"
LECTURE_URL_PRINCIPLES = "ANONYMIZED"
LECTURE_URL_SAMPLE_SOLUTIONS = "ANONYMIZED"

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Processes the intake form by sending emails to fill in the outtake form."

    def handle(self, *args, **options):
        # Load intake form into a dataframe
        df = pandas.read_excel(INTAKE_FORM_PATH)

        if len(df.index) == 0:
            logger.error("No users found in the intake form.")
            return

        # Detect already existing users
        existing_users = User.objects.filter(
            username__in=df[
                "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
            ]
        )
        if not existing_users:
            logger.error("No users found in the intake form that have passed intake.")
            return

        # Prepare group object
        group_hidden = Group.objects.get(name="Leaderboard - Hidden")

        # Set password for user
        for user in existing_users:
            try:
                user_group_id = int(
                    user.groups.get(name__contains="Experiment Group - ").name.replace(
                        "Experiment Group - ", ""
                    )
                )
            except ObjectDoesNotExist:
                user_group_id = None
            logger.info(f"Reminding user {user.username} with email {user.email}")

            user.groups.add(group_hidden)

            if user_group_id == 1:
                optional_instruction = f"""
Since you were part of the group that did not receive the additional instruction before the CTF, we would still like to offer you the opportunity to have this additional instruction afterwards.
If you are interested in learning more about design principles for writing rules while accounting for specificity and coverage, this will be interesting for you.

You can find the additional instruction here: {LECTURE_URL_PRINCIPLES}
"""
            else:
                optional_instruction = ""

            # Send email
            message = EmailMessage(
                "Suricata CTF - Outtake",
                """Dear CTF participant ({}),

Thank you for participating in the Suricata CTF. We hope you had a great time!

We would like to remind you to fill in the outtake form to complete your participation in the CTF.
The outtake form is important since it helps us to improve the CTF for future editions and provide us with a better understanding of the collected data for our research.

You can find the form here: {}
{}
We have adjusted the CTF platform to show you your score including results from hidden tests on the leaderboard.
The platform will remain available for a while, so if you want to try and further perfect your rules and scores, feel free to take up this challenge.

If you would like to see sample solutions to the various scenarios, we have prepared some examples for you, which you can review here: {}

If you have any questions or issues, please do not hesitate to contact us.

Kind regards,
ANONYMIZED
""".format(
                    user.username,
                    OUTTAKE_FORM_URL,
                    optional_instruction,
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
