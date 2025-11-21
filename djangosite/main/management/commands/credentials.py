import logging
import os
import secrets
import string

import pandas
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand

ALPHABET = string.ascii_letters + string.digits

INTAKE_FORM_PATH = "ANONYMIZED"

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Processes the intake form by setting passwords and sending emails."

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

        # Set password for user
        for user in existing_users:
            password = "".join(secrets.choice(ALPHABET) for i in range(12))
            user.set_password(password)

            user.save()
            logger.info(f"Modified user {user.username} with email {user.email}")

            # Send email
            message = EmailMessage(
                "Suricata CTF - Account Credentials",
                f"""Dear CTF participant ({user.username}),

Thank you for signing up for the Suricata CTF. Your account for https://ctf.anonymized.net/ has been created and you can now log in using the following credentials:

Username: {user.username}
Password: {password}

If you have any questions or issues, please do not hesitate to contact us.

Kind regards,
ANONYMIZED
""",
                os.environ.get("DEFAULT_FROM_EMAIL"),
                [user.email],
                bcc=["ANONYMIZED"],
            )

            message.send(
                fail_silently=False,
            )

        return
