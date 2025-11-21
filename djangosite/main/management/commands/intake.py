import logging
import os

import numpy
import pandas
import sklearn
import sklearn.model_selection
from django.contrib.auth.models import Group, User
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand

INTAKE_FORM_PATH = "ANONYMIZED"

# LEADERBOARD_GROUP = "Leaderboard - ANONYMIZED"

LECTURE_URL_GROUP1 = "ANONYMIZED"
LECTURE_URL_GROUP2 = "ANONYMIZED"

REMINDER = """ANONYMIZED"""

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Processes the intake form by creating users, assigning them to groups, and sending emails."

    def handle(self, *args, **options):
        # Load intake form into a dataframe
        df = pandas.read_excel(INTAKE_FORM_PATH)

        assert (
            df[
                "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
            ]
            .value_counts()
            .max()
            == 1
        ), "Duplicate usernames found in the intake form: {}".format(
            df[
                "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
            ]
            .value_counts()[
                df[
                    "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                ].value_counts()
                > 1
            ]
            .index.to_list()
        )

        if len(df.index) == 0:
            logger.error("No users found in the intake form.")
            return

        # Detect and drop already existing users
        existing_users = User.objects.filter(
            username__in=df[
                "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
            ]
        ).all()
        if existing_users:
            logger.warning(
                f"Found {len(existing_users)} users that already exist in the database."
            )
            df = df[
                ~df[
                    "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                ].isin([user.username for user in existing_users])
            ]

            group2_largest = (
                existing_users.filter(groups__name="Experiment Group - 2").count()
                > existing_users.filter(groups__name="Experiment Group - 1").count()
            )

            if len(df.index) == 0:
                logger.error("No users found in the intake form that do not exist yet.")
                return

        # Split users into two groups
        logger.info("Performing uniform random user group assignment")
        if len(df.index) == 1:
            df_group1 = pandas.DataFrame(columns=df.columns)
            df_group2 = df.copy()
        else:
            df_group1, df_group2 = sklearn.model_selection.train_test_split(
                df, test_size=0.5, random_state=0
            )
            # Note that in case of uneven group sizes, group2 is largest
            if existing_users and group2_largest:
                df_group1, df_group2 = df_group2, df_group1

        # Prepare group objects
        group1 = Group.objects.get(name="Experiment Group - 1")
        group2 = Group.objects.get(name="Experiment Group - 2")
        leaderboard_group = Group.objects.get(name=LEADERBOARD_GROUP)

        # Create users, assign them to groups and send emails
        for _, row in df.iterrows():
            username = row[
                "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
            ]
            email = row[
                "What is the email address you would like us to contact you on?\n"
            ]
            if (
                email is None
                or email == ""
                or (not isinstance(email, str) and numpy.isnan(email))
            ):
                logger.error(f"Email address is missing for user {username}")
                continue

            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=None,
            )
            if not user:
                logger.error(f"Failed to create user {username} with email {email}")

            is_user_group1 = (
                df_group1[
                    "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                ]
                .str.contains(user.username)
                .any()
            )

            if is_user_group1:
                user.groups.add(group1)
            else:
                user.groups.add(group2)

            user.groups.add(leaderboard_group)

            user.save()
            logger.info(f"Created user {user.username} with email {user.email}")

            # Send email
            message = EmailMessage(
                "Suricata CTF - Instruction Video Lecture and Handout",
                f"""Dear CTF participant ({user.username}),

Thank you for signing up for the Suricata CTF via Microsoft Forms. Your account for https://ctf.anonymized.net/ has been created. You will receive credentials for the platform in a separate email when the activity commences.

We have prepared a instruction lecture that will prepare you for the Capture The Flag. It covers the basics of Wireshark and Suricata, and provides an overview of the CTF platform and the scenarios you will work on during the activity.
Please, watch the lecture before the activity starts.
The slides for the lecture can be found in the attachment of this email, which you can also use as a reference during the activity.

You can find the video lecture here: {LECTURE_URL_GROUP1 if is_user_group1 else LECTURE_URL_GROUP2}

{REMINDER}
Please be sure to bring your laptop (fully charged) and a charger with you to the activity.

Although there is no need to install Suricata on your laptop, you should install Wireshark and have it ready for the activity.
You can download Wireshark from https://www.wireshark.org/download.html.

If you have any questions or issues, please do not hesitate to contact us.

Kind regards,
ANONYMIZED
""",
                os.environ.get("DEFAULT_FROM_EMAIL"),
                [email],
                bcc=["ANONYMIZED"],
            )

            if is_user_group1:
                message.attach_file("handouts/group1/handout.pdf")
            else:
                message.attach_file("handouts/group2/handout.pdf")

            message.send(
                fail_silently=False,
            )

        return
