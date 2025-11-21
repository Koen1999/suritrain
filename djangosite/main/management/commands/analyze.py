import difflib
import logging
import re
import traceback
from collections import defaultdict
from typing import Optional

import idstools
import idstools.rule
import numpy
import pandas
import suricata_check
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db.models import (
    Sum,
)
from Levenshtein import distance
from multiset import Multiset

from ...grading import grade_intake, grade_intake_pilot
from ...models import Result, Scenario, Submission
from ...utils import (
    get_user_ordered_scenarios,
    get_user_scenario_scores,
    get_user_scores,
)

INTAKE_FORM_PATHS = {"ANONYMIZED"}

NON_FUNCTIONAL_FIELDS = [
    "msg",
    "classtype",
    "sid",
    "rev",
    "metadata",
    "reference",
    "target",
    "priority",
]
PROTO_TREE = defaultdict(
    list,
    {"udp": ["dns"], "tcp": ["http", "tls", "tcp-pkt", "tcp-stream", "smb", "ssh"]},
)

logger = logging.getLogger(__name__)

logging.getLogger("suricata_check").setLevel(logging.ERROR)


class Command(BaseCommand):
    help = "Prepares dataframes for data analysis based on intake, lecture, and outtake forms, leaderboard data, and rule submissions."

    @staticmethod
    def seconds_worked_towards_scenario_submission(row):
        seconds = 0
        working_on_scenario = False
        previous_submitted_at = None
        for submission in (
            Submission.objects.filter(
                user__id=row["User ID"],
                submitted_at__lt=row["submitted_at"],
            )
            .order_by("submitted_at")
            .all()
        ):
            if submission.scenario.title == row["Scenario"]:
                if previous_submitted_at is not None:
                    seconds += (
                        submission.submitted_at - previous_submitted_at
                    ).total_seconds()
                working_on_scenario = True
            else:
                if working_on_scenario:
                    seconds += (
                        submission.submitted_at - previous_submitted_at
                    ).total_seconds()
                    working_on_scenario = False
            previous_submitted_at = submission.submitted_at

        if previous_submitted_at is not None:
            seconds += (row["submitted_at"] - previous_submitted_at).total_seconds()

        return seconds

    def handle(self, *args, **options):
        # Load intake form into a dataframe
        logger.info("Collecting participant data from questionnaire")

        df_intake = pandas.concat(pandas.read_excel(path) for path in INTAKE_FORM_PATHS)
        df_lecture = pandas.read_excel(
            "forms/Capture the Flag - Network Intrusion Detection rule engineering with Suricata - Lecture.xlsx"
        )
        df_outtake = pandas.read_excel(
            "forms/Capture the Flag - Network Intrusion Detection rule engineering with Suricata - Outtake.xlsx"
        )

        df_intake.set_index(
            df_intake[
                "What is the email address you would like us to contact you on?\n"
            ]
        )
        df_lecture.set_index(
            df_lecture["What is the email address you previously shared with us?\n"]
        )
        df_outtake.set_index(
            df_outtake[
                "What is the email address you would like us to contact you on?\n"
            ]
        )
        df_grading = df_intake.join(df_lecture, how="left", rsuffix="_lecture").join(
            df_outtake, how="left", rsuffix="_outtake"
        )

        # participant_df = grade_intake_pilot(df_intake)
        # participant_df = grade_intake(df_grading)
        try:
            participant_df = grade_intake_pilot(df_intake)
        except:
            participant_df = grade_intake(df_grading)

        participant_df = participant_df[participant_df["Informed Consent Granted"]]

        participant_df = participant_df[
            participant_df["username"].apply(lambda x: x not in ("Epa13_2",))
        ]

        logger.info("Collecting participant data from platform")

        participant_df["Participated"] = participant_df["username"].apply(
            lambda username: Submission.objects.filter(user__username=username).exists()
        )
        (
            participant_df["Score"],
            _,
            participant_df["Hidden Score"],
            _,
        ) = zip(
            *participant_df["username"].apply(
                lambda username: get_user_scores(User.objects.get(username=username))
            )
        )
        participant_df["Scenario Order"] = participant_df["username"].apply(
            lambda username: ",".join(
                [
                    scenario.title
                    for scenario in get_user_ordered_scenarios(
                        User.objects.get(username=username)
                    )
                ]
            )
        )
        for scenario in Scenario.objects.all():
            (
                participant_df[scenario.title + " Score"],
                _,
                participant_df[scenario.title + " Hidden Score"],
                _,
            ) = zip(
                *participant_df["username"].apply(
                    lambda username: get_user_scenario_scores(
                        User.objects.get(username=username), scenario
                    )
                )
            )
        participant_df["Participant Pool"] = participant_df["username"].apply(
            lambda username: User.objects.get(username=username)
            .groups.exclude(name__in=["Leaderboard - Hide", "Leaderboard - Hidden"])
            .get(name__contains="Leaderboard - ")
            .name.replace("Leaderboard - ", "")
        )
        participant_df["Had Design Principle Instruction"] = participant_df[
            "username"
        ].apply(
            lambda username: int(
                User.objects.get(username=username)
                .groups.get(name__contains="Experiment Group - ")
                .name.replace("Experiment Group - ", "")
            )
            == 2
        )

        participant_df["User ID"] = participant_df["username"].apply(
            lambda username: User.objects.get(username=username).pk
        )
        # participant_df = participant_df.drop(columns=["username"])
        participant_df = participant_df.set_index("User ID")
        participant_df = participant_df.sort_index()

        logger.info("Collecting rule data")

        rule_df = pandas.DataFrame(
            list(
                Submission.objects.filter(user__id__in=participant_df.index)
                .values(
                    "check_only",
                    "id",
                    "rule",
                    "scenario__title",
                    "submitted_at",
                    "user__id",
                    "valid",
                )
                .order_by("submitted_at")
            )
        ).rename(
            {
                "user__id": "User ID",
                "scenario__title": "Scenario",
                "valid": "Valid",
                "id": "Rule ID",
                "rule": "Rule",
            },
            axis=1,
        )
        rule_df["Submission"] = rule_df["check_only"].apply(
            lambda check_only: not check_only
        )
        rule_df["Score"] = rule_df["Rule ID"].apply(
            lambda rule_id: Submission.objects.get(id=rule_id).score
        )
        rule_df["Hidden Score"] = rule_df["Rule ID"].apply(
            lambda rule_id: Submission.objects.get(id=rule_id).hidden_score
        )
        rule_df["Number of Alerts"] = rule_df["Rule ID"].apply(
            lambda rule_id: Submission.objects.get(id=rule_id).results.aggregate(
                Sum("n_alerts")
            )["n_alerts__sum"]
        )

        def get_user_ctf_start_time(user_id):
            rule_pool = participant_df.loc[user_id]["Participant Pool"]

            ctf_start_time = None
            for path, (pool, start_time, end_time) in INTAKE_FORM_PATHS.items():
                if rule_pool == pool:
                    ctf_start_time = start_time

            assert ctf_start_time is not None

            return ctf_start_time

        try:
            participant_df["Watched Lecture Before CTF"] = (
                participant_df.index.to_series().apply(get_user_ctf_start_time)
                > participant_df["Watched Lecture On"]
            )
        except:
            participant_df["Watched Lecture Before CTF"] = False
        participant_df = participant_df.drop(columns=["Watched Lecture On"])

        def get_user_ctf_end_time(user_id):
            rule_pool = participant_df.loc[user_id]["Participant Pool"]

            ctf_end_time = None
            for path, (pool, start_time, end_time) in INTAKE_FORM_PATHS.items():
                if rule_pool == pool:
                    ctf_end_time = end_time

            assert ctf_end_time is not None

            return ctf_end_time

        def is_submitted_during_ctf(row):
            return row["submitted_at"] < get_user_ctf_end_time(row["User ID"])

        rule_df["Submitted During CTF"] = rule_df.apply(
            is_submitted_during_ctf,
            axis=1,
        )
        rule_df["Final Valid Submitted Rule"] = rule_df.apply(
            lambda row: (
                Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                )
                .order_by("submitted_at")
                .last()
                .pk
                == row["Rule ID"]
                if Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                )
                .order_by("submitted_at")
                .last()
                else False
            ),
            axis=1,
        )
        rule_df["Final Valid Submitted Rule During CTF"] = rule_df.apply(
            lambda row: (
                Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                    submitted_at__lt=get_user_ctf_end_time(row["User ID"]),
                )
                .order_by("submitted_at")
                .last()
                .pk
                == row["Rule ID"]
                if Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                    submitted_at__lt=get_user_ctf_end_time(row["User ID"]),
                )
                .order_by("submitted_at")
                .last()
                else False
            ),
            axis=1,
        )
        rule_df["First Rule"] = rule_df.apply(
            lambda row: Submission.objects.filter(
                user__id=row["User ID"], scenario__title=row["Scenario"]
            )
            .order_by("submitted_at")
            .first()
            .pk
            == row["Rule ID"],
            axis=1,
        )
        rule_df["First Valid Submitted Rule"] = rule_df.apply(
            lambda row: (
                Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                )
                .order_by("submitted_at")
                .first()
                .pk
                == row["Rule ID"]
                if Submission.objects.filter(
                    user__id=row["User ID"],
                    scenario__title=row["Scenario"],
                    valid=True,
                    check_only=False,
                )
                .order_by("submitted_at")
                .first()
                else False
            ),
            axis=1,
        )
        rule_df["Seconds Since First User Submission"] = rule_df.apply(
            lambda row: (
                row["submitted_at"]
                - Submission.objects.filter(user__id=row["User ID"])
                .order_by("submitted_at")
                .first()
                .submitted_at
            ).total_seconds(),
            axis=1,
        )
        rule_df["Seconds Since First User Scenario Submission"] = rule_df.apply(
            lambda row: (
                row["submitted_at"]
                - Submission.objects.filter(
                    user__id=row["User ID"], scenario__title=row["Scenario"]
                )
                .order_by("submitted_at")
                .first()
                .submitted_at
            ).total_seconds(),
            axis=1,
        )
        rule_df["Seconds Worked Towards Scenario Submission"] = rule_df.apply(
            self.seconds_worked_towards_scenario_submission,
            axis=1,
        )
        mask_tested = ~rule_df["Score"].isna()

        rule_df["Recall Visible"] = numpy.nan
        rule_df["Precision Visible"] = numpy.nan
        rule_df.loc[mask_tested, "Recall Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=True,
                test__hidden=False,
                status__in=["Success", "Warning"],
            )
            .count()
            / Submission.objects.get(id=id)
            .results.filter(test__expected=True, test__hidden=False)
            .count()
        )
        rule_df.loc[mask_tested, "Precision Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=False, test__hidden=False, status__in=["Success"]
            )
            .count()
            / Submission.objects.get(id=id)
            .results.filter(test__expected=False, test__hidden=False)
            .count()
        )
        rule_df["F1 Visible"] = (
            2
            * (rule_df["Precision Visible"] * rule_df["Recall Visible"])
            / (rule_df["Precision Visible"] + rule_df["Recall Visible"] + 1e-10)
        ).round(2)

        rule_df["Recall Invisible"] = numpy.nan
        rule_df["Precision Invisible"] = numpy.nan
        rule_df.loc[mask_tested, "Recall Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: (
                (
                    Submission.objects.get(id=id)
                    .results.filter(
                        test__expected=True,
                        test__hidden=True,
                        status__in=["Success", "Warning"],
                    )
                    .count()
                    / Submission.objects.get(id=id)
                    .results.filter(test__expected=True, test__hidden=True)
                    .count()
                )
                if Submission.objects.get(id=id)
                .results.filter(test__expected=True, test__hidden=True)
                .exists()
                else numpy.nan
            )
        )
        rule_df.loc[mask_tested, "Precision Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=False, test__hidden=True, status__in=["Success"]
            )
            .count()
            / Submission.objects.get(id=id)
            .results.filter(test__expected=False, test__hidden=True)
            .count()
        )
        rule_df["F1 Invisible"] = (
            2
            * (rule_df["Precision Invisible"] * rule_df["Recall Invisible"])
            / (rule_df["Precision Invisible"] + rule_df["Recall Invisible"] + 1e-10)
        ).round(2)

        rule_df["Recall"] = numpy.nan
        rule_df["Precision"] = numpy.nan
        rule_df.loc[mask_tested, "Recall"] = rule_df.loc[mask_tested, "Rule ID"].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(test__expected=True, status__in=["Success", "Warning"])
            .count()
            / Submission.objects.get(id=id).results.filter(test__expected=True).count()
        )
        rule_df.loc[mask_tested, "Precision"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(test__expected=False, status__in=["Success"])
            .count()
            / Submission.objects.get(id=id).results.filter(test__expected=False).count()
        )
        rule_df["F1"] = (
            2
            * (rule_df["Precision"] * rule_df["Recall"])
            / (rule_df["Precision"] + rule_df["Recall"] + 1e-10)
        ).round(2)

        rule_df["TPs Visible"] = numpy.nan
        rule_df["FPs Visible"] = numpy.nan
        rule_df["TNs Visible"] = numpy.nan
        rule_df["FNs Visible"] = numpy.nan
        rule_df.loc[mask_tested, "TPs Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=True,
                test__hidden=False,
                status__in=["Success", "Warning"],
            )
            .count()
        )
        rule_df.loc[mask_tested, "FPs Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=False, test__hidden=False, status__in=["Failure"]
            )
            .count()
        )
        rule_df.loc[mask_tested, "TNs Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=False,
                test__hidden=False,
                status__in=["Success"],
            )
            .count()
        )
        rule_df.loc[mask_tested, "FNs Visible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=True, test__hidden=False, status__in=["Failure"]
            )
            .count()
        )

        rule_df["TPs Invisible"] = numpy.nan
        rule_df["FPs Invisible"] = numpy.nan
        rule_df["TNs Invisible"] = numpy.nan
        rule_df["FNs Invisible"] = numpy.nan
        rule_df.loc[mask_tested, "TPs Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: (
                (
                    Submission.objects.get(id=id)
                    .results.filter(
                        test__expected=True,
                        test__hidden=True,
                        status__in=["Success", "Warning"],
                    )
                    .count()
                )
                if Submission.objects.get(id=id)
                .results.filter(test__expected=True, test__hidden=True)
                .exists()
                else numpy.nan
            )
        )
        rule_df.loc[mask_tested, "FPs Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=False, test__hidden=True, status__in=["Failure"]
            )
            .count()
        )
        rule_df.loc[mask_tested, "TNs Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: (
                (
                    Submission.objects.get(id=id)
                    .results.filter(
                        test__expected=False,
                        test__hidden=True,
                        status__in=["Success"],
                    )
                    .count()
                )
                if Submission.objects.get(id=id)
                .results.filter(test__expected=True, test__hidden=True)
                .exists()
                else numpy.nan
            )
        )
        rule_df.loc[mask_tested, "FNs Invisible"] = rule_df.loc[
            mask_tested, "Rule ID"
        ].apply(
            lambda id: Submission.objects.get(id=id)
            .results.filter(
                test__expected=True, test__hidden=True, status__in=["Failure"]
            )
            .count()
        )

        rule_df["TPs"] = rule_df["TPs Visible"] + rule_df["TPs Invisible"]
        rule_df["FPs"] = rule_df["FPs Visible"] + rule_df["FPs Invisible"]
        rule_df["TNs"] = rule_df["TNs Visible"] + rule_df["TNs Invisible"]
        rule_df["FNs"] = rule_df["FNs Visible"] + rule_df["FNs Invisible"]

        rule_df.loc[rule_df["TPs"].isna(), "TPs"] = rule_df["TPs Visible"]
        rule_df.loc[rule_df["FPs"].isna(), "FPs"] = rule_df["FPs Visible"]
        rule_df.loc[rule_df["TNs"].isna(), "TNs"] = rule_df["TNs Visible"]
        rule_df.loc[rule_df["FNs"].isna(), "FNs"] = rule_df["FNs Visible"]

        rule_df["Best Submission"] = False
        rule_df["Best Submission During CTF"] = False
        rule_df["Final Best Submission During CTF"] = False
        rule_df["Best Submission On Visible Tests During CTF"] = False
        rule_df["Final Best Submission On Visible Tests During CTF"] = False
        rule_df["First Submission to Pass Visible Tests During CTF"] = False
        for scenario in rule_df["Scenario"].unique():
            participant_df[
                scenario
                + " Seconds Worked Towards First Submission to Pass Visible Tests During CTF"
            ] = numpy.nan
            for id in rule_df["User ID"].unique():
                if not rule_df.loc[
                    (rule_df["User ID"] == id) & (rule_df["Scenario"] == scenario),
                    "F1",
                ].any():
                    continue

                rule_df.loc[
                    rule_df.loc[
                        (rule_df["User ID"] == id) & (rule_df["Scenario"] == scenario),
                        "F1",
                    ].idxmax(),
                    "Best Submission",
                ] = True

                rule_df.loc[
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario
                        ),
                        "F1",
                    ]
                    .idxmax(),
                    "Best Submission During CTF",
                ] = True

                rule_df.loc[
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario
                        ),
                        "F1",
                    ][::-1]
                    .idxmax(),
                    "Final Best Submission During CTF",
                ] = True

                rule_df.loc[
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario
                        ),
                        "F1 Visible",
                    ]
                    .idxmax(),
                    "Best Submission On Visible Tests During CTF",
                ] = True

                rule_df.loc[
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario
                        ),
                        "F1 Visible",
                    ][::-1]
                    .idxmax(),
                    "Final Best Submission On Visible Tests During CTF",
                ] = True

                # TODO: Fix this below
                temp_mask = (
                    (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                    & (rule_df[rule_df["Submitted During CTF"]]["Scenario"] == scenario)
                    & (rule_df["Best Submission On Visible Tests During CTF"])
                    & (rule_df["F1 Visible"] == 1.0)
                )
                if temp_mask.sum() > 0:
                    rule_df.loc[
                        rule_df.loc[temp_mask].index[0],
                        "First Submission to Pass Visible Tests During CTF",
                    ] = True

                    participant_df.loc[
                        id,
                        scenario
                        + " Seconds Worked Towards First Submission to Pass Visible Tests During CTF",
                    ] = rule_df.loc[
                        rule_df.loc[temp_mask].index[0],
                        "Seconds Worked Towards Scenario Submission",
                    ]

        rule_df[
            "Normalized Scenario Progression Towards Final Valid Submitted Rule"
        ] = rule_df.apply(
            lambda row: (
                row["Seconds Worked Towards Scenario Submission"]
                / rule_df.loc[
                    rule_df["Final Valid Submitted Rule"]
                    & (rule_df["User ID"] == row["User ID"])
                    & (rule_df["Scenario"] == row["Scenario"]),
                    "Seconds Worked Towards Scenario Submission",
                ].max()
                if (
                    rule_df["Final Valid Submitted Rule"]
                    & (rule_df["User ID"] == row["User ID"])
                    & (rule_df["Scenario"] == row["Scenario"])
                ).sum()
                > 0
                else numpy.nan
            ),
            axis=1,
        )

        rule_df[
            "Normalized Scenario Progression Towards Final Valid Submitted Rule During CTF"
        ] = rule_df.apply(
            lambda row: row["Seconds Worked Towards Scenario Submission"]
            / rule_df.loc[
                rule_df["Final Valid Submitted Rule During CTF"]
                & (rule_df["User ID"] == row["User ID"])
                & (rule_df["Scenario"] == row["Scenario"]),
                "Seconds Worked Towards Scenario Submission",
            ].max(),
            axis=1,
        )

        rule_df[
            "Normalized Scenario Progression Towards Final Valid Submitted Rule During CTF Since Passing Visible Tests"
        ] = rule_df.apply(
            lambda row: (
                (
                    row["Seconds Worked Towards Scenario Submission"]
                    - rule_df.loc[
                        rule_df["First Submission to Pass Visible Tests During CTF"]
                        & (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"]),
                        "Seconds Worked Towards Scenario Submission",
                    ].min()
                )
                / (
                    rule_df.loc[
                        rule_df["Final Valid Submitted Rule During CTF"]
                        & (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"]),
                        "Seconds Worked Towards Scenario Submission",
                    ].max()
                    - rule_df.loc[
                        rule_df["First Submission to Pass Visible Tests During CTF"]
                        & (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"]),
                        "Seconds Worked Towards Scenario Submission",
                    ].min()
                )
                if (
                    rule_df.loc[
                        rule_df["Final Valid Submitted Rule During CTF"]
                        & (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"]),
                        "Seconds Worked Towards Scenario Submission",
                    ].max()
                    - rule_df.loc[
                        rule_df["First Submission to Pass Visible Tests During CTF"]
                        & (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"]),
                        "Seconds Worked Towards Scenario Submission",
                    ].min()
                )
                != 0
                else 0.0
            ),
            axis=1,
        )

        rule_df = rule_df.drop(columns=["check_only", "submitted_at"])
        rule_df = rule_df.set_index("Rule ID")

        logger.info("Enhancing participant dataframe with rule data")

        participant_df["Number of Rules"] = participant_df.index.to_series().apply(
            lambda id: rule_df[rule_df["User ID"] == id].shape[0]
        )

        participant_df[
            "Number of Valid Rules"
        ] = participant_df.index.to_series().apply(
            lambda id: rule_df[(rule_df["User ID"] == id) & rule_df["Valid"]].shape[0]
        )

        participant_df[
            "Number of Invalid Rules"
        ] = participant_df.index.to_series().apply(
            lambda id: rule_df[(rule_df["User ID"] == id) & ~rule_df["Valid"]].shape[0]
        )

        participant_df["Fraction of Valid Rules"] = (
            participant_df["Number of Valid Rules"] / participant_df["Number of Rules"]
        )

        for scenario in Scenario.objects.all():
            participant_df[scenario.title + " Seconds Worked Towards Scenario"] = [
                numpy.nan
            ] * len(participant_df.index)
            participant_scenario_mask = ~participant_df[
                scenario.title + " Score"
            ].isna()
            participant_df.loc[
                participant_scenario_mask,
                scenario.title + " Seconds Worked Towards Scenario",
            ] = participant_df.index.to_series()[participant_scenario_mask].apply(
                lambda id: rule_df.loc[
                    Submission.objects.filter(
                        user__id=id,
                        scenario__title=scenario.title,
                    )
                    .order_by("submitted_at")
                    .last()
                    .pk
                ]["Seconds Worked Towards Scenario Submission"]
            )

            participant_df[
                scenario.title + " Best F1 Visible"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df.loc[
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title),
                        "F1 Visible",
                    ].max()
                    if (
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title)
                    ).any()
                    else numpy.nan
                )
            )

            participant_df[
                scenario.title + " Best F1 Invisible"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df.loc[
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title),
                        "F1 Invisible",
                    ].max()
                    if (
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title)
                    ).any()
                    else numpy.nan
                )
            )

            participant_df[
                scenario.title + " Best F1"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df.loc[
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title),
                        "F1",
                    ].max()
                    if (
                        (rule_df["User ID"] == id)
                        & (rule_df["Scenario"] == scenario.title)
                    ).any()
                    else numpy.nan
                )
            )

            participant_df[
                scenario.title + " Seconds Worked Towards Scenario During CTF"
            ] = [numpy.nan] * len(participant_df.index)
            participant_scenario_mask = ~participant_df[
                scenario.title + " Score"
            ].isna()
            participant_df.loc[
                participant_scenario_mask,
                scenario.title + " Seconds Worked Towards Scenario During CTF",
            ] = participant_df.index.to_series()[participant_scenario_mask].apply(
                lambda id: rule_df[rule_df["Submitted During CTF"]].loc[
                    Submission.objects.filter(
                        user__id=id,
                        scenario__title=scenario.title,
                        submitted_at__lt=get_user_ctf_end_time(id),
                    )
                    .order_by("submitted_at")
                    .last()
                    .pk
                ]["Seconds Worked Towards Scenario Submission"]
            )

            participant_df[
                scenario.title + " Best F1 Visible During CTF"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        ),
                        "F1 Visible",
                    ]
                    .max()
                    if (
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        )
                    ).any()
                    else numpy.nan
                )
            )

            participant_df[
                scenario.title + " Best F1 Invisible During CTF"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        ),
                        "F1 Invisible",
                    ]
                    .max()
                    if (
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        )
                    ).any()
                    else numpy.nan
                )
            )

            participant_df[
                scenario.title + " Best F1 During CTF"
            ] = participant_df.index.to_series().apply(
                lambda id: (
                    rule_df[rule_df["Submitted During CTF"]]
                    .loc[
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        ),
                        "F1",
                    ]
                    .max()
                    if (
                        (rule_df[rule_df["Submitted During CTF"]]["User ID"] == id)
                        & (
                            rule_df[rule_df["Submitted During CTF"]]["Scenario"]
                            == scenario.title
                        )
                    ).any()
                    else numpy.nan
                )
            )

        logger.info("Detecting rule issues")

        rule_df["Design Principle Issues"] = ""
        rule_df["Design Principle Issues Count"] = numpy.nan
        for i, rule in zip(rule_df.index, rule_df["Rule"]):
            parsed_rule = None
            try:
                # parsed_rule = idstools.rule.parse(rule)
                parsed_rule = idstools.rule.parse(rule.replace("\\\n", " ").strip())
            except:
                rule_df.loc[i, "Design Principle Issues"] = numpy.nan
            if parsed_rule is not None:
                try:
                    issues = suricata_check.analyze_rule(
                        parsed_rule,
                        checkers=suricata_check.get_checkers(include=("Q.*",)),
                    ).issues
                    if issues:
                        rule_df.loc[i, "Design Principle Issues"] = ",".join(
                            sorted([issue.code for issue in issues])
                        )
                        rule_df.loc[i, "Design Principle Issues Count"] = len(
                            rule_df.loc[i, "Design Principle Issues"].split(",")
                        )
                except suricata_check.utils.checker_typing.InvalidRuleError:
                    pass
                except Exception as e:
                    logger.error(f"Error analyzing rule: {rule}")
                    logger.error("".join(traceback.format_exception(e)))
                    pass

        rule_df["Normalized Functionalized Rule"] = numpy.nan
        rule_df["Normalized Functionalized Rule"] = rule_df.loc[
            rule_df["Valid"], "Rule"
        ].apply(normalize_functionalize_rule)

        participant_df["Participated in Scenarios"] = participant_df.apply(
            lambda row: ",".join(
                sorted(
                    list(rule_df[rule_df["User ID"] == row.name]["Scenario"].unique())
                )
            ),
            axis=1,
        )
        participant_df["Participated in Scenarios Number"] = participant_df.apply(
            lambda row: rule_df[rule_df["User ID"] == row.name]["Scenario"].nunique(),
            axis=1,
        )

        participant_df["Passed Visible Tests in Scenarios"] = participant_df.apply(
            lambda row: ",".join(
                sorted(
                    list(
                        rule_df[
                            (rule_df["User ID"] == row.name)
                            & rule_df[
                                "First Submission to Pass Visible Tests During CTF"
                            ]
                        ]["Scenario"].unique()
                    )
                )
            ),
            axis=1,
        )
        participant_df["Passed Visible Tests in Scenarios Number"] = (
            participant_df.apply(
                lambda row: rule_df[
                    (rule_df["User ID"] == row.name)
                    & rule_df["First Submission to Pass Visible Tests During CTF"]
                ]["Scenario"].nunique(),
                axis=1,
            )
        )

        logger.info("Computing overall metrics")

        participant_df["Best Overall Precision During CTF"] = numpy.nan
        participant_df["Best Overall Recall During CTF"] = numpy.nan
        participant_df["Best Overall F1 During CTF"] = numpy.nan
        participant_df["Best Overall Precision Visible During CTF"] = numpy.nan
        participant_df["Best Overall Recall Visible During CTF"] = numpy.nan
        participant_df["Best Overall F1 During Visible CTF"] = numpy.nan
        participant_df["Best Overall Precision Invisible During CTF"] = numpy.nan
        participant_df["Best Overall Recall Invisible During CTF"] = numpy.nan
        participant_df["Best Overall F1 Invisible During CTF"] = numpy.nan
        participant_df[
            "Overall Design Principle Issues Count for with Final Best Submission During CTF"
        ] = numpy.nan
        participant_df[
            "Overall Seconds Worked Towards First Submission to Pass Visible Tests During CTF"
        ] = numpy.nan
        for participant in participant_df.index:
            mask = (rule_df["User ID"] == participant) & rule_df[
                "Final Best Submission During CTF"
            ]
            precision = (
                rule_df.loc[mask, "TPs"].sum()
                / (
                    rule_df.loc[mask, "TPs"].sum()
                    + rule_df.loc[mask, "FPs"].sum()
                    + 1e-10
                )
            ).round(2)
            recall = (
                rule_df.loc[mask, "TPs"].sum()
                / (
                    rule_df.loc[mask, "TPs"].sum()
                    + rule_df.loc[mask, "FNs"].sum()
                    + 1e-10
                )
            ).round(2)
            f1 = (2 * (precision * recall) / (precision + recall + 1e-10)).round(2)
            participant_df.loc[participant, "Best Overall Precision During CTF"] = (
                precision
            )
            participant_df.loc[participant, "Best Overall Recall During CTF"] = recall
            participant_df.loc[participant, "Best Overall F1 During CTF"] = f1

            # visible tests only
            mask = (rule_df["User ID"] == participant) & rule_df[
                "Final Best Submission During CTF"
            ]
            precision = (
                rule_df.loc[mask, "TPs Visible"].sum()
                / (
                    rule_df.loc[mask, "TPs Visible"].sum()
                    + rule_df.loc[mask, "FPs Visible"].sum()
                    + 1e-10
                )
            ).round(2)
            recall = (
                rule_df.loc[mask, "TPs Visible"].sum()
                / (
                    rule_df.loc[mask, "TPs Visible"].sum()
                    + rule_df.loc[mask, "FNs Visible"].sum()
                    + 1e-10
                )
            ).round(2)
            f1 = (2 * (precision * recall) / (precision + recall + 1e-10)).round(2)
            participant_df.loc[
                participant, "Best Overall Precision Visible During CTF"
            ] = precision
            participant_df.loc[
                participant, "Best Overall Recall Visible During CTF"
            ] = recall
            participant_df.loc[participant, "Best Overall F1 Visible During CTF"] = f1

            # invisible tests only
            mask = (rule_df["User ID"] == participant) & rule_df[
                "Final Best Submission During CTF"
            ]
            precision = (
                rule_df.loc[mask, "TPs Invisible"].sum()
                / (
                    rule_df.loc[mask, "TPs Invisible"].sum()
                    + rule_df.loc[mask, "FPs Invisible"].sum()
                    + 1e-10
                )
            ).round(2)
            recall = (
                rule_df.loc[mask, "TPs Invisible"].sum()
                / (
                    rule_df.loc[mask, "TPs Invisible"].sum()
                    + rule_df.loc[mask, "FNs Invisible"].sum()
                    + 1e-10
                )
            ).round(2)
            f1 = (2 * (precision * recall) / (precision + recall + 1e-10)).round(2)
            participant_df.loc[
                participant, "Best Overall Precision Invisible During CTF"
            ] = precision
            participant_df.loc[
                participant, "Best Overall Recall Invisible During CTF"
            ] = recall
            participant_df.loc[participant, "Best Overall F1 Invisible During CTF"] = f1

            participant_df.loc[
                participant,
                "Overall Design Principle Issues Count for with Final Best Submission During CTF",
            ] = rule_df.loc[mask, "Design Principle Issues Count"].sum()
            participant_df.loc[
                participant,
                "Overall Seconds Worked Towards First Submission to Pass Visible Tests During CTF",
            ] = sum(
                [
                    participant_df.at[
                        participant,
                        scenario
                        + " Seconds Worked Towards First Submission to Pass Visible Tests During CTF",
                    ]
                    for scenario in rule_df["Scenario"].unique()
                ]
            )

        logger.info("Collecting result data")

        result_df = pandas.DataFrame(
            list(
                Result.objects.filter(submission__user__id__in=participant_df.index)
                .values(
                    "id",
                    "status",
                    "score",
                    "n_alerts",
                    "test__id",
                    "test__title",
                    "test__scenario__title",
                    "test__hidden",
                    "test__expected",
                    "submission__user__id",
                    "submission__submitted_at",
                    "submission__id",
                )
                .order_by(
                    "submission__submitted_at",
                    "test__hidden",
                    "-test__expected",
                    "test__title",
                )
            )
        ).rename(
            {
                "id": "Result ID",
                "status": "Result",
                "score": "Score",
                "n_alerts": "Number of Alerts",
                "test__id": "Test ID",
                "test__title": "Test",
                "test__scenario__title": "Scenario",
                "test__hidden": "Test Hidden",
                "test__expected": "Test Malicious",
                "submission__user__id": "User ID",
                "submission__id": "Rule ID",
            },
            axis=1,
        )
        result_df = result_df.drop(columns=["submission__submitted_at"])
        result_df = result_df.set_index("Result ID")
        result_df["Unneccessary Workload"] = result_df.apply(
            lambda row: (
                max(0, row["Number of Alerts"] - 1)
                if row["Test Malicious"]
                else row["Number of Alerts"]
            ),
            axis=1,
        )

        rule_df["Unneccessary Workload"] = result_df.groupby("Rule ID")[
            "Unneccessary Workload"
        ].sum()

        rule_df["Multiple Rules"] = rule_df.apply(
            lambda row: row["Valid"]
            and normalize_functionalize_rule(row["Rule"]) is None,
            axis=1,
        )

        logger.info("Collecting rule update data")

        def get_field_type(field: str) -> str:
            if field in (
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "flow",
                "ip.src",
                "ip.dst",
            ):
                return "Traffic Direction"

            if field in (
                "content",
                "pcre",
                "within",
                "distance",
                "offset",
                "depth",
                "isdataat",
                "dsize",
                "bsize",
                "byte_test",
                "byte_jump",
                "byte_extract",
                "startswith",
                "endswith",
                "dotprefix",
            ):
                return "Payload Matching"

            if field in (
                "protocol",
                "tls.subject",
                "tls.version",
                "tls.certs",
                "tls.sni",
                "tls.cert_chain_length",
                "tls.cert_issuer",
                "tls.cert_subject",
                "tls.cert_chain_len",
                "tls.random",
                "tls.cert_serial",
                "tls.issuerdn",
                "tls_cert_expired",
                "tls_cert_notafter",
                "tls_cert_valid",
                "ssl_version",
                "ssl_state",
                "http.uri",
                "http.response_body",
                "http.response_header",
                "http.host",
                "http.method",
                "http.header",
                "http.protocol",
                "http.stat_code",
                "http.content_type",
                "http.content_len",
                "http.request_line",
                "http.response_line",
                "http.request_header",
                "http.user_agent",
                "http.connection",
                "http.request_body",
                "http.accept_enc",
                "http.referer",
                "http.server",
                "http_uri",
                "http_raw_uri",
                "http_header",
                "http_user_agent",
                "http_method",
                "http_server_body",
                "http_host",
                "dns.query",
                "dns.opcode",
                "dns_query",
                "file.data",
                "file.name",
                "fileext",
                "urilen",
                "uricontent",
                "base64_decode",
                "base64_data",
                "to_lowercase",
                "nocase",
                "pkt_data",
                "ja3.hash",
                "ja3s.hash",
                "tcp.hdr",
            ):
                return "Application Layer"

            if field in ("threshold", "flowbits", "xbits"):
                return "Stateful"

            if field in (
                "action",  # Is always 'alert'
                "msg",
                "reference",
                "classtype",
                "sid",
                "rev",
                "metadata",
                "priority",
                "fast_pattern",
            ):
                return "Non-Functional"

            # print(field)
            # raise RuntimeError(f"Unknown field type for {field}")

            return field

        # update_df contains one row for each rule update (i.e. bridge between rev 1 and rev 2)
        update_df = pandas.DataFrame()
        # change_df can contain multiple rows for each rule update (i.e. one row for each added/changed/removed option)
        change_df = pandas.DataFrame()

        # TODO: Implement different masks on rule_df here: i.e., only submissions, or only valid, etc.
        changes_dict = {}
        mask = rule_df["Valid"] & (~rule_df["Multiple Rules"])
        for group_name, rule_group in (
            rule_df[mask].groupby(["Scenario", "User ID"]).groups.items()
        ):
            scenario, user_id = group_name  # type: ignore
            rule_group = rule_df.loc[rule_group]
            rule_group = rule_group.sort_values(
                "Seconds Worked Towards Scenario Submission"
            )
            # TODO: Change this to also show first rule introduction as an update
            for i in range(0, len(rule_group)):
                next_rule_id = rule_group.index[i]
                next_rule = rule_group.iloc[i]["Rule"]
                next_rule_normalized = next_rule.replace("\\\n", "")
                next_submitted_at = rule_group.iloc[i][
                    "Seconds Worked Towards Scenario Submission"
                ]
                next_rule_issues: list[str] = rule_group.loc[
                    next_rule_id, "Design Principle Issues"
                ].split(",")

                if i == 0:
                    previous_rule_id = None
                    previous_rule = None
                    previous_rule_normalized = None
                    previous_rule_issues = []
                    previous_submitted_at = numpy.nan
                    str_distance = numpy.nan
                    key_similarity = numpy.nan
                else:
                    previous_rule_id = rule_group.index[i - 1]
                    previous_rule = rule_group.iloc[i - 1]["Rule"]
                    previous_rule_normalized = previous_rule.replace("\\\n", "")
                    previous_submitted_at = rule_group.iloc[i - 1][
                        "Seconds Worked Towards Scenario Submission"
                    ]
                    previous_rule_issues: list[str] = rule_group.loc[
                        previous_rule_id, "Design Principle Issues"
                    ].split(",")
                    str_distance = (
                        distance(
                            normalize_functionalize_rule(previous_rule),
                            normalize_functionalize_rule(next_rule),
                        )
                        if normalize_functionalize_rule(previous_rule) is not None
                        and normalize_functionalize_rule(next_rule) is not None
                        else numpy.nan
                    )
                    key_similarity = (
                        jaccard_similarity(
                            normalize_functionalize_rule(previous_rule),
                            normalize_functionalize_rule(next_rule),
                        )
                        if normalize_functionalize_rule(previous_rule) is not None
                        and normalize_functionalize_rule(next_rule) is not None
                        else numpy.nan
                    )

                update_time = next_submitted_at - previous_submitted_at
                update_types, is_functional_update, broad_update_types = (
                    get_update_types(previous_rule_normalized, next_rule_normalized)
                )
                added_rule_issues = ",".join(
                    sorted(list(set(next_rule_issues) - set(previous_rule_issues)))
                )
                removed_rule_issues = ",".join(
                    sorted(list(set(previous_rule_issues) - set(next_rule_issues)))
                )

                update_i = len(update_df)
                changes_dict[update_i] = []
                new_update = pandas.DataFrame(
                    [
                        {
                            "Scenario": scenario,
                            "User ID": user_id,
                            "Previous Rule ID": previous_rule_id,
                            "Next Rule ID": next_rule_id,
                            "Previous Rule": previous_rule,
                            "Next Rule": next_rule,
                            "Previous Seconds Worked Towards Scenario Submission": previous_submitted_at,
                            "Next Seconds Worked Towards Scenario Submission": next_submitted_at,
                            "Seconds Worked Towards Scenario Submission Update": update_time,
                            "Update Types": ",".join(sorted(update_types)),
                            "Functional Update": is_functional_update,
                            "Broad Update Types": ",".join(sorted(broad_update_types)),
                            "Added Design Principle Issues": added_rule_issues,
                            "Removed Design Principle Issues": removed_rule_issues,
                            "Updated During CTF": rule_group.iloc[i][
                                "Submitted During CTF"
                            ],
                            "Change in F1": rule_group.iloc[i]["F1"]
                            - rule_group.iloc[i - 1]["F1"],
                            "Change in F1 Visible": rule_group.iloc[i]["F1 Visible"]
                            - rule_group.iloc[i - 1]["F1 Visible"],
                            "Change in F1 Invisible": rule_group.iloc[i]["F1 Invisible"]
                            - rule_group.iloc[i - 1]["F1 Invisible"],
                            "Change in Precision": rule_group.iloc[i]["Precision"]
                            - rule_group.iloc[i - 1]["Precision"],
                            "Change in Precision Visible": rule_group.iloc[i][
                                "Precision Visible"
                            ]
                            - rule_group.iloc[i - 1]["Precision Visible"],
                            "Change in Precision Invisible": rule_group.iloc[i][
                                "Precision Invisible"
                            ]
                            - rule_group.iloc[i - 1]["Precision Invisible"],
                            "Change in Recall": rule_group.iloc[i]["Recall"]
                            - rule_group.iloc[i - 1]["Recall"],
                            "Change in Recall Visible": rule_group.iloc[i][
                                "Recall Visible"
                            ]
                            - rule_group.iloc[i - 1]["Recall Visible"],
                            "Change in Recall Invisible": rule_group.iloc[i][
                                "Recall Invisible"
                            ]
                            - rule_group.iloc[i - 1]["Recall Invisible"],
                            "Levenshtein Distance": str_distance,
                            "Jaccard Similarity": key_similarity,
                        }
                    ],
                    index=[update_i],
                )
                update_df = pandas.concat([update_df, new_update])

                added_fields, removed_fields, modified_fields = get_option_changes(
                    previous_rule_normalized, next_rule_normalized
                )
                # TODO: Map changed field to a broader category and add it as an additional column
                # TODO: Map changes to design principles
                for change in added_fields:
                    change_i = len(change_df)
                    new_change = pandas.DataFrame(
                        [
                            {
                                "Change Type": "Added",
                                "Field": change[0],
                                "Field Type": get_field_type(change[0]),
                                "Next Value": change[1],
                                "Scenario": scenario,
                                "User ID": user_id,
                                "Previous Rule ID": previous_rule_id,
                                "Next Rule ID": next_rule_id,
                                "Update ID": update_i,
                            }
                        ],
                        index=[change_i],
                    )

                    changes_dict[update_i].append(change_i)
                    change_df = pandas.concat([change_df, new_change])

                for change in removed_fields:
                    change_i = len(change_df)
                    new_change = pandas.DataFrame(
                        [
                            {
                                "Change Type": "Removed",
                                "Field": change[0],
                                "Field Type": get_field_type(change[0]),
                                "Next Value": change[1],
                                "Scenario": scenario,
                                "User ID": user_id,
                                "Previous Rule ID": previous_rule_id,
                                "Next Rule ID": next_rule_id,
                                "Update ID": update_i,
                            }
                        ],
                        index=[change_i],
                    )

                    changes_dict[update_i].append(change_i)
                    change_df = pandas.concat([change_df, new_change])

                for change in modified_fields:
                    change_i = len(change_df)
                    new_change = pandas.DataFrame(
                        [
                            {
                                "Change Type": "Modified",
                                "Field": change[0],
                                "Field Type": get_field_type(change[0]),
                                "Previous Value": change[1],
                                "Next Value": change[2],
                                "Scenario": scenario,
                                "User ID": user_id,
                                "Levenshtein Distance": (
                                    distance(change[1], change[2])
                                    if change[1] is not None and change[2] is not None
                                    else numpy.nan
                                ),
                                "Previous Rule ID": previous_rule_id,
                                "Next Rule ID": next_rule_id,
                                "Update ID": update_i,
                            }
                        ],
                        index=[change_i],
                    )

                    changes_dict[update_i].append(change_i)
                    change_df = pandas.concat([change_df, new_change])

        update_df["Changes"] = {
            k: ",".join(sorted([str(x) for x in v])) for k, v in changes_dict.items()
        }
        update_df["Number of Changes"] = len(changes_dict.keys())

        rule_df["Levenshtein Distance From Final Valid Submitted Rule During CTF"] = (
            rule_df.apply(
                lambda row: (
                    distance(
                        normalize_functionalize_rule(row["Rule"]),
                        normalize_functionalize_rule(
                            rule_df.loc[
                                (rule_df["User ID"] == row["User ID"])
                                & (rule_df["Scenario"] == row["Scenario"])
                                & (rule_df["Final Valid Submitted Rule During CTF"]),
                                "Rule",
                            ].iloc[-1]
                        ),
                    )
                    if normalize_functionalize_rule(row["Rule"]) is not None
                    and normalize_functionalize_rule(
                        rule_df.loc[
                            (rule_df["User ID"] == row["User ID"])
                            & (rule_df["Scenario"] == row["Scenario"])
                            & (rule_df["Final Valid Submitted Rule During CTF"]),
                            "Rule",
                        ].iloc[-1]
                    )
                    else numpy.nan
                ),
                axis=1,
            )
        )

        rule_df[
            "Levenshtein Distance From First Submission to Pass Visible Tests During CTF"
        ] = rule_df.apply(
            lambda row: (
                distance(
                    normalize_functionalize_rule(row["Rule"]),
                    normalize_functionalize_rule(
                        rule_df.loc[
                            (rule_df["User ID"] == row["User ID"])
                            & (rule_df["Scenario"] == row["Scenario"])
                            & (
                                rule_df[
                                    "First Submission to Pass Visible Tests During CTF"
                                ]
                            ),
                            "Rule",
                        ].iloc[0]
                    ),
                )
                if normalize_functionalize_rule(row["Rule"]) is not None
                and (
                    (rule_df["User ID"] == row["User ID"])
                    & (rule_df["Scenario"] == row["Scenario"])
                    & (rule_df["First Submission to Pass Visible Tests During CTF"])
                ).sum()
                > 0
                and normalize_functionalize_rule(
                    rule_df.loc[
                        (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"])
                        & (
                            rule_df["First Submission to Pass Visible Tests During CTF"]
                        ),
                        "Rule",
                    ].iloc[0]
                )
                else numpy.nan
            ),
            axis=1,
        )

        rule_df["Jaccard Similarity From Final Valid Submitted Rule During CTF"] = (
            rule_df.apply(
                lambda row: (
                    jaccard_similarity(
                        normalize_functionalize_rule(row["Rule"]),
                        normalize_functionalize_rule(
                            rule_df.loc[
                                (rule_df["User ID"] == row["User ID"])
                                & (rule_df["Scenario"] == row["Scenario"])
                                & (rule_df["Final Valid Submitted Rule During CTF"]),
                                "Rule",
                            ].iloc[-1]
                        ),
                    )
                    if normalize_functionalize_rule(row["Rule"]) is not None
                    and normalize_functionalize_rule(
                        rule_df.loc[
                            (rule_df["User ID"] == row["User ID"])
                            & (rule_df["Scenario"] == row["Scenario"])
                            & (rule_df["Final Valid Submitted Rule During CTF"]),
                            "Rule",
                        ].iloc[-1]
                    )
                    else numpy.nan
                ),
                axis=1,
            )
        )

        rule_df[
            "Jaccard Similarity From First Submission to Pass Visible Tests During CTF"
        ] = rule_df.apply(
            lambda row: (
                jaccard_similarity(
                    normalize_functionalize_rule(row["Rule"]),
                    normalize_functionalize_rule(
                        rule_df.loc[
                            (rule_df["User ID"] == row["User ID"])
                            & (rule_df["Scenario"] == row["Scenario"])
                            & (
                                rule_df[
                                    "First Submission to Pass Visible Tests During CTF"
                                ]
                            ),
                            "Rule",
                        ].iloc[0]
                    ),
                )
                if normalize_functionalize_rule(row["Rule"]) is not None
                and (
                    (rule_df["User ID"] == row["User ID"])
                    & (rule_df["Scenario"] == row["Scenario"])
                    & (rule_df["First Submission to Pass Visible Tests During CTF"])
                ).sum()
                > 0
                and normalize_functionalize_rule(
                    rule_df.loc[
                        (rule_df["User ID"] == row["User ID"])
                        & (rule_df["Scenario"] == row["Scenario"])
                        & (
                            rule_df["First Submission to Pass Visible Tests During CTF"]
                        ),
                        "Rule",
                    ].iloc[0]
                )
                else numpy.nan
            ),
            axis=1,
        )

        # Verify dtypes
        for df in (participant_df, rule_df, result_df, update_df, change_df):
            for col in df.columns:
                if df[col].dtype == "object" and isinstance(df[col].iloc[0], list):
                    logger.error("Column type is object, list: %s", col)

        logger.info("Writing analysis output")

        participant_df.to_parquet("dumps/participant.parquet")
        rule_df.to_parquet("dumps/rule.parquet")
        result_df.to_parquet("dumps/result.parquet")
        update_df.to_parquet("dumps/update.parquet")
        change_df.to_parquet("dumps/change.parquet")

        return


# https://arxiv.org/pdf/2110.09619
def jaccard_similarity(rule1: str, rule2: str) -> float:
    try:
        r1 = idstools.rule.parse(rule1)
        r2 = idstools.rule.parse(rule2)
    except:
        return numpy.nan

    if r1 is None or r2 is None:
        return numpy.nan

    r1_options = Multiset([x["name"] for x in r1["options"]])
    r2_options = Multiset([x["name"] for x in r2["options"]])

    return sum(
        min(r1_options[k], r2_options[k])
        for k in set(r1_options.distinct_elements()).union(
            set(r2_options.distinct_elements())
        )
    ) / len(r1_options.union(r2_options))


def get_str_diffs(previous: str, next: str) -> tuple[int, int, int]:
    matches = difflib.SequenceMatcher(None, previous, next).get_matching_blocks()

    total_inserted = 0
    total_removed = 0
    total_modified = 0

    prev_a = 0
    prev_b = 0
    prev_size = 0
    for m in matches:
        removed = m.a - prev_a - prev_size
        inserted = m.b - prev_b - prev_size

        if inserted == removed:
            total_modified += inserted
        else:
            total_inserted += inserted
            total_removed += removed

        prev_a = m.a
        prev_b = m.b
        prev_size = m.size

    return total_inserted, total_removed, total_modified


def label_rule_parts(rule_parts: list[str]) -> list[str]:
    rule_parts[0] = "action:" + rule_parts[0]
    rule_parts[1] = "protocol:" + rule_parts[1]
    rule_parts[2] = "src_ip:" + rule_parts[2]
    rule_parts[3] = "src_port:" + rule_parts[3]
    rule_parts[4] = "dst_ip:" + rule_parts[4]
    rule_parts[5] = "dst_port:" + rule_parts[5]

    return rule_parts


def get_rule_parts(rule: Optional[str], labelled=True):
    if rule is None:
        return []

    if idstools.rule.parse(rule.replace("\\\n", "").strip()) is None:
        # logger.warning("Skipping multiline or unparseable rule: %s", rule)
        return None

    try:
        rule_parts = re.match(
            r"^\s*(\w+)\s+([\w\-]+)\s+([\w\$\_\[\]\,\!\.\/ ]+)\s+([\w\$\_\[\]\,\!\: ]+)\s+[-<>]+\s+([\w\$\_\[\]\,\!\.\/ ]+)\s+([\w\$\_\[\]\,\!\: ]+)\s+\((.+)\)\s*$",
            rule,
        ).groups()

        splits = re.split(r"((?!\\).);", rule_parts[-1])
        processed_splits = []
        i = 0
        for split in splits:
            if i % 2 == 0:
                if split.strip() == "":
                    continue
                processed_splits.append(split)
            else:
                processed_splits[-1] += split
            i += 1

        rule_parts = [x for x in rule_parts[:-1]] + processed_splits
        rule_parts = [x.strip() for x in rule_parts]

        if labelled:
            rule_parts = label_rule_parts(rule_parts)
    except:
        logger.warning("Failed to extract rule parts from rule: %s", rule)
        rule_parts = []

    return rule_parts


def get_option_changes(previous_rule: Optional[str], next_rule: str) -> tuple[
    list[tuple[str, Optional[str]]],
    list[tuple[str, Optional[str]]],
    list[tuple[str, Optional[str], Optional[str]]],
]:
    # TODO: Also map changed fields to field types: i.e. map tls.certs to buffer
    previous_rule_parts = get_rule_parts(previous_rule)
    next_rule_parts = get_rule_parts(next_rule)

    if previous_rule_parts is None and previous_rule is None:
        previous_rule_parts = []

    if previous_rule_parts is None or next_rule_parts is None:
        return [], [], []

    added_fields: list[tuple[str, Optional[str]]] = []
    removed_fields: list[tuple[str, Optional[str]]] = []
    modified_fields: list[tuple[str, Optional[str], Optional[str]]] = []
    for d in sorted(difflib.ndiff(previous_rule_parts, next_rule_parts)):
        if d.startswith("+ "):
            s = d[2:].split(":")
            fieldname = s[0].strip()
            if fieldname.strip() == "":
                continue

            fieldvalue = None
            if len(s) > 1:
                fieldvalue = "".join(s[1:]).strip()

            # if fieldname in [x[0] for x in modified_fields] or fieldname in [
            #     x[0] for x in added_fields
            # ]:
            #     pass
            # if fieldname in [x[0] for x in removed_fields]:
            #     for removed_field in removed_fields[::-1]:
            #         if removed_field[0] == fieldname:
            #             previous_fieldvalue = removed_field[1]
            #             removed_fields.remove(removed_field)
            #             break
            #     modified_fields.append((fieldname, previous_fieldvalue, fieldvalue))  # type: ignore reportPossiblyUnboundVariable
            # else:
            added_fields.append((fieldname, fieldvalue))
        elif d.startswith("- "):
            s = d[2:].split(":")
            fieldname = s[0].strip()
            fieldvalue = None
            if len(s) > 1:
                fieldvalue = "".join(s[1:]).strip()

            # if fieldname in [x[0] for x in modified_fields] or fieldname in [
            #     x[0] for x in removed_fields
            # ]:
            #     pass
            if fieldname in [x[0] for x in added_fields]:
                for added_field in added_fields:
                    if added_field[0] == fieldname:
                        next_fieldvalue = added_field[1]
                        added_fields.remove(added_field)
                        break
                modified_fields.append((fieldname, fieldvalue, next_fieldvalue))  # type: ignore reportPossiblyUnboundVariable
            else:
                removed_fields.append((fieldname, fieldvalue))

        for modified_field in modified_fields:
            if modified_field[1] == modified_field[2]:
                modified_fields.remove(modified_field)

    return added_fields, removed_fields, modified_fields


def get_update_types(
    previous_rule: Optional[str], next_rule: str
) -> tuple[list[str], bool, list[str]]:
    if previous_rule is None:
        return ["First observation"], True, ["First observation"]

    added_fields, removed_fields, modified_fields = get_option_changes(
        previous_rule, next_rule
    )

    update_types = []

    for field in added_fields:
        update_types.append(f"Inserted field {field[0]}")

    for field in removed_fields:
        update_types.append(f"Removed field {field[0]}")

    for field in modified_fields:
        total_inserted, total_removed, total_modified = get_str_diffs(
            field[1], field[2]
        )
        if total_inserted > 0 and total_removed == 0 and total_modified == 0:
            update_types.append(f"Insertion into field {field[0]}")
        elif total_inserted == 0 and total_removed > 0 and total_modified == 0:
            update_types.append(f"Removal from field {field[0]}")
        else:
            update_types.append(f"Modified field {field[0]}")

    n_updates = len(update_types)
    n_non_functional_updates = 0
    for update_type in update_types:
        if update_type.split(" ")[-1] in NON_FUNCTIONAL_FIELDS:
            n_non_functional_updates += 1

    is_functional_update = n_non_functional_updates < n_updates

    broad_update_types = []
    for added_field in added_fields:
        if added_field[0] in NON_FUNCTIONAL_FIELDS:
            broad_update_types.append("Metadata update")
        elif added_field[0] == "nocase" and len(
            re.findall(r'content:"(?!.*content.*nocase).*nocase', previous_rule)
        ) < len(re.findall(r'content:"(?!.*content.*nocase).*nocase', next_rule)):
            broad_update_types.append("More general")
        elif added_field[0] == "nocase" and len(
            re.findall(r'content:!"(?!.*content.*nocase).*nocase', previous_rule)
        ) < len(re.findall(r'content:!"(?!.*content.*nocase).*nocase', next_rule)):
            broad_update_types.append("More specific")
        elif added_field[0] in ("content", "pcre") and not added_field[1].startswith(
            "!"
        ):
            broad_update_types.append("More specific")
        elif added_field[0] in ("content", "pcre") and added_field[1].startswith("!"):
            broad_update_types.append("Added exclusion")
        elif added_field[0] in ("tls_cert_notafter",):
            broad_update_types.append("More specific")
        elif added_field[0] == "distance" and len(
            re.findall(
                r'(content)|(pcre):"(?!.*(content)|(pcre)).*distance', previous_rule
            )
        ) < len(
            re.findall(r'(content)|(pcre):"(?!.*(content)|(pcre)).*distance', next_rule)
        ):
            broad_update_types.append("More specific")
            # TODO: This update is mostly performance but might have an effect on detection
        elif added_field[0] == "distance" and len(
            re.findall(
                r'(content)|(pcre):!"(?!.*(content)|(pcre)).*distance', previous_rule
            )
        ) < len(
            re.findall(
                r'(content)|(pcre):!"(?!.*(content)|(pcre)).*distance', next_rule
            )
        ):
            broad_update_types.append("More general")
            # TODO: This update is mostly performance but might have an effect on detection
        elif (
            added_field[0] == "dotprefix"
            and 'dotprefix; content:".' not in previous_rule
            and 'dotprefix; content:".' in next_rule
        ):
            broad_update_types.append("More specific")
        elif (
            added_field[0] == "dotprefix"
            and 'dotprefix; content:"' not in previous_rule
            and 'dotprefix; content:"' in next_rule
        ):
            broad_update_types.append("Meaningless update")
        elif added_field[0] == "startswith" and len(
            re.findall(r'content:"(?!.*content.*startswith).*startswith', previous_rule)
        ) < len(
            re.findall(r'content:"(?!.*content.*startswith).*startswith', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "startswith" and len(
            re.findall(
                r'content:!"(?!.*content.*startswith).*startswith', previous_rule
            )
        ) < len(
            re.findall(r'content:!"(?!.*content.*startswith).*startswith', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "endswith" and len(
            re.findall(r'content:"(?!.*content.*endswith).*endswith', previous_rule)
        ) < len(re.findall(r'content:"(?!.*content.*endswith).*endswith', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "endswith" and len(
            re.findall(r'content:!"(?!.*content.*endswith).*endswith', previous_rule)
        ) < len(re.findall(r'content:!"(?!.*content.*endswith).*endswith', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "depth" and len(
            re.findall(r'content:"(?!.*content).*depth', previous_rule)
        ) < len(re.findall(r'content:"(?!.*content).*depth', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "depth" and len(
            re.findall(r'content:!"(?!.*content).*depth', previous_rule)
        ) < len(re.findall(r'content:!"(?!.*content).*depth', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "http.header" and len(
            re.findall(
                r'content:"(?!.*content.*http\.header;).*http\.header;', previous_rule
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*http\.header;).*http\.header;', next_rule
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "http.header" and len(
            re.findall(
                r'content:!"(?!.*content.*http\.header;).*http\.header;', previous_rule
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*http\.header;).*http\.header;', next_rule
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "tls.cert_issuer" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "tls.cert_issuer" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "tls.cert_subject" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "tls.cert_subject" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "tls.certs" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.certs;).*tls\.certs;', previous_rule
            )
        ) < len(
            re.findall(r'content:"(?!.*content.*tls\.certs;).*tls\.certs;', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif added_field[0] == "tls.certs" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.certs;).*tls\.certs;', previous_rule
            )
        ) < len(
            re.findall(r'content:!"(?!.*content.*tls\.certs;).*tls\.certs;', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif added_field[0] == "threshold" and "limit" in added_field[1]:
            broad_update_types.append("Less alerts")
        elif added_field[0] == "flowbits" and added_field[1].startswith("set"):
            broad_update_types.append("Flowbit set")
        elif added_field[0] == "tls.cert_chain_len":
            broad_update_types.append("More specific")
        elif added_field[0] == "tls.version":
            broad_update_types.append("More specific")
        elif added_field[0] == "flow":
            broad_update_types.append("More specific")
        elif added_field[0] == "fast_pattern":
            broad_update_types.append("Performance optimization")
        else:
            logger.warning(
                f"Added field {added_field[0]} not recognized as broad update type"
            )
            logger.warning(f"Previous rule: \t{previous_rule}")
            logger.warning(f"Next rule: \t{next_rule}")
            logger.warning(f"Next segment: \t{added_field}")
            broad_update_types.append("Unknown update")

    for removed_field in removed_fields:
        if removed_field[0] in NON_FUNCTIONAL_FIELDS:
            broad_update_types.append("Metadata update")
        elif removed_field[0] in ("content", "pcre") and not removed_field[
            1
        ].startswith("!"):
            broad_update_types.append("More general")
        elif removed_field[0] in ("content", "pcre") and removed_field[1].startswith(
            "!"
        ):
            broad_update_types.append("Removed exclusion")
        elif removed_field[0] in ("tls_cert_notafter",):
            broad_update_types.append("More general")
        elif (
            removed_field[0] == "dotprefix"
            and 'dotprefix; content:".' in previous_rule
            and 'dotprefix; content:".' not in next_rule
        ):
            broad_update_types.append("More general")
        elif removed_field[0] == "startswith" and len(
            re.findall(
                r'content:"(?!.*content.*startswith).*startswith',
                previous_rule,
            )
        ) > len(
            re.findall(r'content:"(?!.*content.*startswith).*startswith', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "startswith" and len(
            re.findall(
                r'content:!"(?!.*content.*startswith).*startswith',
                previous_rule,
            )
        ) > len(
            re.findall(r'content:!"(?!.*content.*startswith).*startswith', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "endswith" and len(
            re.findall(
                r'content:"(?!.*content.*endswith).*endswith',
                previous_rule,
            )
        ) > len(re.findall(r'content:"(?!.*content.*endswith).*endswith', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "endswith" and len(
            re.findall(
                r'content:!"(?!.*content.*endswith).*endswith',
                previous_rule,
            )
        ) > len(re.findall(r'content:!"(?!.*content.*endswith).*endswith', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "bsize" and len(
            re.findall(
                r'content:"(?!.*content).*bsize',
                previous_rule,
            )
        ) > len(re.findall(r'content:"(?!.*content).*bsize', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "bsize" and len(
            re.findall(
                r'content:!"(?!.*content).*bsize',
                previous_rule,
            )
        ) > len(re.findall(r'content:!"(?!.*content).*bsize', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "nocase" and len(
            re.findall(
                r'content:"(?!.*content).*nocase',
                previous_rule,
            )
        ) > len(re.findall(r'content:"(?!.*content).*nocase', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "nocase" and len(
            re.findall(
                r'content:!"(?!.*content).*nocase',
                previous_rule,
            )
        ) > len(re.findall(r'content:!"(?!.*content).*nocase', next_rule)):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "http.header" and len(
            re.findall(
                r'content:"(?!.*content.*http\.header;).*http\.header;', previous_rule
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*http\.header;).*http\.header;', next_rule
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "http.header" and len(
            re.findall(
                r'content:!"(?!.*content.*http\.header;).*http\.header;', previous_rule
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*http\.header;).*http\.header;', next_rule
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "tls.cert_issuer" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "tls.cert_issuer" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_issuer;).*tls\.cert_issuer;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "tls.cert_subject" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "tls.cert_subject" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                previous_rule,
            )
        ) < len(
            re.findall(
                r'content:!"(?!.*content.*tls\.cert_subject;).*tls\.cert_subject;',
                next_rule,
            )
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "tls.certs" and len(
            re.findall(
                r'content:"(?!.*content.*tls\.certs;).*tls\.certs;', previous_rule
            )
        ) < len(
            re.findall(r'content:"(?!.*content.*tls\.certs;).*tls\.certs;', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More general")
        elif removed_field[0] == "tls.certs" and len(
            re.findall(
                r'content:!"(?!.*content.*tls\.certs;).*tls\.certs;', previous_rule
            )
        ) < len(
            re.findall(r'content:!"(?!.*content.*tls\.certs;).*tls\.certs;', next_rule)
        ):
            # TODO: This update is mostly performance but might have an effect on detection
            broad_update_types.append("More specific")
        elif removed_field[0] == "tls.cert_chain_len":
            broad_update_types.append("More general")
        elif removed_field[0] == "tls.version":
            broad_update_types.append("More general")
        elif removed_field[0] == "flow":
            broad_update_types.append("More general")
        elif removed_field[0] == "fast_pattern":
            broad_update_types.append("Performance optimization")
        else:
            logger.warning(
                f"Removed field {removed_field[0]} not recognized as broad update type"
            )
            logger.warning(f"Previous rule: \t{previous_rule}")
            logger.warning(f"Next rule: \t{next_rule}")
            logger.warning(f"Previous segment: \t{removed_field[1]}")
            broad_update_types.append("Unknown update")

    for modified_field in modified_fields:
        if modified_field[0] in NON_FUNCTIONAL_FIELDS:
            broad_update_types.append("Metadata update")
        elif modified_field[0] in ("flow",) and ",".join(
            sorted(modified_field[1].split(","))
        ) == ",".join(sorted(modified_field[2].split(","))):
            broad_update_types.append("Formatting update")
        elif modified_field[0] == "content" and re.sub(
            r"\|([\s\da-f]+)\|",
            lambda x: "".join(
                [
                    chr(int(x.group(1).replace(" ", "")[i * 2 : i * 2 + 2], 16))
                    for i in range(len(x.group(1).replace(" ", "")) // 2)
                ]
            ),
            modified_field[1],
        ) == re.sub(
            r"\|([\s\da-f]+)\|",
            lambda x: "".join(
                [
                    chr(int(x.group(1).replace(" ", "")[i * 2 : i * 2 + 2], 16))
                    for i in range(len(x.group(1).replace(" ", "")) // 2)
                ]
            ),
            modified_field[2],
        ):
            broad_update_types.append("Formatting update")
        elif (
            modified_field[0] == "content"
            and 'dotprefix; content:".' not in previous_rule
            and 'dotprefix; content:".' in next_rule
        ):
            broad_update_types.append("More specific")
        elif (
            modified_field[0] == "protocol"
            and modified_field[1] in PROTO_TREE[modified_field[2]]
        ):
            broad_update_types.append("More general")
        elif (
            modified_field[0] == "protocol"
            and modified_field[2] in PROTO_TREE[modified_field[1]]
        ):
            broad_update_types.append("More specific")
        elif (
            modified_field[0] in ("src_ip", "dst_ip", "src_port", "dst_port")
            and modified_field[1] == "any"
        ):
            broad_update_types.append("More specific")
        elif (
            modified_field[0] in ("src_ip", "dst_ip", "src_port", "dst_port")
            and modified_field[2] == "any"
        ):
            broad_update_types.append("More general")
        elif (
            modified_field[1] is not None
            and modified_field[2] is not None
            and not modified_field[1].startswith("!")
            and modified_field[1] in modified_field[2]
        ):
            broad_update_types.append("More general")
        elif (
            modified_field[1] is not None
            and modified_field[2] is not None
            and not modified_field[1].startswith("!")
            and modified_field[2] in modified_field[1]
        ):
            broad_update_types.append("More specific")
        elif (
            modified_field[1] is not None
            and modified_field[2] is not None
            and modified_field[1].startswith("!")
            and modified_field[1] in modified_field[2]
        ):
            broad_update_types.append("More specific")
        elif (
            modified_field[1] is not None
            and modified_field[2] is not None
            and modified_field[1].startswith("!")
            and modified_field[2] in modified_field[1]
        ):
            broad_update_types.append("More general")
        elif (
            modified_field[1] is not None
            and modified_field[2] is not None
            and modified_field[1] not in modified_field[2]
            and modified_field[2] not in modified_field[1]
        ):
            broad_update_types.append("Changed detected characteristic")
        elif (
            modified_field[0] in ("src_ip", "dst_ip")
            and re.match(r"\[[\d\.\,]+\]", modified_field[1])
            and re.match(r"\[[\d\.\,]+\]", modified_field[2])
        ):
            broad_update_types.append("Threat intel update")
        else:
            logger.warning(
                f"Modified field {modified_field[0]} not recognized as broad update type"
            )
            logger.warning(f"Previous rule: \t{previous_rule}")
            logger.warning(f"Next rule: \t{next_rule}")
            logger.warning(f"Previous segment: \t{modified_field[1]}")
            logger.warning(f"Next segment: \t{modified_field[2]}")
            broad_update_types.append("Unknown update")

    broad_update_types = sorted(list(set(broad_update_types)))

    return update_types, is_functional_update, broad_update_types


def normalize_functionalize_rule(rule: str):
    try:
        parsed_rule = idstools.rule.parse(rule.replace("\\\n", "").strip())
    except:
        logger.error("Failed to parse rule: %s", rule.replace("\\\n", "").strip())
        return None

    if parsed_rule is None:
        logger.error("Failed to parse rule: %s", rule.replace("\\\n", "").strip())
        return None

    parsed_rule = idstools.rule.remove_option(parsed_rule, "msg")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "sid")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "rev")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "gid")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "classtype")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "metadata")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "target")
    parsed_rule = idstools.rule.remove_option(parsed_rule, "fast_pattern")

    for keyword in (
        "msg",
        "flow",
        "threshold",
        "reference",
        "classtype",
        "sid",
        "rev",
    ):
        if (
            keyword not in parsed_rule.keys()
            or parsed_rule[keyword] is None
            or parsed_rule[keyword] == ""
            or parsed_rule[keyword] == []
        ):
            continue
        parsed_rule = idstools.rule.add_option(
            idstools.rule.remove_option(parsed_rule, keyword),
            keyword,
            parsed_rule[keyword],
        )
    if (
        "metadata" in parsed_rule.keys()
        and parsed_rule["metadata"] is None
        and parsed_rule["metadata"] == ""
        and parsed_rule["metadata"] == []
    ):
        parsed_rule = idstools.rule.add_option(
            idstools.rule.remove_option(parsed_rule, "metadata"),
            "metadata",
            ", ".join(parsed_rule["metadata"]),
        )

    return str(parsed_rule)
