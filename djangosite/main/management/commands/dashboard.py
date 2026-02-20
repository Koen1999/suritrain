import os
from typing import Optional

import pandas
from django.core.management.base import BaseCommand

from .analyze2 import get_dataframes


class Command(BaseCommand):
    help = "Starts workers for the Dashboard in the background."

    def handle(self, *args, **options) -> None:  # noqa: ANN002, ANN003, ARG002
        os.makedirs("dumps/dashboard", exist_ok=True)

        while True:
            participant_df, rule_df, result_df, update_df, change_df = get_dataframes()

            participant_df.to_parquet("dumps/dashboard/participant.parquet")
            rule_df.to_parquet("dumps/dashboard/rule.parquet")
            result_df.to_parquet("dumps/dashboard/result.parquet")
            update_df.to_parquet("dumps/dashboard/update.parquet")
            change_df.to_parquet("dumps/dashboard/change.parquet")


def get_dashboard_dataframes() -> Optional[
    tuple[
        pandas.DataFrame,
        pandas.DataFrame,
        pandas.DataFrame,
        pandas.DataFrame,
        pandas.DataFrame,
    ]
]:
    try:
        participant_df = pandas.read_parquet("dumps/dashboard/participant.parquet")
        rule_df = pandas.read_parquet("dumps/dashboard/rule.parquet")
        result_df = pandas.read_parquet("dumps/dashboard/result.parquet")
        update_df = pandas.read_parquet("dumps/dashboard/update.parquet")
        change_df = pandas.read_parquet("dumps/dashboard/change.parquet")

        return participant_df, rule_df, result_df, update_df, change_df
    except FileNotFoundError:
        return None
