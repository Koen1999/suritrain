import datetime
import hashlib
import logging
import os
import shutil
import subprocess
from functools import lru_cache
from typing import Optional

import cacheout
import idstools
import idstools.rule
from django.contrib.auth.models import AbstractBaseUser, User
from django.utils.timezone import localtime

from .models import Result, Scenario, Submission

logger = logging.getLogger(__name__)


REQUIRE_SCENARIO_UNLOCKING = True
UNLOCK_AFTER_SECONDS = 60 * 5
UNLOCK_AFTER_COMPLETION = True


def format_rule(rule: str) -> Optional[str]:
    try:
        parsed_rule: idstools.rule.Rule = idstools.rule.parse(rule.strip())

        if parsed_rule is None:
            return None

        return parsed_rule.format()
    except Exception:
        return None


def __highlight_with_color(string: str, colorcode: str) -> str:
    string = """\
<b style="color:{}">{}</b>\
""".format(
        colorcode, string
    )

    return string


def __highlight_character(string: str, in_string, escape) -> str:
    if string == '"' and not escape:
        return __highlight_with_color(string, "#FF22CC")

    if string == "\\" and not escape:
        return __highlight_with_color(string, "#FF22CC")

    if string == "|" and not escape:
        return __highlight_with_color(string, "#FF22CC")

    if string == "$" and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")
    if string == "," and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")
    if string == "[" and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")
    if string == "]" and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")
    if string == ":" and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")
    if string == "!" and not in_string and not escape:
        return __highlight_with_color(string, "#FFCC22")

    return string


def __highlight(string: str) -> str:
    new_string = ""
    escape = False
    in_string = False
    for s in string:
        new_string += __highlight_character(s, in_string, escape)

        if not escape and s == "\\":
            escape = True
        else:
            escape = False
        if not escape and s == '"':
            in_string += True

    return new_string


def __escape(string: str) -> str:
    return string.replace("<", "&lt;").replace(">", "&gt;")


def __conditional_format_value(value: Optional[str]):
    if value is None:
        return ""

    return """\
<p class="px-1 m-0">:</p>
<i class="px-0 m-0" style="color:#FFFFFF">{}</i>\
""".format(
        __highlight(__escape(value))
    )


def format_rule_html(input: Optional[str]) -> Optional[str]:
    if input is None:
        return None

    rules_html: list[str] = []
    for rule in input.split("\n"):
        try:
            parsed_rule: idstools.rule.Rule = idstools.rule.parse(rule.strip())

            if parsed_rule is None:
                continue

            options_html = "\n".join(
                [
                    """\
    <div class="row">
        <div class="d-inline-flex">
            <p class="px-0 m-0" style="color:#FFAAAA">{}</p>
            {}
            <p class="px-1 m-0" style="color:#FFAAAA">;</p>
        </div>
    </div>\
    """.format(
                        option["name"], __conditional_format_value(option["value"])
                    )
                    for option in parsed_rule["options"]
                ]
            )

            html = """\
    <div class="container">
        <div class="row">
            <div class="col-auto">
                <div class="d-inline-flex">
                    <p class="px-1 m-0" style="color:#FFAAAA">{}</p>
                    <p class="px-1 m-0" style="color:#FFFFFF">{}</p>
                    <p class="px-1 m-0" style="color:#FFFFFF">{}</p>
                    <i class="px-1 m-0" style="color:#FFFFFF">{}</i>
                    <p class="px-1 m-0" style="color:#FFAAAA">{}</p>
                    <p class="px-1 m-0" style="color:#FFFFFF">{}</p>
                    <i class="px-1 m-0" style="color:#FFFFFF">{}</i>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-auto">
                <div class="d-inline-flex">
                    <p class="px-1 m-0">(</p>
                </div>
            </div>
        </div>
        <div class="col-auto container px-4">
            {}
        </div>
        <div class="row">
            <div class="d-inline-flex">
                <p class="px-1 m-0">)</p>
            </div>
        </div>
    </div>\
    """.format(
                parsed_rule["action"],
                __highlight(parsed_rule["proto"]),
                __highlight(parsed_rule["source_addr"]),
                __highlight(parsed_rule["source_port"]),
                __highlight(parsed_rule["direction"]),
                __highlight(parsed_rule["dest_addr"]),
                __highlight(parsed_rule["dest_port"]),
                options_html,
            )
        except Exception:
            html = """<p class="px-1 m-0">Failed to format signature.</p>"""

        rules_html.append(html)

    if len(rules_html) == 0:
        return None

    return "\n".join(rules_html)


def validate_rule(rule: str) -> tuple[bool, str]:
    filename = (
        str(hash("validate_rule" + rule + str(datetime.datetime.now()))) + ".rules"
    )
    path = os.path.join("/tmp", filename)

    formatted_rule = format_rule(rule)
    with open(path, "w") as fh:
        if formatted_rule is not None:
            fh.writelines(formatted_rule)
        else:
            fh.writelines(rule)

    log_path = path + ".out"
    os.mkdir(log_path)

    result = subprocess.run(
        ["suricata", "-T", "-v", "-S", path, "-l", log_path],
        capture_output=True,
        text=True,
    )

    rule_loaded = True
    if os.path.exists(os.path.join(log_path, "suricata.log")):
        with open(os.path.join(log_path, "suricata.log"), "r") as fh:
            log = "\n".join(fh.readlines())
        if "no rules were loaded" in log:
            rule_loaded = False
    else:
        rule_loaded = False

    os.remove(path)
    shutil.rmtree(log_path)

    if result.returncode != 0:
        return True, result.stderr

    return not rule_loaded, result.stdout


def get_user_scenario_hash(user: AbstractBaseUser, scenario: Scenario) -> str:
    hasher = hashlib.new("sha3_256")
    hasher.update(bytes(str(scenario.title) + user.get_username(), encoding="ascii"))

    return hasher.hexdigest()


@lru_cache(maxsize=128)
def get_user_ordered_scenarios(user: AbstractBaseUser) -> list[Scenario]:
    scenarios = sorted(
        Scenario.objects.all(),
        key=lambda scenario: str(scenario.ordering_priority)
        + "-"
        + get_user_scenario_hash(user, scenario),
        reverse=True,
    )
    return scenarios


def is_scenario_unlocked(user: AbstractBaseUser, scenario: Scenario) -> bool:
    if not REQUIRE_SCENARIO_UNLOCKING:
        return True

    scenarios = get_user_ordered_scenarios(user)
    scenario_i = [scenario.title for scenario in scenarios].index(scenario.title)

    if scenario_i == 0:
        return True

    previous_scenario = scenarios[scenario_i - 1]

    if UNLOCK_AFTER_SECONDS >= 0:
        unlocked_by_time = Submission.objects.filter(
            scenario=previous_scenario,
            user=user,
            submitted_at__lte=localtime()
            - datetime.timedelta(seconds=UNLOCK_AFTER_SECONDS),
            valid=True,
        ).exists()
        if unlocked_by_time:
            return True

    if UNLOCK_AFTER_COMPLETION:
        for submission in Submission.objects.filter(
            scenario=previous_scenario,
            user=user,
            valid=True,
            check_only=False,
            tested=True,
        ):
            unlocked_by_completion_expected = Result.objects.filter(
                submission=submission,
                test__expected=True,
                test__hidden=False,
                status="Success",
            ).exists()
            unlocked_by_completion_unexpected = Result.objects.filter(
                submission=submission,
                test__expected=False,
                test__hidden=False,
                status="Success",
            ).exists()
            unlocked_by_completion = (
                unlocked_by_completion_expected and unlocked_by_completion_unexpected
            )
            if unlocked_by_completion:
                return True

    return False


@lru_cache(maxsize=128)
def get_previous_and_next_user_scenarios(
    user: AbstractBaseUser, scenario: Scenario
) -> tuple[Optional[Scenario], Optional[Scenario]]:
    previous_scenario = None
    next_scenario = None

    user_ordered_scenarios = get_user_ordered_scenarios(user)

    for i, s in enumerate(user_ordered_scenarios):
        if s.title == scenario.title:
            if i > 0:
                previous_scenario = user_ordered_scenarios[i - 1]
            if i < len(user_ordered_scenarios) - 1:
                next_scenario = user_ordered_scenarios[i + 1]

    return (previous_scenario, next_scenario)


_cache_get_user_scenario_scores = cacheout.Cache(maxsize=8192)


@_cache_get_user_scenario_scores.memoize(ttl=60)
def get_user_scenario_scores(user: User, scenario: Scenario):
    best_submission_score = -100
    best_submission_submitted_at = None
    best_submission_hidden_score = -100
    best_submission_hidden_submitted_at = None

    for submission in (
        Submission.objects.filter(
            scenario=scenario, user=user, valid=True, check_only=False, tested=True
        )
        .order_by("submitted_at")
        .all()
    ):
        if submission.score is None or submission.hidden_score is None:
            continue

        if best_submission_score < submission.score:
            best_submission_score = submission.score
            best_submission_submitted_at = submission.submitted_at

        if best_submission_hidden_score < submission.hidden_score:
            best_submission_hidden_score = submission.hidden_score
            best_submission_hidden_submitted_at = submission.submitted_at

    if best_submission_submitted_at is None:
        best_submission_score = None
    if best_submission_hidden_submitted_at is None:
        best_submission_hidden_score = None

    return (
        best_submission_score,
        best_submission_submitted_at,
        best_submission_hidden_score,
        best_submission_hidden_submitted_at,
    )


_cache_get_user_scores = cacheout.Cache(maxsize=1024)


@_cache_get_user_scores.memoize(ttl=15)
def get_user_scores(user: User, force_datetime=False):
    score = 0
    obtained_at = datetime.datetime.fromisoformat("2000-01-01 00:00:00+00:00")
    staff_score = 0
    staff_obtained_at = datetime.datetime.fromisoformat("2000-01-01 00:00:00+00:00")

    for scenario in Scenario.objects.all():
        (
            best_submission_score,
            best_submission_submitted_at,
            best_submission_hidden_score,
            best_submission_hidden_submitted_at,
        ) = get_user_scenario_scores(user, scenario)

        if best_submission_submitted_at is not None and best_submission_score > 0:
            score += best_submission_score
            obtained_at = max(obtained_at, best_submission_submitted_at)

        if (
            best_submission_hidden_submitted_at is not None
            and best_submission_hidden_score > 0
        ):
            staff_score += best_submission_hidden_score
            staff_obtained_at = max(
                staff_obtained_at, best_submission_hidden_submitted_at
            )

    if not force_datetime and obtained_at == datetime.datetime.fromisoformat(
        "2000-01-01 00:00:00+00:00"
    ):
        obtained_at = None
    if not force_datetime and staff_obtained_at == datetime.datetime.fromisoformat(
        "2000-01-01 00:00:00+00:00"
    ):
        staff_obtained_at = None

    return score, obtained_at, staff_score, staff_obtained_at


def delete_cache(user: User, scenario: Scenario):
    result = get_user_scenario_scores.cache.delete(
        get_user_scenario_scores.cache_key(user, scenario)
    )

    if result == 1:
        logger.debug(
            f"Deleted cache for user {user.username} and scenario {scenario.title}"
        )
