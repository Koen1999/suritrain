import base64
import datetime
import io
import json
import logging
import os
import re
from typing import Union

import idstools
import idstools.rule
import matplotlib
import matplotlib.lines
import matplotlib.pyplot
import pandas
import seaborn
import suricata_check
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.core.exceptions import ObjectDoesNotExist
from django.forms import model_to_dict
from django.http import (
    FileResponse,
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotAllowed,
    HttpResponseNotFound,
    HttpResponseRedirect,
    HttpResponseServerError,
    JsonResponse,
)
from django.template import loader
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from .forms import RegisterForm
from .management.commands.dashboard import get_dashboard_dataframes
from .models import Result, Scenario, Submission, Test, UserPreferences
from .utils import (
    delete_cache,
    format_rule_html,
    get_previous_and_next_user_scenarios,
    get_user_ordered_scenarios,
    get_user_scores,
    is_scenario_unlocked,
    validate_rule,
)

SUBMIT_RATE_LIMIT = 5

logger = logging.getLogger(__name__)


def index(request: HttpRequest) -> HttpResponse:
    template = loader.get_template("main/index.html")
    context = {}

    return HttpResponse(template.render(context, request))


def register(request: HttpRequest) -> HttpResponse:
    if not getattr(settings, "REGISTRATION_ALLOWED", False):
        return HttpResponseForbidden("Registration is not allowed")

    if request.user.is_authenticated:
        return HttpResponseRedirect("/")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user: User = form.save()

            user.groups.add(
                Group.objects.get_or_create(
                    name=getattr(settings, "REGISTRATION_LEADERBOARD_GROUP", None)
                )[0]
            )
            user.groups.add(
                Group.objects.get_or_create(
                    name=getattr(settings, "REGISTRATION_EXPERIMENT_GROUP", None)
                )[0]
            )

            user.save()

            user_preferences = UserPreferences()
            user_preferences.user = user
            user_preferences.research_consent = form.accept_informed_consent
            user_preferences.save()

            login(request, user)
            return HttpResponseRedirect("/")
    else:
        form = RegisterForm()

    template = loader.get_template("main/register.html")
    context = {"form": form}

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def leaderboard(request: HttpRequest) -> HttpResponse:
    template = loader.get_template("main/leaderboard.html")

    show_hidden = False
    if isinstance(request.user, User) and request.user.is_staff:
        show_hidden = True
    if request.user.groups.filter(name="Leaderboard - Hidden").exists():
        show_hidden = True

    if isinstance(request.user, User) and request.user.is_staff:
        users = User.objects.all()
    else:
        users = (
            User.objects.filter(
                groups__name__in=[
                    group.name
                    for group in request.user.groups.exclude(
                        name__in=["Leaderboard - Hidden"]
                    )
                    if group.name.startswith("Leaderboard - ")
                ]
            )
            .exclude(groups__name__in=["Leaderboard - Hide"])
            .union(User.objects.filter(pk=request.user.pk))
            .all()
        )

    processed_users = []
    for user in users:
        score, obtained_at, staff_score, staff_obtained_at = get_user_scores(
            user, force_datetime=True
        )

        user_dict = {"name": user.username, "score": score, "obtained_at": obtained_at}
        if show_hidden:
            user_dict["staff_score"] = staff_score
            user_dict["staff_obtained_at"] = staff_obtained_at

        if request.user.is_staff or request.user.pk == user.pk or score > 0:
            processed_users.append(user_dict)

    if show_hidden:
        processed_users = sorted(
            processed_users, key=lambda user: user["staff_obtained_at"]
        )
        processed_users = sorted(
            processed_users, key=lambda user: user["staff_score"], reverse=True
        )
    else:
        processed_users = sorted(processed_users, key=lambda user: user["obtained_at"])
        processed_users = sorted(
            processed_users, key=lambda user: user["score"], reverse=True
        )

    context = {"show_hidden": show_hidden, "users": processed_users}

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def scenarios(request: HttpRequest) -> HttpResponse:
    template = loader.get_template("main/scenarios.html")
    context = {
        "scenarios": [
            scenario
            for scenario in get_user_ordered_scenarios(request.user)
            if is_scenario_unlocked(request.user, scenario)
        ]
    }

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def scenario_first(request: HttpRequest) -> HttpResponse:
    return HttpResponseRedirect(
        reverse("main:scenario", args=[get_user_ordered_scenarios(request.user)[0].id])
    )


@login_required(login_url="/login")
def scenario(request: HttpRequest, scenario_id: int) -> HttpResponse:
    try:
        scenario = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    if not request.user.is_staff:
        if not is_scenario_unlocked(request.user, scenario):
            return HttpResponseForbidden("Scenario is locked")

    if isinstance(request.user, User) and request.user.is_staff:
        tests = Test.objects.filter(scenario=scenario).all()
    else:
        tests = Test.objects.filter(scenario=scenario, hidden=False).all()

    last_checked_rule = (
        Submission.objects.filter(scenario=scenario, user=request.user)
        .order_by("-submitted_at")
        .first()
    )
    if last_checked_rule is not None:
        last_checked_rule = last_checked_rule.rule

    last_submitted_rule = (
        Submission.objects.filter(
            scenario=scenario, user=request.user, check_only=False
        )
        .order_by("-submitted_at")
        .first()
    )
    if last_submitted_rule is not None:
        last_submitted_rule = last_submitted_rule.rule

    template = loader.get_template("main/scenario.html")
    context = {
        "scenario": scenario,
        "tests": tests,
        "last_checked_rule": last_checked_rule,
        "last_checked_rule_formatted": format_rule_html(last_checked_rule),
        "last_submitted_rule": last_submitted_rule,
        "last_submitted_rule_formatted": format_rule_html(last_submitted_rule),
        "is_staff": request.user.is_staff,
    }

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def scenario_test(request: HttpRequest, scenario_id: int, test_id: int) -> HttpResponse:
    try:
        scenario = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    if not request.user.is_staff:
        if not is_scenario_unlocked(request.user, scenario):
            return HttpResponseForbidden("Scenario is locked")

    try:
        if isinstance(request.user, User) and request.user.is_staff:
            test = Test.objects.filter(scenario=scenario).get(pk=test_id)
        else:
            test = (
                Test.objects.filter(scenario=scenario, hidden=False)
                .all()
                .get(pk=test_id)
            )
    except Test.DoesNotExist:
        return HttpResponseNotFound("Test does not exist")

    submission = (
        Submission.objects.filter(
            scenario=scenario, user=request.user, check_only=False
        )
        .order_by("-submitted_at")
        .first()
    )
    if submission is None:
        return HttpResponseNotFound("Submission does not exist")

    try:
        result = Result.objects.filter(test=test, submission=submission).get()
    except Result.DoesNotExist:
        return HttpResponseNotFound("Result does not exist")

    template = loader.get_template("main/scenario_test.html")
    context = {
        "scenario": scenario,
        "test": test,
        "last_submitted_rule": submission.rule,
        "last_submitted_rule_formatted": format_rule_html(submission.rule),
        "result": result,
        "yaml": list(result.yaml.split("\n")),
        "log": [line.strip() for line in result.log.split("\n") if line.strip() != ""],
        "eve": [line.strip() for line in result.eve.split("\n") if line.strip() != ""],
        "fast": [
            line.strip() for line in result.fast.split("\n") if line.strip() != ""
        ],
    }

    return HttpResponse(template.render(context, request))


@csrf_exempt
def check(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    if "rule" not in request.POST:
        return HttpResponseBadRequest("Field `rule` missing")
    rule = request.POST["rule"]

    include = None
    if "include" in request.POST:
        include = request.POST["include"]

    has_errors, output = validate_rule(rule)

    issues = []
    try:
        parsed_rule = idstools.rule.parse(rule)
        issues = [
            {"code": issue.code, "message": issue.message}
            for issue in suricata_check.analyze_rule(
                parsed_rule,
                checkers=suricata_check.get_checkers(include=((include or "Q.*"),)),
            ).issues
        ]
    except suricata_check.utils.checker_typing.InvalidRuleError:
        return HttpResponseBadRequest("Invalid and unparseable rule")
    except:  # noqa: E722
        return HttpResponseServerError("suricata-check failure")

    response = JsonResponse(
        {
            "formatted": format_rule_html(rule),
            "has_errors": has_errors,
            "output": output,
            "issues": issues,
        }
    )

    response.headers["Access-Control-Allow-Origin"] = "*"

    return response


@login_required(login_url="/login")
def submit(request: HttpRequest, scenario_id: int) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    if "rule" not in request.POST:
        return HttpResponseBadRequest("Field `rule` missing")
    rule = request.POST["rule"]
    rule = rule.replace("“", '"').replace("”", '"')

    try:
        scenario = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    if not request.user.is_staff:
        if not is_scenario_unlocked(request.user, scenario):
            return HttpResponseForbidden("Scenario is locked")

    user = request.user

    most_recent_submission = (
        Submission.objects.filter(scenario=scenario, user=user)
        .order_by("-submitted_at")
        .first()
    )
    if most_recent_submission is not None:
        seconds_since_last_submission = (
            most_recent_submission.submitted_at
            - datetime.datetime.now(tz=most_recent_submission.submitted_at.tzinfo)
        ).seconds
        if seconds_since_last_submission < SUBMIT_RATE_LIMIT:
            return HttpResponse(
                "Submissions are allowed at most once every {} seconds.".format(
                    SUBMIT_RATE_LIMIT
                ),
                status=429,
            )

    check_only = False
    if "check_only" in request.POST:
        check_only = request.POST["check_only"] == "true"

    has_errors, output = validate_rule(rule)

    # issues = []
    # try:
    #     parsed_rule = idstools.rule.parse(rule)
    #     issues = [
    #         {"code": issue.code, "message": issue.message}
    #         for issue in suricata_check.analyze_rule(
    #             parsed_rule, checkers=suricata_check.get_checkers(include=("M.*",))
    #         ).issues
    #     ]
    # except:
    #     pass

    submission = Submission(
        rule=rule,
        user=user,
        scenario=scenario,
        valid=not has_errors,
        suricata_output=output,
        check_only=check_only,
    )
    submission.check()
    submission.save()

    if not check_only:
        delete_cache(User.objects.get(pk=user.pk), scenario)

    return JsonResponse(
        {
            "submission": model_to_dict(submission, exclude=["scenario", "user"]),
            "submitted_at": submission.submitted_at,
            "formatted": format_rule_html(rule),
            "has_errors": has_errors,
            "output": output,
            # "suricata_check": issues,
        }
    )


@login_required(login_url="/login")
def status(request: HttpRequest, scenario_id: int) -> HttpResponse:
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    try:
        scenario = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    if not request.user.is_staff:
        if not is_scenario_unlocked(request.user, scenario):
            return HttpResponseForbidden("Scenario is locked")

    user = request.user

    if isinstance(request.user, User) and request.user.is_staff:
        tests = scenario.tests.all()
    else:
        tests = scenario.tests.filter(hidden=False).all()

    submission = (
        Submission.objects.filter(
            user=user, scenario=scenario, valid=True, check_only=False
        )
        .order_by("-submitted_at")
        .first()
    )

    if submission is None:
        return JsonResponse(
            {
                "tests": [
                    model_to_dict(test, exclude=["pcap", "hidden"]) for test in tests
                ],
            },
        )
    rule = submission.rule

    if isinstance(request.user, User) and request.user.is_staff:
        results = Result.objects.filter(submission=submission).all()
    else:
        results = Result.objects.filter(submission=submission, test__hidden=False).all()

    last_updated = None
    if len(results) > 0:
        last_updated = max(result.generated_at for result in results)

    previous_scenario, next_scenario = get_previous_and_next_user_scenarios(
        request.user, scenario
    )

    return JsonResponse(
        {
            "submission": model_to_dict(submission, exclude=["scenario", "user"]),
            "submitted_at": submission.submitted_at,
            "formatted": format_rule_html(rule),
            "tests": [
                model_to_dict(test, exclude=["pcap", "hidden"]) for test in tests
            ],
            "results": [
                model_to_dict(result, exclude=["submission", "yaml", "log", "eve"])
                for result in results
            ],
            "last_updated": last_updated,
            "previous_scenario": (
                model_to_dict(previous_scenario, exclude=["details_pdf"])
                if previous_scenario
                else None
            ),
            "next_scenario": (
                model_to_dict(next_scenario, exclude=["details_pdf"])
                if next_scenario
                else None
            ),
            "next_scenario_unlocked": (
                is_scenario_unlocked(request.user, next_scenario)
                if next_scenario
                else None
            ),
        }
    )


@login_required(login_url="/login")
def handout(request: HttpRequest) -> Union[FileResponse, HttpResponseForbidden]:
    try:
        user_group_id = int(
            User.objects.get(pk=request.user.pk)
            .groups.get(name__contains="Experiment Group - ")
            .name.replace("Experiment Group - ", "")
        )
    except ObjectDoesNotExist:
        user_group_id = None

    if os.path.exists(f"handouts/group{user_group_id}"):
        path = f"handouts/group{user_group_id}/handout.pdf"
    else:
        return HttpResponseForbidden("You are not allowed to download the handout")

    return FileResponse(open(path, "rb"), as_attachment=True)


@login_required(login_url="/login")
def dashboard(request: HttpRequest) -> HttpResponse:
    if not isinstance(request.user, User) or not request.user.is_staff:
        return HttpResponseForbidden()

    result = get_dashboard_dataframes()

    if result is None:
        template = loader.get_template("main/dashboard_loading.html")
        context = {}
        return HttpResponse(template.render(context, request))
    participant_df, rule_df, result_df, update_df, change_df = result

    rule_errors = {}
    participant_errors = {}
    mapping = {}
    error_rule_mapping = {}

    for i, row in rule_df[~rule_df["Valid"]].iterrows():
        for raw_line in row["Suricata Output"].splitlines():
            line = raw_line

            line = re.compile(r"rule \d+").sub("rule []", line)
            line = re.compile(r"signature \".*\"($| from)").sub(
                r'signature "[]" \1', line
            )
            line = re.compile(r"from file .* at").sub("from file [] at", line)
            line = re.compile(r"line \d+").sub("line []", line)
            line = re.compile(r"parse error, .*").sub("parse error, []", line)
            line = re.compile(
                r"bad option value formatting \(possible missing semicolon\) for keyword (.*)\: .*"
            ).sub(
                r"bad option value formatting \(possible missing semicolon\) for keyword \1\: []",
                line,
            )
            line = re.compile(r"failed to parse (\w+) \".*\"").sub(
                r'failed to parse \1 "[]"', line
            )
            line = re.compile(r" \".*\" is not a valid").sub(
                r' "[]" is not a valid"', line
            )
            line = re.compile(r"unknown regex modifier '.*'").sub(
                r"unknown regex modifier '[]'", line
            )
            line = re.compile(r"Variable \".*\" ").sub(r'Variable "[]" ', line)
            line = re.compile(r"protocol \".*\" ").sub(r'protocol "[]" ', line)
            line = re.compile(r"sid value \d+ ").sub(r"sid value [] ", line)
            line = re.compile(r"invalid action \".*\" ").sub(
                r'invalid action "[]" ', line
            )
            line = re.compile(r"unknown rule keyword '.*'").sub(
                r"unknown rule keyword '[]'", line
            )

            if line in rule_errors:
                rule_errors[line] += 1
            else:
                rule_errors[line] = 1

            if line in participant_errors:
                if row["User ID"] not in participant_errors[line]:
                    participant_errors[line].append(row["User ID"])
            else:
                participant_errors[line] = [row["User ID"]]

            if line in error_rule_mapping:
                error_rule_mapping[line].append(row["Rule"])
            else:
                error_rule_mapping[line] = [row["Rule"]]

            if line in mapping:
                mapping[line].append(raw_line)
            else:
                mapping[line] = [raw_line]

    participant_errors = {k: len(v) for k, v in participant_errors.items()}

    temp_a = pandas.Series(participant_errors).sort_values(ascending=False).to_dict()
    temp_b = {
        error: pandas.Series(rules).unique().tolist()
        for error, rules in error_rule_mapping.items()
    }
    syntax_errors = {
        error: {"count": temp_a[error], "rules": temp_b[error]}
        for error in temp_a.keys()
    }

    df = rule_df[(rule_df["Final Best Submission During CTF"])]

    y_cols = [
        "Precision Visible",
        "Precision Invisible",
        "Recall Visible",
        "Recall Invisible",
    ]

    df = df.melt(
        id_vars=["Scenario", "User ID"],
        value_vars=y_cols,
        var_name="Performance Score Type",
        value_name="Performance Score",
    )

    for user_id in df["User ID"].unique():
        user_df = df[(df["User ID"] == user_id)]
        for scenario in df["Scenario"].unique():
            if scenario not in user_df["Scenario"].unique():
                df = pandas.concat(
                    [
                        df,
                        pandas.DataFrame(
                            [
                                {
                                    "Scenario": scenario,
                                    "User ID": user_id,
                                    "Performance Score Type": t,
                                    "Performance Score": 0.0,
                                }
                                for t in df["Performance Score Type"].unique()
                            ]
                        ),
                    ],
                    ignore_index=True,
                )

    fig, ax = matplotlib.pyplot.subplots(figsize=(8, 4))

    palette = seaborn.color_palette()

    seaborn.boxplot(
        df,
        x="Performance Score Type",
        y="Performance Score",
        hue="Scenario",
        ax=ax,
        gap=0.1,
        medianprops={"linewidth": 3},
    )

    custom_lines = [
        matplotlib.lines.Line2D([0], [0], color=palette[i], lw=4)
        for i in range(df["Scenario"].nunique())
    ]
    custom_labels = [f"{y_col} - Median" for y_col in df["Scenario"].unique()]
    ax.legend(
        custom_lines, custom_labels, loc="upper right", bbox_to_anchor=(0.85, 0.85)
    )

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=600)
    image_boxplot_precision_recall_base64 = (
        base64.b64encode(buf.getvalue()).decode("utf-8").replace("\n", "")
    )
    buf.close()

    template = loader.get_template("main/dashboard_classroom.html")
    context = {
        "syntax_errors": syntax_errors,
        "image_boxplot_precision_recall_base64": image_boxplot_precision_recall_base64,
        "scenarios": Scenario.objects.all(),
    }

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def dashboard_scenario(request: HttpRequest, scenario_id: int) -> HttpResponse:
    if not isinstance(request.user, User) or not request.user.is_staff:
        return HttpResponseForbidden()

    try:
        scenario_model = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    result = get_dashboard_dataframes()

    if result is None:
        template = loader.get_template("main/dashboard_loading.html")
        context = {}
        return HttpResponse(template.render(context, request))
    participant_df, rule_df, result_df, update_df, change_df = result

    best_submissions = rule_df[
        (rule_df["Final Best Submission During CTF"])
    ].index.to_list()
    df = result_df[result_df["Rule ID"].apply(lambda x: x in best_submissions)]

    df["Result Numeric"] = df.apply(
        lambda x: (
            2 if x["Result"] == "Success" else 0 if x["Result"] == "Failure" else 1
        ),
        axis=1,
    )

    scenario = scenario_model.title

    scenario_df = df[(df["Scenario"] == scenario)].sort_values(
        ["Result Numeric", "Test Hidden", "Test Malicious", "Test"]
    )

    fig, ax = matplotlib.pyplot.subplots(figsize=(16, 4))

    plot_df = scenario_df.copy()
    plot_df["Test"] = plot_df.apply(
        lambda row: row["Test"]
        + f"\n({'Hidden' if row['Test Hidden'] else 'Visible'} {'Malicious' if row['Test Malicious'] else 'Benign'})",
        axis=1,
    )
    plot_df = (
        plot_df.groupby(["Test"])["Result"]
        .value_counts()
        .reset_index()
        .pivot(index="Test", columns="Result", values="count")
        .sort_values(["Success", "Warning", "Failure"], ascending=False)
    )
    plot_df = plot_df.loc[:, ["Failure", "Warning", "Success"]]

    plot_df.plot.bar(
        color={"Failure": "#fc8d59", "Warning": "#ffffbf", "Success": "#91bfdb"},
        ax=ax,
        stacked=True,
    )

    ax.set_xticks(ax.get_xticks())
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")

    ax.set_yticks(range(scenario_df["User ID"].nunique() + 1))

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=600)
    image_tests_success_failure_base64 = (
        base64.b64encode(buf.getvalue()).decode("utf-8").replace("\n", "")
    )
    buf.close()

    code_desc = {
        "Q000": "No Limited Proxy",
        "Q001": "No Successful Malicious Action",
        "Q002": "No Alert Throttling",
        "Q003": "No Exceptions",
        "Q004": "No Generalized Characteristic",
        "Q005": "No Generalized Position",
    }

    scenario_rule_df = rule_df[
        rule_df.apply(
            lambda row: int(row.name) in scenario_df["Rule ID"].astype(int).values,
            axis=1,
        )
    ]

    for code, desc in code_desc.items():
        scenario_rule_df[desc] = scenario_rule_df["Design Principle Issues"].apply(
            lambda x: code in x
        )

    fig, ax = matplotlib.pyplot.subplots(figsize=(8, 4))

    plot_df = scenario_rule_df.reset_index().melt(
        id_vars=["Rule ID"],
        value_vars=code_desc.values(),
        var_name="Principle",
        value_name="Issue",
    )
    plot_df = (
        plot_df.groupby(["Principle"])["Issue"]
        .value_counts()
        .reset_index()
        .pivot(index="Principle", columns="Issue", values="count")
        .sort_values([False, True], ascending=False)
    )
    plot_df.index = plot_df.index.str.replace(" ", "\n")

    plot_df.plot.bar(
        color={True: "#fc8d59", False: "#91bfdb"},
        ax=ax,
        stacked=True,
    )

    ax.set_xticks(ax.get_xticks())
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0, ha="center")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=600)
    image_design_principle_adherence_base64 = (
        base64.b64encode(buf.getvalue()).decode("utf-8").replace("\n", "")
    )
    buf.close()

    inadhering_rules = {}
    for principle in code_desc.values():
        inadhering_rules[principle] = []
        for rule in scenario_rule_df[
            scenario_rule_df.apply(
                lambda row: int(row.name)
                in scenario_rule_df[scenario_rule_df[principle]]
                .index.astype(int)
                .values,
                axis=1,
            )
        ]["Rule"].unique():
            inadhering_rules[principle].append(rule)

    best_submissions = rule_df[
        (rule_df["Final Best Submission During CTF"])
    ].index.to_list()
    df = result_df[result_df["Rule ID"].apply(lambda x: x in best_submissions)]

    df["Result Numeric"] = df.apply(
        lambda x: (
            2 if x["Result"] == "Success" else 0 if x["Result"] == "Failure" else 1
        ),
        axis=1,
    )

    scenario = scenario_model.title

    scenario_df = df[(df["Scenario"] == scenario)].sort_values(
        ["Result Numeric", "Test Hidden", "Test Malicious", "Test"]
    )

    tests_fps = {}
    for test in scenario_df["Test"].unique():
        test_df = scenario_df[(scenario_df["Test"] == test)]

        detections = []
        for _, rule_row in test_df.iterrows():
            rule_id = rule_row["Rule ID"]
            rule = rule_df.loc[rule_id, "Rule"]
            user_id = rule_row["User ID"]
            scenario = rule_row["Scenario"]

            for line in rule_row["Eve"].splitlines():
                try:
                    parsed_line = json.loads(line)
                except:
                    continue
                timestamp = parsed_line["timestamp"]
                src_ip = parsed_line["src_ip"]
                src_port = parsed_line["src_port"]
                dest_ip = parsed_line["dest_ip"]
                dest_port = parsed_line["dest_port"]
                proto = parsed_line["proto"]
                flow_start = parsed_line["flow"]["start"]
                flow_src_ip = parsed_line["flow"]["src_ip"]
                flow_src_port = parsed_line["flow"]["src_port"]
                flow_dest_ip = parsed_line["flow"]["dest_ip"]
                flow_dest_port = parsed_line["flow"]["dest_port"]
                try:
                    payload = parsed_line["payload"]
                except:
                    decoded_payload = b"No payload"
                try:
                    decoded_payload = base64.b64decode(payload).decode("utf-8")
                except:
                    decoded_payload = "Raw payload: " + str(payload)
                detections.append(
                    (
                        rule_id,
                        rule,
                        user_id,
                        scenario,
                        test,
                        timestamp,
                        src_ip,
                        src_port,
                        dest_ip,
                        dest_port,
                        proto,
                        flow_start,
                        flow_src_ip,
                        flow_src_port,
                        flow_dest_ip,
                        flow_dest_port,
                        payload,
                        decoded_payload,
                    )
                )

        detection_df = pandas.DataFrame(
            detections,
            columns=[
                "Rule ID",
                "Rule",
                "User ID",
                "Scenario",
                "Test",
                "Timestamp",
                "Src IP",
                "Src Port",
                "Dest IP",
                "Dest Port",
                "Proto",
                "Flow Start",
                "Flow Src IP",
                "Flow Src Port",
                "Flow Dest IP",
                "Flow Dest Port",
                "Payload",
                "Decoded Payload",
            ],
        )
        detection_df["Flow Tuple"] = detection_df.apply(
            lambda row: tuple(
                row[
                    [
                        "Flow Start",
                        "Proto",
                        "Flow Src IP",
                        "Flow Src Port",
                        "Flow Dest IP",
                        "Flow Dest Port",
                    ]
                ]
            ),
            axis=1,
        )
        detection_df["Timestamp"] = pandas.to_datetime(detection_df["Timestamp"])
        detection_df["Flow Start"] = pandas.to_datetime(detection_df["Flow Start"])

        counts = detection_df[["Flow Tuple", "Decoded Payload"]].value_counts()

        test_fps = []

        for index, count in counts.items():
            flow_tuple, decoded_payload = index
            rules = (
                detection_df.loc[
                    (detection_df["Flow Tuple"] == flow_tuple)
                    & (detection_df["Decoded Payload"] == decoded_payload)
                ]["Rule"]
                .unique()
                .tolist()
            )
            test_fps.append(
                {
                    "flow_tuple": flow_tuple,
                    "decoded_payload": decoded_payload,
                    "rules": rules,
                    "count": count,
                }
            )

        tests_fps[test] = test_fps

    df = participant_df[participant_df["Participated"]]
    x_col = "User ID"
    y_cols = ["Best Overall Precision During CTF", "Best Overall Recall During CTF"]

    fig, ax = matplotlib.pyplot.subplots(figsize=(16, 4))

    # df[x_col] = [str(x) for x in range(len(df.index))]
    df = df.reset_index()

    palette = seaborn.color_palette()

    df_plot = df.melt(
        id_vars=["User ID"],
        value_vars=y_cols,
        var_name="Performance Score Type",
        value_name="Performance Score",
    )

    seaborn.barplot(
        df_plot,
        x=x_col,
        y="Performance Score",
        hue="Performance Score Type",
        ax=ax,
        alpha=0.3,
    )

    for i, y_col in enumerate(y_cols):
        seaborn.lineplot(
            x=[-1, len(df.index)],
            y=df[y_col].mean(),
            ax=ax,
            color=palette[i],
            label=y_col + " - Median",
            linestyle="--",
        )

    custom_lines = [
        matplotlib.lines.Line2D([0], [0], color=palette[i], lw=4)
        for i in range(len(y_cols))
    ] + [
        matplotlib.lines.Line2D([0], [0], color=palette[i], lw=1, linestyle="--")
        for i in range(len(y_cols))
    ]
    custom_labels = y_cols + [f"{y_col} - Mean" for y_col in y_cols]
    ax.legend(custom_lines, custom_labels)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=600)
    image_participant_performance_base64 = (
        base64.b64encode(buf.getvalue()).decode("utf-8").replace("\n", "")
    )
    buf.close()

    template = loader.get_template("main/dashboard_scenario.html")
    context = {
        "scenario": scenario_model,
        "image_tests_success_failure_base64": image_tests_success_failure_base64,
        "image_design_principle_adherence_base64": image_design_principle_adherence_base64,
        "inadhering_rules": inadhering_rules,
        "tests_fps": tests_fps,
        "image_participant_performance_base64": image_participant_performance_base64,
        "users": User.objects.filter(id__in=scenario_df["User ID"].unique()).all(),
    }

    return HttpResponse(template.render(context, request))


@login_required(login_url="/login")
def dashboard_scenario_user(
    request: HttpRequest, scenario_id: int, user_id: int
) -> HttpResponse:
    if not isinstance(request.user, User) or not request.user.is_staff:
        return HttpResponseForbidden()

    try:
        scenario_model = Scenario.objects.get(pk=scenario_id)
    except Scenario.DoesNotExist:
        return HttpResponseNotFound("Scenario does not exist")

    try:
        user_model = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return HttpResponseNotFound("User does not exist")

    result = get_dashboard_dataframes()

    if result is None:
        template = loader.get_template("main/dashboard_loading.html")
        context = {}
        return HttpResponse(template.render(context, request))
    participant_df, rule_df, result_df, update_df, change_df = result

    x_col = (
        "Normalized Scenario Progression Towards Final Valid Submitted Rule During CTF"
    )
    y_cols = ["Precision", "Recall"]

    user_id = user_model.id
    scenario = scenario_model.title

    fig, axs = matplotlib.pyplot.subplots(
        figsize=(8, 6),
        nrows=2,
        ncols=2,
        gridspec_kw={
            "width_ratios": [5, 1],
            "height_ratios": [1, 5],
            "wspace": 0.05,
            "hspace": 0.05,
        },
        sharex=False,
        sharey=False,
    )

    axs[0, 1].remove()

    mask = rule_df["Valid"] & rule_df["Submitted During CTF"]

    extra_mask = rule_df["Scenario"] == scenario
    extra_extra_mask = rule_df["User ID"] == user_id

    # Plot performance on top
    for y_col in y_cols:
        seaborn.lineplot(
            x=rule_df.loc[mask & extra_mask & extra_extra_mask, x_col],
            y=rule_df.loc[mask & extra_mask & extra_extra_mask, y_col],
            label=y_col,
            ax=axs[0, 0],
        )

    # Plot changes in the main window
    plot_df = change_df[
        change_df["Next Rule ID"].apply(
            lambda x: x
            in rule_df.loc[
                mask & extra_mask & extra_extra_mask & (~rule_df["Multiple Rules"]),
                x_col,
            ].index
        )
    ]
    plot_df[x_col] = plot_df["Next Rule ID"].apply(lambda x: rule_df.loc[x, x_col])

    str_category_converter = matplotlib.category.StrCategoryConverter()
    change_freqs = plot_df["Field"].value_counts(normalize=True).sort_values()
    unit_data = matplotlib.category.UnitData(change_freqs.index)
    for i, row in plot_df.iterrows():
        color = "black"
        marker = "."
        if row["Change Type"] == "Added":
            color = "green"
            marker = "1"
        if row["Change Type"] == "Modified":
            color = "orange"
            marker = "2"
        if row["Change Type"] == "Removed":
            color = "red"
            marker = "3"

        # update = update_df[update_df["Changes"].apply(lambda x: str(row.name) in x.split(","))].iloc[0]
        # color="grey"
        # if (update["Change in Precision"] >= 0.0 and update["Change in Recall"] >= 0.0 and update["Change in F1"] != 0.0):
        #     color = "green"
        # if (update["Change in Precision"] <= 0.0 and update["Change in Recall"] <= 0.0 and update["Change in F1"] != 0.0):
        #     color = "red"
        # if (update["Change in Precision"] > 0.0 and update["Change in Recall"] < 0.0) or (update["Change in Precision"] < 0.0 and update["Change in Recall"] > 0.0):
        #     color = "orange"

        axs[1, 0].plot(
            row[x_col],
            str_category_converter.convert(
                row["Field"], unit=unit_data, axis=axs[1, 0]
            ),
            marker=marker,
            markersize=15,
            markeredgewidth=2,
            markerfacecolor=color,
            markeredgecolor=color,
            alpha=0.75,
        )

    x0 = 0.0
    x1 = None
    for i, row in rule_df.loc[mask & extra_mask & extra_extra_mask].iterrows():
        if row["Multiple Rules"]:
            if x1 is None:
                x1 = row[x_col]
        else:
            if x1 is not None:
                axs[1, 0].axvspan(x0, x1, color="grey", alpha=0.2)
                x1 = None
            x0 = row[x_col]

    axisinfo = str_category_converter.axisinfo(unit_data, axs[1, 0])
    axs[1, 0].yaxis.set_major_locator(axisinfo.majloc)
    axs[1, 0].yaxis.set_major_formatter(axisinfo.majfmt)

    # Plot density of changes on the side
    axs[1, 1].yaxis.set_major_locator(axisinfo.majloc)
    axs[1, 1].yaxis.set_major_formatter(axisinfo.majfmt)
    axs[1, 1].barh(change_freqs.index, change_freqs.values)

    # Limit x-axis
    axs[0, 0].set_xlim(-0.01, 1.01)
    axs[1, 0].set_xlim(-0.01, 1.01)

    # Limit y-axis
    axs[0, 0].set_ylim(-0.01, 1.01)

    # Drop labels on the top right
    axs[0, 0].set_xlabel(None)
    axs[0, 0].set_xticklabels([])
    axs[1, 1].set_yticklabels([])

    # Set label on main plot
    axs[1, 0].set_xlabel(x_col)

    # Move legend
    axs[0, 0].legend(loc="upper left", bbox_to_anchor=(1, 1))

    rules = rule_df.loc[mask & extra_mask & extra_extra_mask, "Rule"].values.tolist()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=600)
    image_engineering_process_base64 = (
        base64.b64encode(buf.getvalue()).decode("utf-8").replace("\n", "")
    )
    buf.close()

    template = loader.get_template("main/dashboard_scenario_user.html")
    context = {
        "scenario": scenario_model,
        "user": user_model,
        "image_engineering_process_base64": image_engineering_process_base64,
        "rules": rules,
    }

    return HttpResponse(template.render(context, request))
