import datetime
import logging

import idstools
import idstools.rule
import suricata_check
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
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
from .models import Result, Scenario, Submission, Test
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
    if request.user.is_authenticated:
        return HttpResponseRedirect("/")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.save()
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
    if request.user.is_staff:
        show_hidden = True
    if request.user.groups.filter(name="Leaderboard - Hidden").exists():
        show_hidden = True

    if request.user.is_staff:
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

    if request.user.is_staff:
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

    response = HttpResponse(template.render(context, request))

    return response


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
        if request.user.is_staff:
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
        "yaml": [line for line in result.yaml.split("\n")],
        "log": [line.strip() for line in result.log.split("\n") if line.strip() != ""],
        "eve": [line.strip() for line in result.eve.split("\n") if line.strip() != ""],
        "fast": [
            line.strip() for line in result.fast.split("\n") if line.strip() != ""
        ],
    }

    response = HttpResponse(template.render(context, request))

    return response


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
    # except:  # noqa: E722
    #     pass

    submission = Submission(
        rule=rule,
        user=user,
        scenario=scenario,
        valid=not has_errors,
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

    if request.user.is_staff:
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
        response = JsonResponse(
            {
                "tests": [
                    model_to_dict(test, exclude=["pcap", "hidden"]) for test in tests
                ],
            },
        )

        return response

    rule = submission.rule

    if request.user.is_staff:
        results = Result.objects.filter(submission=submission).all()
    else:
        results = Result.objects.filter(submission=submission, test__hidden=False).all()

    last_updated = None
    if len(results) > 0:
        last_updated = max(result.generated_at for result in results)

    previous_scenario, next_scenario = get_previous_and_next_user_scenarios(
        request.user, scenario
    )

    response = JsonResponse(
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

    return response


@login_required(login_url="/login")
def handout(request: HttpRequest) -> FileResponse:
    try:
        user_group_id = int(
            User.objects.get(pk=request.user.pk)
            .groups.get(name__contains="Experiment Group - ")
            .name.replace("Experiment Group - ", "")
        )
    except ObjectDoesNotExist:
        user_group_id = None

    if user_group_id == 1:
        path = "handouts/group1/handout.pdf"
    elif user_group_id == 2:
        path = "handouts/group2/handout.pdf"
    else:
        path = "handouts/group1/handout.pdf"

    return FileResponse(open(path, "rb"), as_attachment=True)
