from django.contrib import admin
from django.db.models.query import QuerySet

from .models import Pcap, Result, Scenario, Submission, Test, UserPreferences
from .utils import validate_rule


@admin.action(description="Test submissions again")
def mark_for_testing(
    modeladmin, request, queryset: QuerySet["Submission"]  # noqa: ANN001, ARG001
) -> None:
    Result.objects.filter(submission__in=queryset).delete()
    queryset.update(tested=False)


@admin.action(description="Check submission validity and collect Suricata output")
def check_validity(
    modeladmin, request, queryset: QuerySet["Submission"]  # noqa: ANN001, ARG001
) -> None:
    for submission in queryset:
        has_errors, output = validate_rule(submission.rule)
        submission.valid = not has_errors
        submission.suricata_output = output
        submission.save()


@admin.register(Pcap)
class PcapAdmin(admin.ModelAdmin):
    list_display = ("title",)


@admin.register(Test)
class TestAdmin(admin.ModelAdmin):
    list_display = (
        "scenario",
        "expected",
        "hidden",
        "title",
    )
    list_filter = ["scenario", "expected", "hidden"]


@admin.register(Scenario)
class ScenarioAdmin(admin.ModelAdmin):
    list_display = ("title", "ordering_priority")


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    readonly_fields = ("score", "hidden_score")
    list_display = (
        "scenario",
        "user",
        "rule",
        "valid",
        "submitted_at",
        "check_only",
        "tested",
        "score",
        "hidden_score",
    )
    list_filter = ["user", "scenario", "valid", "check_only", "tested"]
    search_fields = ["rule"]
    actions = [mark_for_testing, check_validity]


@admin.register(Result)
class ResultAdmin(admin.ModelAdmin):
    list_display = (
        "test__scenario",
        "test",
        "submission__user",
        "submission__rule",
        "status",
        "score",
        "submission__submitted_at",
        "n_alerts",
    )
    list_filter = [
        "test__scenario",
        "test",
        "submission__user",
        "status",
        "test__expected",
        "test__hidden",
    ]


@admin.register(UserPreferences)
class UserPreferencesAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "research_consent",
    )
