from typing import Optional

from django.contrib.auth.models import User
from django.db.models import (
    CASCADE,
    BooleanField,
    CharField,
    DateTimeField,
    FileField,
    ForeignKey,
    IntegerField,
    Model,
    Sum,
    TextField,
    URLField,
)
from django.db.models.manager import BaseManager


class Pcap(Model):
    title = CharField(max_length=64)
    pcap = FileField(upload_to="pcap")
    note = CharField(max_length=256, blank=True)
    reference_link = URLField(blank=True)
    yaml = TextField(default="", blank=True)

    class Meta:
        verbose_name_plural = "pcaps"
        ordering = ["title"]

    def __str__(self):
        return str(self.title)


class Scenario(Model):
    title = CharField(max_length=128)
    pcap = ForeignKey(Pcap, on_delete=CASCADE)
    details_pdf = FileField(upload_to="scenario_details", blank=True)
    description = TextField(max_length=8192)
    ordering_priority = IntegerField(default=0)

    class Meta:
        verbose_name_plural = "scenarios"
        ordering = ["-ordering_priority", "title"]

    @property
    def tests(self) -> BaseManager["Test"]:
        return Test.objects.filter(scenario=self).all()

    @property
    def submissions(self) -> BaseManager["Submission"]:
        return Submission.objects.filter(scenario=self).all()

    @property
    def results(self) -> BaseManager["Result"]:
        return Result.objects.filter(
            test__scenario=self, submission__scenario=self
        ).all()

    def __str__(self):
        return str(self.title)


class Test(Model):
    title = CharField(max_length=64)
    pcap = ForeignKey(Pcap, on_delete=CASCADE)
    scenario = ForeignKey(Scenario, on_delete=CASCADE)
    expected = BooleanField()
    hidden = BooleanField()

    class Meta:
        verbose_name_plural = "tests"
        ordering = ["scenario", "hidden", "-expected", "title"]

    @property
    def results(self) -> BaseManager["Result"]:
        return Result.objects.filter(test=self).all()

    def __str__(self):
        return str(self.title)


class Submission(Model):
    scenario = ForeignKey(Scenario, on_delete=CASCADE)
    user = ForeignKey(User, on_delete=CASCADE)
    rule = CharField(max_length=4096)
    submitted_at = DateTimeField(auto_now_add=True)
    check_only = BooleanField()
    valid = BooleanField()
    tested = BooleanField(default=False)

    class Meta:
        verbose_name_plural = "submissions"
        ordering = ["-submitted_at"]

    @property
    def results(self) -> BaseManager["Result"]:
        return Result.objects.filter(submission=self).all()

    @property
    def score(self) -> Optional[int]:
        if (
            self.results.filter(test__hidden=False).count()
            != self.scenario.tests.filter(hidden=False).count()
        ):
            return None
        return self.results.filter(test__hidden=False).aggregate(Sum("score"))[
            "score__sum"
        ]

    @property
    def hidden_score(self) -> Optional[int]:
        if self.results.count() != self.scenario.tests.count():
            return None
        return self.results.aggregate(Sum("score"))["score__sum"]

    def __str__(self):
        return str((self.scenario, self.user, self.submitted_at))


class Result(Model):
    submission = ForeignKey(Submission, on_delete=CASCADE)
    test = ForeignKey(Test, on_delete=CASCADE)
    status = CharField()
    score = IntegerField()
    generated_at = DateTimeField(auto_now_add=True)
    yaml = TextField()
    log = TextField()
    eve = TextField()
    fast = TextField()
    n_alerts = IntegerField()

    class Meta:
        verbose_name_plural = "results"
        ordering = ["-generated_at"]
