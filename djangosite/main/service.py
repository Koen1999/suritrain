import copy
import datetime
import json
import logging
import math
import os
import random
import shutil
import subprocess
import time
import urllib
import urllib.request
import warnings

import deepmerge
import psutil
import yaml
from django.db import close_old_connections, transaction

from .models import Pcap, Result, Submission, Test
from .utils import format_rule

PCAP_HOST_URL = "https://ctf.anonymized.net"
N_WORKERS = int(os.environ.get("N_WORKERS", math.floor(os.cpu_count() * 0.85)))
WORKER_NICENESS = 5

BACKOFF_FACTOR = 1.5
MAX_SLEEPTIME = 60

STORE_YAML = True
STORE_LOG = True
STORE_EVE = True
STORE_FAST = True
MAX_ALERTS = 100
SURICATA_TIMEOUT = 30

__SURICATA_YAML: dict = yaml.load(
    """\
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
    AIM_SERVERS: $EXTERNAL_NET
    DC_SERVERS: $HOME_NET
    DNP3_CLIENT: $HOME_NET
    DNP3_SERVER: $HOME_NET
    DNS_SERVERS: $HOME_NET
    ENIP_CLIENT: $HOME_NET
    ENIP_SERVER: $HOME_NET
    HTTP_SERVERS: $HOME_NET
    MODBUS_CLIENT: $HOME_NET
    MODBUS_SERVER: $HOME_NET
    SMTP_SERVERS: $HOME_NET
    SQL_SERVERS: $HOME_NET
    TELNET_SERVERS: $HOME_NET
stats:
  enabled: no
outputs:
  - fast:
      enabled: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      metadata: true
      types:
        - alert:
            payload: yes
            payload-buffer-size: 1 KB
            payload-printable: yes
            payload-length: yes
            # packet: yes
            metadata:
              app-layer: true
              flow: true
              rule:
                metadata: true
                raw: true
                reference: true
            http-body: yes
            http-body-printable: yes
            # websocket-payload: yes
            # websocket-payload-printable: yes
            tagged-packets: yes
            verdict: yes
        # - anomaly:
        #     enabled: yes
        #     types:
        #       decode: yes
        #       stream: yes
        #       applayer: yes
        #     packethdr: yes
        # - http:
        #     extended: yes
        #     dump-all-headers: both
        # - dns:
        #     version: 2
        #     enabled: yes
        #     requests: yes
        #     responses: yes
        #     formats: [detailed, grouped]
        #     types: [a, aaaa, cname, mx, ns, ptr, txt]
        # - http2
        # - tls:
        #     extended: yes
        #     session-resumption: yes
        #     ja4: on
        #     custom: [subject, issuer, session_resumed, serial, fingerprint, sni, version, not_before, not_after, certificate, chain, ja3, ja3s, ja4]
vlan:
  use-for-tracking: false
defrag:
  memcap: 32mb
  memcap-policy: ignore
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 3600
reassembly:
  memcap: 512 MB
  depth: 64 MB
  check-overlap-different-data: true
flow-timeouts:
  default:
    new: 3600
    established: 3600
    closed: 0
    bypassed: 3600
    emergency-new: 3600
    emergency-established: 3600
    emergency-closed: 0
    emergency-bypassed: 3600
  icmp:
    new: 3600
    established: 3600
    bypassed: 3600
    emergency-new: 3600
    emergency-established: 3600
    emergency-bypassed: 3600
  tcp:
    new: 3600
    established: 3600
    closed: 0
    bypassed: 3600
    emergency-new: 3600
    emergency-established: 3600
    emergency-closed: 0
    emergency-bypassed: 3600
  udp:
    new: 3600
    established: 3600
    bypassed: 3600
    emergency-new: 3600
    emergency-established: 3600
    emergency-bypassed: 3600
stream:
  midstream: true
  async_oneside: true
  inline: yes
  drop-invalid: false
  checksum-validation: yes
app-layer:
  protocols:
    http:
      enabled: yes
      byterange:
        memcap: 1000mb
        timeout: 3600
      default-config:
        personality: IDS
      libhtp:
        default-config:
           personality: IDS
           request-body-limit: 64mb
           response-body-limit: 64mb
           request-body-minimal-inspect-size: 64mb
           request-body-inspect-window: 64mb
           response-body-minimal-inspect-size: 64mb
           response-body-inspect-window: 64mb
           response-body-decompress-layer-limit: 8
           http-body-inline: auto
           swf-decompression:
             enabled: yes
             type: both
             compress-depth: 64mb
             decompress-depth: 64mb
           randomize-inspection-sizes: no
           double-decode-path: yes
           double-decode-query: yes
           lzma-enabled: true
           lzma-memlimit: 64mb
           compression-bomb-limit: 64mb
           decompression-time-limit: 100000
           max-tx: 51200
    dns:
      enabled: yes
    http2:
      enabled: yes
      max-streams: 4096
      max-table-size: 65536
      max-reassembly-size: 102400
    tls:
      enabled: yes
      detection-ports:
        dp: 443
      ja3-fingerprints: auto
      ja4-fingerprints: auto
      encryption-handling: full
pcap-file:
  checksum-checks: no
""",
    yaml.Loader,
)

_merger = deepmerge.Merger(
    [
        (list, ["override"]),
        (dict, ["merge"]),
    ],
    ["override"],
    ["override"],
)

default_suricata_yaml: dict = yaml.load(
    open("/etc/suricata/suricata.yaml", "r"), yaml.Loader
)
suricata_yaml = _merger.merge(default_suricata_yaml, copy.deepcopy(__SURICATA_YAML))

logger = logging.getLogger(__name__)


class TestService:
    @staticmethod
    def _set_low_priority():
        os.nice(WORKER_NICENESS)

    @staticmethod
    def start():
        # Preload pcaps for tests
        for pcap in Pcap.objects.all():
            TestService.ensure_pcap_availability(pcap)

        logger.info("PCAPs have been preloaded for testing.")

        services = [
            subprocess.Popen(
                ["/venv/bin/python3", "manage.py", "starttestserviceworker"],
                preexec_fn=TestService._set_low_priority,
            )
            for _ in range(N_WORKERS)
        ]

        for _ in range(60):
            time.sleep(1)

            for service in services:
                ret = service.poll()
                if ret is not None:
                    if service.stdout is not None:
                        warnings.warn(RuntimeWarning(service.stdout.read().decode()))
                    if service.stderr is not None:
                        warnings.warn(RuntimeWarning(service.stderr.read().decode()))
                    raise RuntimeError(
                        "TestService Worker has exited with code {}".format(ret)
                    )

    @staticmethod
    def stop():
        for proc in psutil.process_iter():
            # check whether the process name matches
            if (
                " ".join(proc.cmdline())
                == "/venv/bin/python3 manage.py starttestserviceworker"
            ):
                proc.kill()
                logger.info("Killed existing TestService worker.")

    @staticmethod
    def ensure_pcap_availability(pcap: Pcap):
        if os.path.exists(pcap.pcap.path):
            return

        if not os.path.exists(os.path.dirname(pcap.pcap.path)):
            os.makedirs(os.path.dirname(pcap.pcap.path))

        logger.info(
            "Downloading PCAP %s for running tests from %s", pcap.title, pcap.pcap.url
        )

        try:
            urllib.request.urlretrieve(
                "/".join([PCAP_HOST_URL, pcap.pcap.url]),
                pcap.pcap.path,
            )
        except:
            raise RuntimeError(
                "Failed to download PCAP for running tests: %s", pcap.title
            )

    @staticmethod
    def start_loop():
        sleeptime = random.uniform(0, MAX_SLEEPTIME / 10)
        while True:
            # Close old connections to prevent OperationalError
            close_old_connections()
            cycle_start_time = time.time()
            # Get all testable submissions
            submissions = (
                Submission.objects.filter(valid=True, check_only=False)
                .order_by("submitted_at")
                .all()
            )

            # Select untested submission and mark as tested atomically
            untested_submissions = (
                submissions.filter(tested=False).order_by("submitted_at").all()
            )

            if len(untested_submissions) == 0:
                # If no submission is found, sleep and backoff
                time.sleep(sleeptime)
                sleeptime = min(MAX_SLEEPTIME, sleeptime * BACKOFF_FACTOR)
                continue

            # If a submission is found decrease backoff time
            sleeptime = sleeptime / BACKOFF_FACTOR

            # Determine the submission with the highest priority
            # - If a submission has been waiting the longest it will be tested
            # - Unless there is a newer submission from the same user/scenario, then that one will be tested
            # - Unless a more recent submission for that user/scenario has already been tested
            i = 0
            submission = untested_submissions[0]

            # Check if the most recent submission for the same user/scenario is not yet tested by another worker
            if submission is None:
                continue

            # Check if the current submission is the most recent untested submission for the user/scenario
            while (
                submissions.filter(
                    user=submission.user,
                    scenario=submission.scenario,
                    submitted_at__gt=submission.submitted_at,
                ).count()
                > 0
            ):
                # If a newer untested submission for the same user/scenario exists and no newer submissions for the same user/scenario have been tested yet, select the most recent one for testing
                if (
                    submissions.filter(
                        user=submission.user,
                        scenario=submission.scenario,
                        submitted_at__gt=submission.submitted_at,
                        tested=False,
                    ).count()
                    > 0
                ) and (
                    submissions.filter(
                        user=submission.user,
                        scenario=submission.scenario,
                        submitted_at__gt=submission.submitted_at,
                        tested=True,
                    ).count()
                    == 0
                ):
                    submission = submissions.filter(
                        user=submission.user,
                        scenario=submission.scenario,
                        submitted_at__gt=submission.submitted_at,
                        tested=False,
                    ).last()

                    origin = "RECENT"

                    break

                i += 1

                # If all users have had their most recent submission for each scenario tested, start clearing the backlog
                if i >= len(untested_submissions):
                    submission = random.choice(untested_submissions)
                    origin = "BACKLOG"
                    break

                # Select the next submission
                submission = untested_submissions[i]

            if i == 0:
                origin = "OLDEST"

            with transaction.atomic():
                # Check if the most recent submission for the same user/scenario is not yet tested by another worker
                if submission is None or submission.pk is None:
                    continue

                # Select for update
                submission = Submission.objects.select_for_update().get(
                    pk=submission.pk
                )

                # Check if the most recent submission for the same user/scenario is not yet tested by another worker
                if submission is None or submission.tested is None:
                    continue

                submission.refresh_from_db()
                if submission.tested:
                    continue

                # Mark selected submission as tested and decrease backoff time
                submission.tested = True
                submission.save()

            logger.debug("Submission selection strategy: %s", origin)

            logger.debug(
                "Selecting submission to test took %s seconds",
                time.time() - cycle_start_time,
            )

            logger.info(
                "Testing submission from user %s for scenario %s with id %s",
                submission.user.username,
                submission.scenario.title,
                submission.pk,
            )

            # Conduct tests
            for test in submission.scenario.tests:
                TestService.test_submission(submission, test)

            logger.debug(
                "Selecting submission and running tests to test took %s seconds",
                time.time() - cycle_start_time,
            )

    @staticmethod
    def test_submission(submission: Submission, test: Test):
        # Close old connections to prevent OperationalError
        close_old_connections()

        id = str(
            hash(
                "validate_rule"
                + str(submission)
                + str(test)
                + str(datetime.datetime.now())
            )
        )

        filename = id + ".rules"
        path = os.path.join("/tmp", filename)
        conf_path = path.replace(".rules", ".yaml")

        if test.pcap.yaml is not None and test.pcap.yaml != "":
            test_suricata_yaml = _merger.merge(
                copy.deepcopy(suricata_yaml), yaml.load(test.pcap.yaml, yaml.Loader)
            )
        else:
            test_suricata_yaml = suricata_yaml

        formatted_rule = format_rule(submission.rule)
        if formatted_rule is None:
            formatted_rule = submission.rule

        with open(path, "w") as fh:
            fh.writelines(formatted_rule)

        with open(conf_path, "w") as fh:
            fh.writelines(
                [
                    "%YAML 1.1\n",
                    "---\n",
                    "\n",
                ]
            )

            fh.write(yaml.dump(test_suricata_yaml))

        log_path = path + ".out"
        if os.path.exists(log_path):
            shutil.rmtree(log_path)
        os.mkdir(log_path)

        try:
            result = subprocess.run(
                [
                    "suricata",
                    "-v",
                    "-S",
                    path,
                    "-c",
                    conf_path,
                    "-l",
                    log_path,
                    "-r",
                    test.pcap.pcap.path,
                ],
                capture_output=True,
                text=True,
                timeout=SURICATA_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "Failed to run Suricata due to timeout for submission by user %s with submission ID %s and test %s for scenario %s",
                submission.user.username,
                submission.pk,
                test.title,
                submission.scenario.title,
            )

        with open(os.path.join(log_path, "suricata.log"), "r") as fh:
            log = fh.read()

        if os.path.exists(os.path.join(log_path, "fast.log")):
            with open(os.path.join(log_path, "fast.log"), "r") as fh:
                n_alerts = len(fh.readlines())
        else:
            n_alerts = 0
            warnings.warn(RuntimeWarning(log))

        raised_alert = False
        raised_alerts = False
        if os.path.exists(os.path.join(log_path, "eve.json")):
            with open(os.path.join(log_path, "eve.json"), "r") as fh:
                for line in fh.readlines():
                    d = json.loads(line)
                    if d["event_type"] == "alert":
                        if raised_alert:
                            raised_alerts = True
                            break
                        raised_alert = True
            if n_alerts > MAX_ALERTS:
                eve = "Too many alerts to store"
            else:
                with open(os.path.join(log_path, "eve.json"), "r") as fh:
                    eve = fh.read()
        else:
            eve = "Failed to read eve"
            warnings.warn(RuntimeWarning(log))

        if os.path.exists(os.path.join(log_path, "fast.log")):
            if n_alerts > MAX_ALERTS:
                fast = "Too many alerts to store"
            else:
                with open(os.path.join(log_path, "fast.log"), "r") as fh:
                    fast = fh.read()
        else:
            fast = "Failed to read fast"
            warnings.warn(RuntimeWarning(log))

        os.remove(path)
        os.remove(conf_path)
        shutil.rmtree(log_path)

        if test.expected:
            if not raised_alert:
                status = "Failure"
                score = 0
            elif raised_alerts:
                status = "Warning"
                score = 1
            else:
                status = "Success"
                score = 2
        else:
            if raised_alert:
                status = "Failure"
                score = -1
            else:
                status = "Success"
                score = 0

        result_yaml = yaml.dump(test_suricata_yaml)

        if not STORE_YAML:
            result_yaml = ""

        if not STORE_LOG:
            log = ""

        if not STORE_EVE:
            eve = ""

        if not STORE_FAST:
            fast = ""

        # Close old connections to prevent OperationalError
        # Saving result may still fail due to too many alerts or timeout?

        try:
            close_old_connections()
            result = Result(
                submission=submission,
                test=test,
                status=status,
                score=score,
                yaml=result_yaml,
                log=log,
                eve=eve,
                fast=fast,
                n_alerts=n_alerts,
            )
            result.save()
        except:
            logger.error(
                "Failed to save result for submission by user %s with submission ID %s and test %s for scenario %s",
                submission.user.username,
                submission.pk,
                test.title,
                submission.scenario.title,
            )
            logger.info(result)
