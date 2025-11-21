import logging
import re

import numpy
import pandas
from pandas import DataFrame

logger = logging.getLogger(__name__)


def grade_intake_pilot(df_in: DataFrame) -> DataFrame:
    df_out_rows = []

    for _, row in df_in.iterrows():
        isced = row[
            "What is the highest level of education that you have completed?\n\nWhen in doubt, please refer to:\nhttps://en.wikipedia.org/wiki/International_Standard_Classification_of_Education\nor\nhttps://www.ocwinci"
        ]
        if isced == "":
            isced = numpy.nan
        else:
            isced = int(re.match(r".*ISCED (\d).*", isced).group(1))

        self_graded_networking = row[
            "What is your level of expertise regarding network protocols (i.e., UDP, TCP, DNS, HTTP, TLS, etc.)?\n"
        ]
        if self_graded_networking == "I have never heard of these.":
            self_graded_networking = 1
        elif (
            self_graded_networking
            == "I have heard of them but do not know how they differ."
        ):
            self_graded_networking = 2
        elif (
            self_graded_networking
            == "I know the differences between these protocols but do not know how they work."
        ):
            self_graded_networking = 3
        elif (
            self_graded_networking
            == "I know how (most of) these protocols work but have never implemented any application using them."
        ):
            self_graded_networking = 4
        elif (
            self_graded_networking
            == "I have implemented applications using at least one of these protocols."
        ):
            self_graded_networking = 5
        else:
            logger.warning("Unknown level: %s", self_graded_networking)

        self_graded_computer_security = row[
            "What is your level of expertise regarding offensive computer security?"
        ]
        if self_graded_computer_security == "I have never heard of this concept.":
            self_graded_computer_security = 1
        elif (
            self_graded_computer_security
            == "I have heard of of offensive computer security but are not familiar with specific techniques."
        ):
            self_graded_computer_security = 2
        elif (
            self_graded_computer_security
            == "I am familiar with offensive computer security and am familiar with the basic concepts of techniques such as Scanning, XSS, and Persistence."
        ):
            self_graded_computer_security = 3
        elif (
            self_graded_computer_security
            == "I am familiar with offensive computer security and have previously applied at least one offensive computer security technique."
        ):
            self_graded_computer_security = 4
        elif (
            self_graded_computer_security
            == "I am familiar with offensive computer security and have previously applied several different offensive computer security techniques."
        ):
            self_graded_computer_security = 5
        else:
            logger.warning("Unknown level: %s", self_graded_computer_security)

        self_graded_wireshark = row[
            "What is your level of expertise regarding Wireshark?\n"
        ]
        if self_graded_wireshark == "I have never heard of Wireshark.":
            self_graded_wireshark = 1
        elif self_graded_wireshark == "I know what Wireshark is, but never used it.":
            self_graded_wireshark = 2
        elif (
            self_graded_wireshark
            == "I have previously used Wireshark to inspect PCAPs but am not familiar with features such as network statistics or decoding of data."
        ):
            self_graded_wireshark = 3
        elif (
            self_graded_wireshark
            == "I have used Wireshark including the features mentioned above."
        ):
            self_graded_wireshark = 4
        elif (
            self_graded_wireshark
            == "I regularly use Wireshark including the features mentioned above. "
        ):
            self_graded_wireshark = 5
        else:
            logger.warning("Unknown level: %s", self_graded_wireshark)

        self_graded_intrusion_detection = row[
            "What is your level of expertise regarding intrusion detection?"
        ]
        if (
            self_graded_intrusion_detection
            == "I do not know what intrusion detection is."
        ):
            self_graded_intrusion_detection = 1
        elif (
            self_graded_intrusion_detection
            == "I know what intrusion detection is, but do not know any specific methods."
        ):
            self_graded_intrusion_detection = 2
        elif (
            self_graded_intrusion_detection
            == "I know about a specific intrusion detection method, but do not know how any specific intrusion detection method works."
        ):
            self_graded_intrusion_detection = 3
        elif (
            self_graded_intrusion_detection
            == "I know how a specific intrusion detection method may work."
        ):
            self_graded_intrusion_detection = 4
        elif (
            self_graded_intrusion_detection
            == "I have previously implemented a specific intrusion detection method."
        ):
            self_graded_intrusion_detection = 5
        else:
            logger.warning("Unknown level: %s", self_graded_intrusion_detection)

        self_graded_suricata = row[
            "What is your level of expertise regarding Suricata?\n"
        ]
        if self_graded_suricata == "I have never heard of Suricata.":
            self_graded_suricata = 1
        elif self_graded_suricata == "I know what Suricata is, but never used it.":
            self_graded_suricata = 2
        elif (
            self_graded_suricata
            == "I have previously used Suricata to analyze PCAPs, but have never written any rule for it."
        ):
            self_graded_suricata = 3
        elif self_graded_suricata == "I have previously written Suricata rules.":
            self_graded_suricata = 4
        elif self_graded_suricata == "I regularly write Suricata rules.":
            self_graded_suricata = 5
        else:
            logger.warning("Unknown level: %s", self_graded_suricata)

        self_graded_english = row[
            "What is your level of expertise regarding the English language?\n"
        ]
        if (
            self_graded_english
            == "I do not speak English, can you repeat the question?"
        ):
            self_graded_english = 1
        elif (
            self_graded_english
            == "I occasionally speak and write English during basic conversations."
        ):
            self_graded_english = 2
        elif (
            self_graded_english
            == "I regularly speak and write English including professionally (study or work) but do not understand complicated expert texts (i.e. research papers, or legal texts)"
        ):
            self_graded_english = 3
        elif (
            self_graded_english
            == "I regularly speak and write English including professionally (study or work) and can understand complicated expert texts (i.e. research papers, or legal texts), but do not frequently communicate expert topics in English."
        ):
            self_graded_english = 4
        elif self_graded_english.startswith(
            "I regularly speak and write English and communicate expert"
        ):
            self_graded_english = 5
        else:
            logger.warning("Unknown level: %s", self_graded_english)

        self_graded_ctf = row[
            "What is your level of expertise regarding Capture the Flags (or similar activities)?"
        ]
        if self_graded_ctf == "I have never heard of a Capture the Flag.":
            self_graded_ctf = 1
        elif (
            self_graded_ctf
            == "I know what a Capture the Flag is but have never participated in one."
        ):
            self_graded_ctf = 2
        elif self_graded_ctf == "I have previously participated in a Capture the Flag.":
            self_graded_ctf = 3
        elif self_graded_ctf == "I have participated in multiple Capture the Flags.":
            self_graded_ctf = 4
        elif self_graded_ctf == "I have previously organized a Capture the Flag.":
            self_graded_ctf = 5
        else:
            logger.warning("Unknown level: %s", self_graded_ctf)

        quiz_networking_internet_model = int(
            row[
                "On which layer of the Internet model does TLS operate to provide security for communications over port 443?"
            ]
            == "Transport layer"
        )

        quiz_networking_tcp = int(
            row[
                "How does the TCP protocol ensure that the packets are delivered in the correct order?"
            ]
            == "Through the use of sequence and acknowledgment numbers."
        )

        quiz_networking_tls_answer = (
            row[
                "During the initiation of a TLS session, what types of information can be exchanged?"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "During the initiation of a TLS session, what types of information can be exchanged?"
                ]
            )
            else []
        )
        quiz_networking_tls_correct = [
            "Server and client Hello messages",
            "Encrypted handshake messages",
            "Certificate",
        ]
        quiz_networking_tls_incorrect = ["Plain-text HTTP requests"]
        quiz_networking_tls = 0
        for answer in quiz_networking_tls_correct:
            if answer in quiz_networking_tls_answer:
                quiz_networking_tls += 1
        for answer in quiz_networking_tls_incorrect:
            if answer in quiz_networking_tls_answer:
                quiz_networking_tls -= 1
        for answer in quiz_networking_tls_answer:
            if (
                answer not in quiz_networking_tls_correct
                and answer not in quiz_networking_tls_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_networking_tls = max(quiz_networking_tls, 0)

        quiz_networking_total = (
            quiz_networking_internet_model + quiz_networking_tcp + quiz_networking_tls
        )

        quiz_ocs_scanning_answer = (
            row[
                "Which of the following statements regarding network scanning are true?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding network scanning are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_scanning_correct = [
            "Network scanning may be used to inspect application layer features such as used software and versions.",
        ]
        quiz_ocs_scanning_incorrect = [
            "Lack of response (SYN,ACK) to a TCP SYN implies a port is filtered.",
            "Lack of response (SYN,ACK) to a TCP SYN implies a port is closed.",
            "Lack of response to a UDP packet sent to a port implies that port is closed or filtered.",
            "If you want to know which ports may be open on a public-facing IP address, you must scan it.",
            "If a vulnerability scanner detects a vulnerability, the scanned device has an exploitable vulnerability.",
        ]
        quiz_ocs_scanning = 0
        for answer in quiz_ocs_scanning_correct:
            if answer in quiz_ocs_scanning_answer:
                quiz_ocs_scanning += 1
        for answer in quiz_ocs_scanning_incorrect:
            if answer in quiz_ocs_scanning_answer:
                quiz_ocs_scanning -= 1
        for answer in quiz_ocs_scanning_answer:
            if (
                answer not in quiz_ocs_scanning_correct
                and answer not in quiz_ocs_scanning_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_scanning = max(quiz_ocs_scanning, 0)

        quiz_ocs_xss_answer = (
            row[
                "Which of the following statements regarding Cross-Site Scripting (XSS) are true?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding Cross-Site Scripting (XSS) are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_xss_correct = [
            "XSS attacks may be prevented through input sanitization.",
            "XSS attacks can be used to steal credentials.",
            "During a successful XSS attack the attacker may execute malicious code within the web browsers of other users visiting a website.",
        ]
        quiz_ocs_xss_incorrect = [
            "During a successful XSS attack malicious code is executed on a server distributing content.",
            "XSS attacks always require vulnerable web browsers to be successful.",
            "XSS attacks are considered to be a subset of SQL injection attacks.",
        ]
        quiz_ocs_xss = 0
        for answer in quiz_ocs_xss_correct:
            if answer in quiz_ocs_xss_answer:
                quiz_ocs_xss += 1
        for answer in quiz_ocs_xss_incorrect:
            if answer in quiz_ocs_xss_answer:
                quiz_ocs_xss -= 1
        for answer in quiz_ocs_xss_answer:
            if (
                answer not in quiz_ocs_xss_correct
                and answer not in quiz_ocs_xss_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_xss = max(quiz_ocs_xss, 0)

        quiz_ocs_persistence_answer = (
            row["Which of the following statements regarding Persistence are true?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding Persistence are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_persistence_correct = [
            "Metasploit is a tool that can be used to obtain persistence.",
        ]
        quiz_ocs_persistence_incorrect = [
            "Persistence always implies malware will remain present after reinstallation of the operating system following a malware infection.",
            "Persistence always implies malware will be executed at some point during the boot process of the infected machine.",
            "In order to obtain persistence, malware must add an executable file to the startup folder on Windows.",
            "Persistence must be acquired in order for malware to accomplish its goal.",
        ]
        quiz_ocs_persistence = 0
        for answer in quiz_ocs_persistence_correct:
            if answer in quiz_ocs_persistence_answer:
                quiz_ocs_persistence += 1
        for answer in quiz_ocs_persistence_incorrect:
            if answer in quiz_ocs_persistence_answer:
                quiz_ocs_persistence -= 1
        for answer in quiz_ocs_persistence_answer:
            if (
                answer not in quiz_ocs_persistence_correct
                and answer not in quiz_ocs_persistence_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_persistence = max(quiz_ocs_persistence, 0)

        quiz_ocs_total = quiz_ocs_scanning + quiz_ocs_xss + quiz_ocs_persistence

        quiz_wireshark_features_answer = (
            row["What is/are not (a) feature offered by Wireshark?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["What is/are not (a) feature offered by Wireshark?\n"]
            )
            else []
        )
        quiz_wireshark_features_correct = [
            "Blocking network traffic",
            "Decrypting all encrypted network traffic",
        ]
        quiz_wireshark_features_incorrect = [
            "Filtering of packets",
            "Decoding of transmitted data",
            "Producing network I/O statistics",
        ]
        quiz_wireshark_features = 0
        for answer in quiz_wireshark_features_correct:
            if answer in quiz_wireshark_features_answer:
                quiz_wireshark_features += 1
        for answer in quiz_wireshark_features_incorrect:
            if answer in quiz_wireshark_features_answer:
                quiz_wireshark_features -= 1
        for answer in quiz_wireshark_features_answer:
            if (
                answer not in quiz_wireshark_features_correct
                and answer not in quiz_wireshark_features_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_wireshark_features = max(quiz_wireshark_features, 0)

        quiz_wireshark_filter = int(
            row[
                "What is the purpose of the ip.addr==192.168.178.1 filter in Wireshark?\n"
            ]
            == "To only show network packets originating from or sent to 192.168.178.1 "
        )

        quiz_wireshark_stream_answer = (
            row[
                "What can be valid (a) goal(s) of following an HTTP stream in Wireshark?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "What can be valid (a) goal(s) of following an HTTP stream in Wireshark?\n"
                ]
            )
            else []
        )
        quiz_wireshark_stream_correct = [
            "Inspecting response headers",
            "Inspecting the raw bytes transmitted as part of the HTTP request headers",
            "Inspecting decoded data transmitted over HTTP",
            "Inspecting data transmitted as part of the TCP stream of which the HTTP stream is part",  # Drop, it's too ambiguous
        ]
        quiz_wireshark_stream_incorrect = []
        quiz_wireshark_stream = 0
        for answer in quiz_wireshark_stream_correct:
            if answer in quiz_wireshark_stream_answer:
                quiz_wireshark_stream += 1
        for answer in quiz_wireshark_stream_incorrect:
            if answer in quiz_wireshark_stream_answer:
                quiz_wireshark_stream -= 1
        for answer in quiz_wireshark_stream_answer:
            if (
                answer not in quiz_wireshark_stream_correct
                and answer not in quiz_wireshark_stream_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_wireshark_stream = max(quiz_wireshark_stream, 0)

        quiz_wireshark_total = (
            quiz_wireshark_features + quiz_wireshark_filter + quiz_wireshark_stream
        )

        quiz_ids_definition = int(
            row[
                "Which description best describes the difference between signature-based and anomaly-based intrusion detection methods?\n"
            ]
            == "Signature-based intrusion detection methods primarily rely on knowledge of malicious behaviors whereas anomaly-based intrusion detection methods primarily rely on knowledge of benign behaviors"
        )

        quiz_ids_issues_answer = (
            row["What is/are (a) major issue(s) in intrusion detection?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["What is/are (a) major issue(s) in intrusion detection?\n"]
            )
            else []
        )
        quiz_ids_issues_correct = [
            "Lack of suitable data for training/engineering detection methods",
            "Large imbalance between number of benign and malicious connections",
            "Large quantities of data to be processed",
        ]
        quiz_ids_issues_incorrect = []
        quiz_ids_issues = 0
        for answer in quiz_ids_issues_correct:
            if answer in quiz_ids_issues_answer:
                quiz_ids_issues += 1
        for answer in quiz_ids_issues_incorrect:
            if answer in quiz_ids_issues_answer:
                quiz_ids_issues -= 1
        for answer in quiz_ids_issues_answer:
            if (
                answer not in quiz_ids_issues_correct
                and answer not in quiz_ids_issues_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ids_issues = max(quiz_ids_issues, 0)

        quiz_ids_suricata_answer = (
            row["Suricata can function as a:\n"].strip(";").split(";")
            if not pandas.isna(row["Suricata can function as a:\n"])
            else []
        )
        quiz_ids_suricata_correct = [
            "Signature-based intrusion detection system",
            "Rule-based intrusion detection system",
            "Network-based intrusion detection system",
        ]
        quiz_ids_suricata_incorrect = []
        quiz_ids_suricata = 0
        for answer in quiz_ids_suricata_correct:
            if answer in quiz_ids_suricata_answer:
                quiz_ids_suricata += 1
        for answer in quiz_ids_suricata_incorrect:
            if answer in quiz_ids_suricata_answer:
                quiz_ids_suricata -= 1
        for answer in quiz_ids_suricata_answer:
            if (
                answer not in quiz_ids_suricata_correct
                and answer not in quiz_ids_suricata_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ids_suricata = max(quiz_ids_suricata, 0)

        quiz_ids_total = quiz_ids_definition + quiz_ids_issues + quiz_ids_suricata

        quiz_suricata_mandatory_answer = (
            row["Which of the following fields are mandatory for Suricata rules\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["Which of the following fields are mandatory for Suricata rules\n"]
            )
            else []
        )
        quiz_suricata_mandatory_correct = ["msg", "sid"]
        quiz_suricata_mandatory_incorrect = ["rev", "classtype", "content"]
        quiz_suricata_mandatory = 0
        for answer in quiz_suricata_mandatory_correct:
            if answer in quiz_suricata_mandatory_answer:
                quiz_suricata_mandatory += 1
        for answer in quiz_suricata_mandatory_incorrect:
            if answer in quiz_suricata_mandatory_answer:
                quiz_suricata_mandatory -= 1
        for answer in quiz_suricata_mandatory_answer:
            if (
                answer not in quiz_suricata_mandatory_correct
                and answer not in quiz_suricata_mandatory_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_suricata_mandatory = max(quiz_suricata_mandatory, 0)

        quiz_suricata_functionality_answer = (
            row["What are standard functionalities offered by Suricata?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["What are standard functionalities offered by Suricata?\n"]
            )
            else []
        )
        quiz_suricata_functionality_correct = [
            "Matching bytes at specific locations",
            "Stateful detection across different flows in which the same IP address is involved",
            "Matching specific traffic directions",
            "Decoding of certain HTTP buffers",
            "Stateful detection within the same flow",
            "Matching using regular expressions",
        ]
        quiz_suricata_functionality_incorrect = ["Matching using a remote API"]
        quiz_suricata_functionality = 0
        for answer in quiz_suricata_functionality_correct:
            if answer in quiz_suricata_functionality_answer:
                quiz_suricata_functionality += 1
        for answer in quiz_suricata_functionality_incorrect:
            if answer in quiz_suricata_functionality_answer:
                quiz_suricata_functionality -= 1
        for answer in quiz_suricata_functionality_answer:
            if (
                answer not in quiz_suricata_functionality_correct
                and answer not in quiz_suricata_functionality_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_suricata_functionality = max(quiz_suricata_functionality, 0)

        quiz_suricata_match_answer = (
            row[
                """Which of the following buffers would be matched by the following sequence of Suricata options: \n\ncontent:"FOO"; content:"bar"; depth:5;\n"""
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    """Which of the following buffers would be matched by the following sequence of Suricata options: \n\ncontent:"FOO"; content:"bar"; depth:5;\n"""
                ]
            )
            else []
        )
        quiz_suricata_match_correct = ["barFOO"]
        quiz_suricata_match_incorrect = ["FOObar", "foobar", "barfoo"]
        quiz_suricata_match = 0
        for answer in quiz_suricata_match_correct:
            if answer in quiz_suricata_match_answer:
                quiz_suricata_match += 1
        for answer in quiz_suricata_match_incorrect:
            if answer in quiz_suricata_match_answer:
                quiz_suricata_match -= 1
        for answer in quiz_suricata_match_answer:
            if (
                answer not in quiz_suricata_match_correct
                and answer not in quiz_suricata_match_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_suricata_match = max(quiz_suricata_match, 0)

        quiz_suricata_total = (
            quiz_suricata_mandatory + quiz_suricata_functionality + quiz_suricata_match
        )

        quiz_english_docs_answer = (
            x + ")" if not x[-1] == ")" else x
            for x in (
                row[
                    "Read the following Suricata documentation and select the factually correct statements one can derive from the given sentence.\n\n\n\nModifiers\n\nstartswith\nThe startswith keyword is similar to depth. It ta"
                ]
                .strip(";")
                .split(");")
                if not pandas.isna(
                    row[
                        "Read the following Suricata documentation and select the factually correct statements one can derive from the given sentence.\n\n\n\nModifiers\n\nstartswith\nThe startswith keyword is similar to depth. It ta"
                    ]
                )
                else []
            )
        )
        quiz_english_docs_correct = [
            """alert dns any any -> any 53 (msg:"DNS Request to google.com"; dns.query; dotprefix; content:".google.com"; startswith; sid:1;)"""
        ]
        quiz_english_docs_incorrect = [
            """alert dns any any -> any 53 (msg:"DNS Request to google.com"; dns.query; dotprefix; content:"google.com"; startswith; sid:1;)"""
        ]
        quiz_english_docs = 0
        for answer in quiz_english_docs_correct:
            if answer in quiz_english_docs_answer:
                quiz_english_docs += 1
        for answer in quiz_english_docs_incorrect:
            if answer in quiz_english_docs_answer:
                quiz_english_docs -= 1
        for answer in quiz_english_docs_answer:
            if (
                answer not in quiz_english_docs_correct
                and answer not in quiz_english_docs_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_english_docs = max(quiz_english_docs, 0)

        quiz_english_abe_answer = (
            x + ")" if not x[-1] == ")" else x
            for x in (
                row[
                    "Read the following sentence and select the factually correct statements one can derive from the given sentence.\n\nAlice should not have sent flowers to Bob whereas Eve should have since Bob favors the "
                ]
                .strip(";")
                .split(");")
                if not pandas.isna(
                    row[
                        "Read the following sentence and select the factually correct statements one can derive from the given sentence.\n\nAlice should not have sent flowers to Bob whereas Eve should have since Bob favors the "
                    ]
                )
                else []
            )
        )
        quiz_english_abe_correct = ["Alice sent flowers to Bob"]
        quiz_english_abe_incorrect = ["Bob received flowers;", "I do not know."]
        quiz_english_abe = 0
        for answer in quiz_english_abe_correct:
            if answer in quiz_english_abe_answer:
                quiz_english_abe += 1
        for answer in quiz_english_abe_incorrect:
            if answer in quiz_english_abe_answer:
                quiz_english_abe -= 1
        for answer in quiz_english_abe_answer:
            if (
                answer not in quiz_english_abe_correct
                and answer not in quiz_english_abe_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_english_abe = max(quiz_english_abe, 0)

        quiz_english_total = quiz_english_docs + quiz_english_abe

        quiz_total = (
            quiz_networking_total
            + quiz_ocs_total
            + quiz_wireshark_total
            + quiz_ids_total
            + quiz_suricata_total
            + quiz_english_total
        )

        df_out_rows.append(
            {
                "username": row[
                    "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                ],
                "Consent Age Reached": row[
                    "Are you 16 years or older?\n\nNote: If you are younger than 16 years, you are not allowed to consent to participation in the research due to the legal age of consent in the Netherlands (but you can stil"
                ]
                == "Yes",
                "Informed Consent Granted": row[
                    'By selecting "yes" below, I confirm:\n\n1.  I have enough information about the research project from the separate  information sheet. I have read it and I had the chance to ask questions,  which have b'
                ]
                == "Yes",
                "Gender": row["What is your gender?\n"],
                "ISCED": isced,
                "Control Question Correct": row[
                    "This is a control question to see if you are reading the questions and answering them consciously. Please select the third option below.\n"
                ]
                == "SSH",
                "Intake Remarks": row.fillna("")[
                    "Do you have any feedback or remarks on the survey?\n"
                ],
                "Other Relevant Experiences": row.fillna("")[
                    "Do you have any other relevant experiences (such as a job in this area or high expertise in another area you deem relevant) that may be relevant for the research? If so, describe the topic and the rel"
                ],
                "Self Graded Networking": self_graded_networking,
                "Self Graded Computer Security": self_graded_computer_security,
                "Self Graded Wireshark": self_graded_wireshark,
                "Self Graded Intrusion Detection": self_graded_intrusion_detection,
                "Self Graded Suricata": self_graded_suricata,
                "Self Graded English": self_graded_english,
                "Self Graded CTF": self_graded_ctf,
                "Quiz Networking Internet Model": quiz_networking_internet_model,
                "Quiz Networking TCP": quiz_networking_tcp,
                "Quiz Networking TLS": quiz_networking_tls,
                "Quiz Networking Scanning": quiz_ocs_scanning,
                "Quiz Networking Total": quiz_networking_total,
                "Quiz OCS Scanning": quiz_ocs_scanning,
                "Quiz OCS XSS": quiz_ocs_xss,
                "Quiz OCS Persistence": quiz_ocs_persistence,
                "Quiz OCS Total": quiz_ocs_total,
                "Quiz Wireshark Features": quiz_wireshark_features,
                "Quiz Wireshark Filter": quiz_wireshark_filter,
                "Quiz Wireshark Stream": quiz_wireshark_stream,
                "Quiz Wireshark Total": quiz_wireshark_total,
                "Quiz IDS Definition": quiz_ids_definition,
                "Quiz IDS Issues": quiz_ids_issues,
                "Quiz IDS Suricata": quiz_ids_suricata,
                "Quiz IDS Total": quiz_ids_total,
                "Quiz Suricata Mandatory": quiz_suricata_mandatory,
                "Quiz Suricata Functionality": quiz_suricata_functionality,
                "Quiz Suricata Match": quiz_suricata_match,
                "Quiz Suricata Total": quiz_suricata_total,
                "Quiz English Docs": quiz_english_docs,
                "Quiz English ABE": quiz_english_abe,
                "Quiz English Total": quiz_english_total,
                "Quiz Total": quiz_total,
                "Watched Lecture On": pandas.to_datetime(numpy.nan).tz_localize(
                    "ANONYMIZED"
                ),
            },
        )

    return DataFrame(df_out_rows)


def grade_intake(df_in: DataFrame) -> DataFrame:
    df_out_rows = []

    for _, row in df_in.iterrows():
        if (
            row[
                "Are you 16 years or older?\n\nNote: If you are younger than 16 years, you are not allowed to consent to participation in the research due to the legal age of consent in the Netherlands (but you can stil"
            ]
            != "Yes"
            or row[
                'By selecting "yes" below, I confirm:\n\n1.  I have enough information about the research project from the separate  information sheet. I have read it and I had the chance to ask questions,  which have b'
            ]
            != "Yes"
        ):
            df_out_rows.append(
                {
                    "username": row[
                        "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                    ],
                    "Consent Age Reached": row[
                        "Are you 16 years or older?\n\nNote: If you are younger than 16 years, you are not allowed to consent to participation in the research due to the legal age of consent in the Netherlands (but you can stil"
                    ]
                    == "Yes",
                    "Informed Consent Granted": row[
                        'By selecting "yes" below, I confirm:\n\n1.  I have enough information about the research project from the separate  information sheet. I have read it and I had the chance to ask questions,  which have b'
                    ]
                    == "Yes",
                },
            )
            continue

        isced = row[
            "What is the highest level of education that you have completed?\n\nWhen in doubt, please refer to:\nhttps://en.wikipedia.org/wiki/International_Standard_Classification_of_Education\nor\nhttps://www.ocwinci"
        ]
        if isced == "":
            isced = numpy.nan
        else:
            isced = int(re.match(r".*ISCED (\d).*", isced).group(1))

        self_graded_ctf = row[
            "What is your level of expertise regarding Capture the Flags (or similar activities)?"
        ]
        if self_graded_ctf == "I have never heard of a Capture the Flag.":
            self_graded_ctf = 1
        elif (
            self_graded_ctf
            == "I know what a Capture the Flag is but have never participated in one."
        ):
            self_graded_ctf = 2
        elif self_graded_ctf == "I have previously participated in a Capture the Flag.":
            self_graded_ctf = 3
        elif self_graded_ctf == "I have participated in multiple Capture the Flags.":
            self_graded_ctf = 4
        elif self_graded_ctf == "I have previously organized a Capture the Flag.":
            self_graded_ctf = 5
        else:
            logger.warning("Unknown level: %s", self_graded_ctf)

        quiz_networking_tcp = int(
            row[
                "How does the TCP protocol ensure that the packets are delivered in the correct order?"
            ]
            == "Through the use of sequence and acknowledgment numbers."
        )

        quiz_networking_tls_answer = (
            row[
                "What types of information can be exchanged during the initiation of a TLS session?"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "What types of information can be exchanged during the initiation of a TLS session?"
                ]
            )
            else []
        )
        quiz_networking_tls_correct = [
            "Server and client Hello messages",
            "Encrypted handshake messages",
            "Certificate",
        ]
        quiz_networking_tls_incorrect = ["Plain-text HTTP requests", "I do not know."]
        quiz_networking_tls = 0
        for answer in quiz_networking_tls_correct:
            if answer in quiz_networking_tls_answer:
                quiz_networking_tls += 1
        for answer in quiz_networking_tls_incorrect:
            if answer in quiz_networking_tls_answer:
                quiz_networking_tls -= 1
        for answer in quiz_networking_tls_answer:
            if (
                answer not in quiz_networking_tls_correct
                and answer not in quiz_networking_tls_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_networking_tls = max(quiz_networking_tls, 0)

        quiz_networking_total = quiz_networking_tcp + quiz_networking_tls

        quiz_ocs_scanning_answer = (
            row[
                "Which of the following statements regarding network scanning are true?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding network scanning are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_scanning_correct = [
            "Network scanning may be used to inspect application layer features such as used software and versions.",
            "Nmap can only perform UDP/TCP scans.",
        ]
        quiz_ocs_scanning_incorrect = [
            "Lack of response (SYN,ACK) to a TCP SYN implies a port is filtered.",
            "Lack of response (SYN,ACK) to a TCP SYN implies a port is closed.",
            "Lack of response to a UDP packet sent to a port implies that port is closed or filtered.",
            "If you want to know which ports may be open on a public-facing IP address, you must scan it.",
            "If a vulnerability scanner detects a vulnerability, the scanned device has an exploitable vulnerability.",
            "I do not know.",
        ]
        quiz_ocs_scanning = 0
        for answer in quiz_ocs_scanning_correct:
            if answer in quiz_ocs_scanning_answer:
                quiz_ocs_scanning += 1
        for answer in quiz_ocs_scanning_incorrect:
            if answer in quiz_ocs_scanning_answer:
                quiz_ocs_scanning -= 1
        for answer in quiz_ocs_scanning_answer:
            if (
                answer not in quiz_ocs_scanning_correct
                and answer not in quiz_ocs_scanning_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_scanning = max(quiz_ocs_scanning, 0)

        quiz_ocs_xss_answer = (
            row[
                "Which of the following statements regarding Cross-Site Scripting (XSS) are true?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding Cross-Site Scripting (XSS) are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_xss_correct = [
            "XSS attacks may be prevented through input sanitization.",
            "XSS attacks can be used to steal credentials.",
            "During a successful XSS attack the attacker may execute malicious code within the web browsers of other users visiting a website.",
        ]
        quiz_ocs_xss_incorrect = [
            "During a successful XSS attack malicious code is executed on a server distributing content.",
            "XSS attacks always require vulnerable web browsers to be successful.",
            "XSS attacks are considered to be a subset of SQL injection attacks.",
            "I do not know.",
        ]
        quiz_ocs_xss = 0
        for answer in quiz_ocs_xss_correct:
            if answer in quiz_ocs_xss_answer:
                quiz_ocs_xss += 1
        for answer in quiz_ocs_xss_incorrect:
            if answer in quiz_ocs_xss_answer:
                quiz_ocs_xss -= 1
        for answer in quiz_ocs_xss_answer:
            if (
                answer not in quiz_ocs_xss_correct
                and answer not in quiz_ocs_xss_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_xss = max(quiz_ocs_xss, 0)

        quiz_ocs_persistence_answer = (
            row["Which of the following statements regarding Persistence are true?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding Persistence are true?\n"
                ]
            )
            else []
        )
        quiz_ocs_persistence_correct = [
            "Metasploit is a tool that may be used to obtain persistence depending on the targeted system.",
        ]
        quiz_ocs_persistence_incorrect = [
            "Persistence always implies that following a malware infection, malware will remain present after reinstallation of the operating system.",
            "Persistence always implies malware will be executed at some point during the boot process of the infected machine.",
            "In order to obtain persistence, malware must add an executable file to the startup folder on Windows.",
            "Persistence must be obtained in order for malware to accomplish its goal.",
            "Persistence always has associated network traffic.",
            "I do not know.",
        ]
        quiz_ocs_persistence = 0
        for answer in quiz_ocs_persistence_correct:
            if answer in quiz_ocs_persistence_answer:
                quiz_ocs_persistence += 1
        for answer in quiz_ocs_persistence_incorrect:
            if answer in quiz_ocs_persistence_answer:
                quiz_ocs_persistence -= 1
        for answer in quiz_ocs_persistence_answer:
            if (
                answer not in quiz_ocs_persistence_correct
                and answer not in quiz_ocs_persistence_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ocs_persistence = max(quiz_ocs_persistence, 0)

        quiz_ocs_total = quiz_ocs_scanning + quiz_ocs_xss + quiz_ocs_persistence

        quiz_wireshark_features_answer = (
            row["What is/are (a) feature(s) offered by Wireshark?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["What is/are (a) feature(s) offered by Wireshark?\n"]
            )
            else []
        )
        quiz_wireshark_features_correct = [
            "Filtering of packets",
            "Decoding of transmitted data",
            "Producing network I/O statistics",
            "Inspecting raw bytes transmitted in streams",
        ]
        quiz_wireshark_features_incorrect = [
            "Blocking network traffic",
            "Decrypting all encrypted network traffic",
            "I do not know.",
        ]
        quiz_wireshark_features = 0
        for answer in quiz_wireshark_features_correct:
            if answer in quiz_wireshark_features_answer:
                quiz_wireshark_features += 1
        for answer in quiz_wireshark_features_incorrect:
            if answer in quiz_wireshark_features_answer:
                quiz_wireshark_features -= 1
        for answer in quiz_wireshark_features_answer:
            if (
                answer not in quiz_wireshark_features_correct
                and answer not in quiz_wireshark_features_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_wireshark_features = max(quiz_wireshark_features, 0)

        quiz_wireshark_filter = int(
            row[
                "What is the purpose of the ip.addr==192.168.178.1/24 filter in Wireshark?\n"
            ]
            == "To only show network packets originating from or sent to the subnet 192.168.178.1/24"
        )

        quiz_wireshark_total = quiz_wireshark_features + quiz_wireshark_filter

        quiz_ids_paradigms_answer = (
            row[
                "Which of the following statements regarding different intrusion detection paradigms are true?\n"
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    "Which of the following statements regarding different intrusion detection paradigms are true?\n"
                ]
            )
            else []
        )
        quiz_ids_paradigms_correct = [
            "Signature-based intrusion detection methods primarily rely on knowledge of malicious behaviors.",
            "Anomaly-based intrusion detection methods primarily rely on knowledge of benign behaviors.",
        ]
        quiz_ids_paradigms_incorrect = [
            "Signature-based intrusion detection methods always rely on Atomic Indicators of Compromise (IOCs).",
            "Anomaly-based intrusion detection methods always rely on machine learning.",
            "Anomaly-based intrusion detection methods are a subset of signature-based intrusion detection methods.",
            "I do not know.",
        ]
        quiz_ids_paradigms = 0
        for answer in quiz_ids_paradigms_correct:
            if answer in quiz_ids_paradigms_answer:
                quiz_ids_paradigms += 1
        for answer in quiz_ids_paradigms_incorrect:
            if answer in quiz_ids_paradigms_answer:
                quiz_ids_paradigms -= 1
        for answer in quiz_ids_paradigms_answer:
            if (
                answer not in quiz_ids_paradigms_correct
                and answer not in quiz_ids_paradigms_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_ids_paradigms = max(quiz_ids_paradigms, 0)

        quiz_suricata_functionality_answer = (
            row["What are built-in functionalities offered by Suricata?\n"]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row["What are built-in functionalities offered by Suricata?\n"]
            )
            else []
        )
        quiz_suricata_functionality_correct = [
            "Matching bytes at specific locations",
            "Stateful detection across different flows in which the same IP address is involved",
            "Matching specific traffic directions",
            "Decoding of certain HTTP buffers",
            "Stateful detection within the same flow",
            "Matching using regular expressions",
        ]
        quiz_suricata_functionality_incorrect = [
            "Matching using a remote API",
            "I do not know.",
        ]
        quiz_suricata_functionality = 0
        for answer in quiz_suricata_functionality_correct:
            if answer in quiz_suricata_functionality_answer:
                quiz_suricata_functionality += 1
        for answer in quiz_suricata_functionality_incorrect:
            if answer in quiz_suricata_functionality_answer:
                quiz_suricata_functionality -= 1
        for answer in quiz_suricata_functionality_answer:
            if (
                answer not in quiz_suricata_functionality_correct
                and answer not in quiz_suricata_functionality_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_suricata_functionality = max(quiz_suricata_functionality, 0)

        quiz_suricata_match_answer = (
            row[
                """Which of the following buffers would be matched by the following sequence of Suricata options: \n\ncontent:"FOO"; content:"bar"; depth:5;\n"""
            ]
            .strip(";")
            .split(";")
            if not pandas.isna(
                row[
                    """Which of the following buffers would be matched by the following sequence of Suricata options: \n\ncontent:"FOO"; content:"bar"; depth:5;\n"""
                ]
            )
            else []
        )
        quiz_suricata_match_correct = ["barFOO"]
        quiz_suricata_match_incorrect = ["FOObar", "foobar", "barfoo", "I do not know."]
        quiz_suricata_match = 0
        for answer in quiz_suricata_match_correct:
            if answer in quiz_suricata_match_answer:
                quiz_suricata_match += 1
        for answer in quiz_suricata_match_incorrect:
            if answer in quiz_suricata_match_answer:
                quiz_suricata_match -= 1
        for answer in quiz_suricata_match_answer:
            if (
                answer not in quiz_suricata_match_correct
                and answer not in quiz_suricata_match_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_suricata_match = max(quiz_suricata_match, 0)

        quiz_english_docs_answer = (
            x + ")" if not x[-1] == ")" else x
            for x in (
                row[
                    "Read the following Suricata documentation and select the factually correct statements one can derive from the given sentence.\n\n\n\nModifiers\n\nstartswith\nThe startswith keyword is similar to depth. It ta"
                ]
                .strip(";")
                .split(");")
                if not pandas.isna(
                    row[
                        "Read the following Suricata documentation and select the factually correct statements one can derive from the given sentence.\n\n\n\nModifiers\n\nstartswith\nThe startswith keyword is similar to depth. It ta"
                    ]
                )
                else []
            )
        )
        quiz_english_docs_correct = [
            """alert dns any any -> any 53 (msg:"DNS Request to google.com"; dns.query; dotprefix; content:".google.com"; startswith; sid:1;)"""
        ]
        quiz_english_docs_incorrect = [
            """alert dns any any -> any 53 (msg:"DNS Request to google.com"; dns.query; dotprefix; content:"google.com"; startswith; sid:1;)""",
            "I do not know.",
        ]
        quiz_english_docs = 0
        for answer in quiz_english_docs_correct:
            if answer in quiz_english_docs_answer:
                quiz_english_docs += 1
        for answer in quiz_english_docs_incorrect:
            if answer in quiz_english_docs_answer:
                quiz_english_docs -= 1
        for answer in quiz_english_docs_answer:
            if (
                answer not in quiz_english_docs_correct
                and answer not in quiz_english_docs_incorrect
            ):
                logger.warning("Unknown answer: %s", answer)
        quiz_english_docs = max(quiz_english_docs, 0)

        quiz_suricata_total = (
            quiz_suricata_functionality + quiz_suricata_match + quiz_english_docs
        )

        quiz_total = (
            quiz_networking_total
            + quiz_ocs_total
            + quiz_wireshark_total
            + quiz_ids_paradigms
            + quiz_suricata_total
        )

        df_out_rows.append(
            {
                "username": row[
                    "What is the username you would like to reflect your performance on the leaderboard?\n\nNote: The leaderboard is visible to all participants. This can but does not need to be your real name. You can also"
                ],
                "Consent Age Reached": row[
                    "Are you 16 years or older?\n\nNote: If you are younger than 16 years, you are not allowed to consent to participation in the research due to the legal age of consent in the Netherlands (but you can stil"
                ]
                == "Yes",
                "Informed Consent Granted": row[
                    'By selecting "yes" below, I confirm:\n\n1.  I have enough information about the research project from the separate  information sheet. I have read it and I had the chance to ask questions,  which have b'
                ]
                == "Yes",
                "Learned About CTF": row[
                    "How did you first learn about the CTF activity?\n"
                ],
                "Gender": row["What is your gender?\n"],
                "ISCED": isced,
                "Control Question Correct": row[
                    "This question is just to check if you are actually reading questions carefully. It is an attention check. If you read this, please click the third option.\n"
                ]
                == "SSH",
                "Intake Remarks": row.fillna("")[
                    "Do you have any feedback or remarks on the survey?\n"
                ],
                "Other Relevant Experiences": row.fillna("")[
                    "Do you have any other relevant experiences (such as a job related to Security Operations or high expertise in another area you deem relevant) that may be relevant for the research? If so, describe the"
                ],
                "Has Other Relevant Experiences": not row.isna()[
                    "Do you have any other relevant experiences (such as a job related to Security Operations or high expertise in another area you deem relevant) that may be relevant for the research? If so, describe the"
                ],
                "Self Graded CTF": self_graded_ctf,
                "Quiz Networking TCP": quiz_networking_tcp,
                "Quiz Networking TLS": quiz_networking_tls,
                "Quiz Networking Scanning": quiz_ocs_scanning,
                "Quiz Networking Total": quiz_networking_total,
                "Quiz OCS Scanning": quiz_ocs_scanning,
                "Quiz OCS XSS": quiz_ocs_xss,
                "Quiz OCS Persistence": quiz_ocs_persistence,
                "Quiz OCS Total": quiz_ocs_total,
                "Quiz Wireshark Features": quiz_wireshark_features,
                "Quiz Wireshark Filter": quiz_wireshark_filter,
                "Quiz Wireshark Total": quiz_wireshark_total,
                "Quiz IDS Paradigms": quiz_ids_paradigms,
                "Quiz Suricata Functionality": quiz_suricata_functionality,
                "Quiz Suricata Match": quiz_suricata_match,
                "Quiz Suricata Docs": quiz_english_docs,
                "Quiz Suricata Total": quiz_suricata_total,
                "Quiz Total": quiz_total,
                "Watched Lecture On": pandas.to_datetime(
                    row["Completion time_lecture"]
                ).tz_localize("ANONYMIZED"),
                "Feedback Outtake": row["Do you have any feedback or remarks?\n"],
            },
        )

    return DataFrame(df_out_rows)
