"""A benign corpus that actually looks like a SOC queue.

Gap-closure wave 2.

Why this file exists
--------------------
Every labelled corpus in this repository was malicious by construction,
so no verdict accuracy could be measured from any of them — an agent
answering "true positive" to everything scores 100%. The benchmark
corpus appeared to have a benign class and did not: `build_corpus.py`
derived one from ``response_class == "monitor"``, and those eight
incidents are BloodHound domain enumeration tagged **T1087.002** at
medium severity. That is a real attack with a monitoring response, not a
benign event. Labelling it benign conflated "low-severity threat" with
"not a threat", which is the single most important distinction a triage
agent makes.

What makes a benign corpus useful
------------------------------------
**The cases must look like attacks.** A benign corpus of obviously
boring events measures formatting, not judgement: any agent can tell a
successful DNS lookup from ransomware. Every case here is something that
*fires a real detection rule* and is nonetheless the right answer to
close. PsExec at 02:00 during a change window. Encoded PowerShell in a
deployment script. Nmap from the scanner subnet. Bulk file reads by the
backup agent.

**The telemetry must have the same shape.** These carry the same fields,
the same sources and the same severity distribution as the malicious
set, so a model cannot separate the classes on format. Where the
distinguishing evidence exists it is *in the content* — a change ticket
reference, a known service account, a scanner's own subnet — which is
exactly what an analyst reads.

Two classes, and the difference matters
------------------------------------------
``benign`` — the activity happened and was authorised. The detection was
right to fire; the answer is "this was us".

``false_positive`` — the activity did not happen as the alert
characterises it. The rule matched something it should not have.

They are different operationally: a stream of ``benign`` means tuning an
allowlist, a stream of ``false_positive`` means fixing a rule. Collapsing
them, as a single "not malicious" label would, loses the action.

Addresses and names
-------------------
RFC 5737 documentation ranges and RFC 2606 domains throughout, asserted
by test. A corpus that shipped a routable address would eventually have
somebody scan it.
"""

from __future__ import annotations

from typing import Any

__all__ = ["BENIGN_CASES", "benign_corpus_records"]

#: Verbatim the canonical vocabulary from `aisoc_benchmark.replay`, which
#: mirrors `services/actions`. The benchmark corpus previously used
#: `malicious | suspicious | benign`, which shares exactly one label with
#: it — so the corpus was ungradeable by the repository's own scorer and
#: nobody had noticed.
BENIGN = "benign"
FALSE_POSITIVE = "false_positive"


def _case(
    *,
    case_id: str,
    title: str,
    description: str,
    severity: str,
    disposition: str,
    techniques: list[str],
    telemetry: list[dict[str, Any]],
    why: str,
) -> dict[str, Any]:
    """One labelled case.

    `why` is the analyst's reasoning, carried so a human reviewing a
    disagreement can see what the right answer rested on rather than
    having to re-derive it. It is deliberately **not** given to the
    agent: a corpus that hands over the answer measures reading
    comprehension.
    """
    return {
        "id": case_id,
        "provenance": "synthetic",
        "title": title,
        "description": description,
        "severity": severity,
        "expected_disposition": disposition,
        "expected_techniques": techniques,
        "expected_actions": [],
        "raw_alert": {"title": title, "severity": severity},
        "telemetry": telemetry,
        "analyst_rationale": why,
    }


BENIGN_CASES: list[dict[str, Any]] = [
    # ── Administrative activity that trips containment rules ───────────────
    _case(
        case_id="INC-BENIGN-001",
        title="PsExec service installed on WIN-DB-07",
        description=(
            "psexesvc.exe installed and started on WIN-DB-07 by svc-patching@example.com at 02:14 local. Source host WIN-MGMT-01."
        ),
        severity="high",
        disposition=BENIGN,
        techniques=["T1569.002"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 1,
                "Computer": "WIN-DB-07",
                "Image": "C:\\Windows\\PSEXESVC.exe",
                "User": "EXAMPLE\\svc-patching",
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "UtcTime": "2026-03-04T02:14:11Z",
            },
            {
                "source": "itsm",
                "change_ticket": "CHG0041288",
                "window_start": "2026-03-04T02:00:00Z",
                "window_end": "2026-03-04T04:00:00Z",
                "approver": "platform-oncall@example.com",
                "summary": "Quarterly database patch rollout, wave 3",
            },
        ],
        why=(
            "Lateral-movement tooling used by the patching service account inside an "
            "approved change window, from the management jump host it always uses."
        ),
    ),
    _case(
        case_id="INC-BENIGN-002",
        title="Encoded PowerShell from build agent LIN-CI-04",
        description=("powershell.exe -EncodedCommand observed on WIN-BUILD-02, parent process the Jenkins agent service."),
        severity="high",
        disposition=BENIGN,
        techniques=["T1059.001", "T1027"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 1,
                "Computer": "WIN-BUILD-02",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile -EncodedCommand JABFAHIAcgBvAHIAQQBjAHQA",
                "ParentImage": "C:\\Program Files\\Jenkins\\jenkins-agent.exe",
                "User": "EXAMPLE\\svc-jenkins",
            },
            {
                "source": "vcs",
                "repository": "example/platform-deploy",
                "file": "scripts/deploy.ps1",
                "note": "Encoding is how the pipeline passes a multi-line script through the agent.",
            },
        ],
        why=(
            "Base64-encoded PowerShell is how this build pipeline has always invoked its "
            "deployment script; the parent process is the CI agent and the command decodes "
            "to a committed, reviewed script."
        ),
    ),
    _case(
        case_id="INC-BENIGN-003",
        title="Port scan across 10.0.0.0/8 from 198.51.100.40",
        description="Sequential TCP connections to 1,024 ports across 2,300 hosts in eleven minutes.",
        severity="medium",
        disposition=BENIGN,
        techniques=["T1046"],
        telemetry=[
            {
                "source": "netflow",
                "src_ip": "198.51.100.40",
                "distinct_dst": 2300,
                "distinct_ports": 1024,
                "duration_seconds": 660,
            },
            {
                "source": "asset_inventory",
                "ip": "198.51.100.40",
                "hostname": "vulnscan-prod-01.example.com",
                "owner": "security-engineering@example.com",
                "role": "authenticated vulnerability scanner",
                "scan_schedule": "weekly, Sundays 01:00-05:00 UTC",
            },
        ],
        why="The organisation's own vulnerability scanner, on its published schedule, from its registered address.",
    ),
    _case(
        case_id="INC-BENIGN-004",
        title="Mass file read by backup agent on FS-CORP-02",
        description="48,000 file reads in 20 minutes by a single process on the corporate file server.",
        severity="high",
        disposition=BENIGN,
        techniques=["T1005", "T1074.001"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 11,
                "Computer": "FS-CORP-02",
                "Image": "C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe",
                "User": "EXAMPLE\\svc-backup",
                "files_touched": 48000,
                "window_minutes": 20,
            },
            {
                "source": "edr",
                "process_signed": True,
                "signer": "Veeam Software Group GmbH",
                "network_destinations": ["198.51.100.70"],
            },
        ],
        why=(
            "Signed backup agent reading the share it is configured to back up, writing only "
            "to the backup target. No archive creation, no outbound transfer."
        ),
    ),
    _case(
        case_id="INC-BENIGN-005",
        title="LDAP enumeration from LIN-IAM-SYNC01",
        description="12,400 LDAP queries enumerating users, groups and group membership in six minutes.",
        severity="medium",
        disposition=BENIGN,
        techniques=["T1087.002", "T1069.002"],
        telemetry=[
            {
                "source": "windows_event",
                "EventID": 4662,
                "Computer": "DC01.example.com",
                "SubjectUserName": "svc-scim-sync",
                "query_count": 12400,
                "window_minutes": 6,
            },
            {
                "source": "asset_inventory",
                "hostname": "LIN-IAM-SYNC01",
                "role": "SCIM provisioning connector",
                "runs_every": "15 minutes",
            },
        ],
        why=(
            "The SCIM connector reading the directory it exists to read, on its normal cadence. "
            "Enumeration volume is identical to the previous 96 runs."
        ),
    ),
    _case(
        case_id="INC-BENIGN-006",
        title="Impossible travel for j.okafor@example.com",
        description="Sign-in from London then Singapore 40 minutes apart.",
        severity="high",
        disposition=BENIGN,
        techniques=["T1078.004"],
        telemetry=[
            {
                "source": "okta",
                "eventType": "user.session.start",
                "actor": "j.okafor@example.com",
                "client_ip": "198.51.100.12",
                "geo": "London, GB",
                "ts": "2026-03-04T08:02:00Z",
            },
            {
                "source": "okta",
                "eventType": "user.session.start",
                "actor": "j.okafor@example.com",
                "client_ip": "203.0.113.88",
                "geo": "Singapore, SG",
                "ts": "2026-03-04T08:42:00Z",
            },
            {
                "source": "network",
                "ip": "203.0.113.88",
                "note": "Corporate egress gateway, APAC region. Traffic egresses here when the VPN reconnects.",
            },
        ],
        why=(
            "The second address is the organisation's own APAC egress gateway, not a second "
            "location. Both sessions carry the same device id and a satisfied MFA claim."
        ),
    ),
    _case(
        case_id="INC-BENIGN-007",
        title="New privileged account created: svc-terraform-runner",
        description="Account created and added to Domain Admins outside business hours.",
        severity="critical",
        disposition=BENIGN,
        techniques=["T1136.002", "T1098"],
        telemetry=[
            {
                "source": "windows_event",
                "EventID": 4720,
                "Computer": "DC01.example.com",
                "TargetUserName": "svc-terraform-runner",
                "SubjectUserName": "svc-provisioning",
                "ts": "2026-03-04T23:40:00Z",
            },
            {
                "source": "itsm",
                "change_ticket": "CHG0041301",
                "approver": "iam-lead@example.com",
                "summary": "Provision infrastructure-automation service account, approved at CAB 2026-02-27",
            },
        ],
        why="Approved service-account provisioning, executed by the provisioning pipeline against an open change.",
    ),
    _case(
        case_id="INC-BENIGN-008",
        title="Bulk outbound email from 198.51.100.55",
        description="22,000 messages to external recipients in one hour.",
        severity="medium",
        disposition=BENIGN,
        techniques=["T1114.003"],
        telemetry=[
            {
                "source": "m365_audit",
                "Operation": "Send",
                "sender": "campaigns@example.com",
                "message_count": 22000,
                "window_minutes": 60,
            },
            {
                "source": "asset_inventory",
                "ip": "198.51.100.55",
                "hostname": "mkt-sendgrid-relay.example.com",
                "role": "marketing email relay",
            },
        ],
        why="The marketing relay sending a scheduled campaign from its own mailbox and address.",
    ),
    _case(
        case_id="INC-BENIGN-009",
        title="Credential dumping tool executed on WIN-SEC-LAB01",
        description="mimikatz.exe executed by t.nakamura@example.com.",
        severity="critical",
        disposition=BENIGN,
        techniques=["T1003.001"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 1,
                "Computer": "WIN-SEC-LAB01",
                "Image": "C:\\Tools\\mimikatz.exe",
                "User": "EXAMPLE\\t.nakamura",
            },
            {
                "source": "asset_inventory",
                "hostname": "WIN-SEC-LAB01",
                "role": "detection-engineering lab, isolated VLAN, no domain trust",
                "owner": "detection-engineering@example.com",
            },
        ],
        why=(
            "Detection engineering exercising a rule on the isolated lab host built for it. The "
            "host has no domain trust, so there are no credentials present to dump."
        ),
    ),
    _case(
        case_id="INC-BENIGN-010",
        title="Scheduled task created on 140 hosts",
        description="Identical scheduled task written across 140 endpoints within four minutes.",
        severity="high",
        disposition=BENIGN,
        techniques=["T1053.005"],
        telemetry=[
            {
                "source": "windows_event",
                "EventID": 4698,
                "TaskName": "\\Example\\EndpointInventory",
                "host_count": 140,
                "window_minutes": 4,
                "SubjectUserName": "svc-sccm",
            },
            {
                "source": "itsm",
                "change_ticket": "CHG0041312",
                "summary": "Roll out endpoint inventory collector to the finance OU",
            },
        ],
        why="SCCM deploying an inventory task to a named OU under an approved change.",
    ),
    # ── Genuine false positives: the activity is not what the alert says ───
    _case(
        case_id="INC-FP-001",
        title="Ransomware file-extension activity on WIN-HR-21",
        description="Rule matched 400 files renamed to a known ransomware extension.",
        severity="critical",
        disposition=FALSE_POSITIVE,
        techniques=["T1486"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 11,
                "Computer": "WIN-HR-21",
                "TargetFilename": "D:\\archive\\2019-payroll.7z.locked",
                "Image": "C:\\Program Files\\7-Zip\\7zG.exe",
                "User": "EXAMPLE\\m.alvarez",
            },
            {
                "source": "edr",
                "note": "Files were renamed by an archival script appending '.locked' as its own marker.",
                "entropy_change": "none",
                "ransom_note_found": False,
            },
        ],
        why=(
            "The extension matched the rule's list by coincidence: an in-house archival script "
            "uses '.locked' to mark files pending deletion. No encryption occurred — file "
            "entropy is unchanged and no ransom note exists. The rule needs the extension list "
            "narrowed, not an allowlist entry."
        ),
    ),
    _case(
        case_id="INC-FP-002",
        title="C2 beacon to malware-c2.example.net from WIN-FIN-09",
        description="Periodic outbound HTTPS matching a threat-intel indicator.",
        severity="critical",
        disposition=FALSE_POSITIVE,
        techniques=["T1071.001"],
        telemetry=[
            {
                "source": "proxy",
                "src_host": "WIN-FIN-09",
                "dst_domain": "malware-c2.example.net",
                "interval_seconds": 300,
                "bytes_out": 412,
            },
            {
                "source": "threatintel",
                "indicator": "malware-c2.example.net",
                "note": "Sinkholed by the registrar in 2024; the IOC feed never expired the entry.",
                "first_seen": "2023-11-02",
                "sinkholed": True,
            },
        ],
        why=(
            "The domain is sinkholed and has been since 2024. The beacon is a stale agent "
            "retrying a dead address, not an active channel. The indicator should have aged out "
            "of the feed."
        ),
    ),
    _case(
        case_id="INC-FP-003",
        title="Brute force against svc-monitoring from 198.51.100.90",
        description="620 failed authentications in ten minutes.",
        severity="high",
        disposition=FALSE_POSITIVE,
        techniques=["T1110.001"],
        telemetry=[
            {
                "source": "windows_event",
                "EventID": 4625,
                "TargetUserName": "svc-monitoring",
                "IpAddress": "198.51.100.90",
                "failure_count": 620,
                "Status": "0xC000006A",
            },
            {
                "source": "asset_inventory",
                "ip": "198.51.100.90",
                "hostname": "nagios-01.example.com",
                "note": "Credential rotated 2026-03-03; the monitoring host kept the old secret in its config.",
            },
        ],
        why=(
            "One host retrying one stale credential after a rotation, not an attacker trying "
            "many. Every attempt carries the same wrong password hash and the same source."
        ),
    ),
    _case(
        case_id="INC-FP-004",
        title="Data exfiltration: 14 GB uploaded from LIN-APP-12",
        description="Large sustained outbound transfer to an external address.",
        severity="high",
        disposition=FALSE_POSITIVE,
        techniques=["T1048"],
        telemetry=[
            {
                "source": "netflow",
                "src_host": "LIN-APP-12",
                "dst_ip": "198.51.100.200",
                "bytes_out": 15032385536,
                "duration_minutes": 46,
            },
            {
                "source": "asset_inventory",
                "ip": "198.51.100.200",
                "hostname": "artifact-mirror.example.com",
                "note": (
                    "Internal artifact mirror. Classified external by the rule "
                    "because it sits outside the RFC1918 ranges the rule checks."
                ),
            },
        ],
        why=(
            "The destination is an internal mirror on a public-range address the rule's "
            "'external' test does not know about. Direction is a push of build artefacts the "
            "host produces. The rule's definition of external is the defect."
        ),
    ),
    _case(
        case_id="INC-FP-005",
        title="Suspicious parent-child: winword.exe spawning cmd.exe on WIN-LEG-03",
        description="Office application spawned a command shell.",
        severity="high",
        disposition=FALSE_POSITIVE,
        techniques=["T1566.001", "T1059.003"],
        telemetry=[
            {
                "source": "sysmon",
                "EventID": 1,
                "Computer": "WIN-LEG-03",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": 'cmd.exe /c "C:\\Legal\\merge-templates.bat"',
                "User": "EXAMPLE\\r.devlin",
            },
            {
                "source": "vcs",
                "note": "merge-templates.bat is a reviewed document-assembly macro deployed to the legal OU in 2021.",
            },
        ],
        why=(
            "The parent-child pair is genuinely suspicious as a shape, and in this estate it is "
            "a sanctioned legal-department macro. The command line names a known, reviewed batch "
            "file rather than an encoded payload or a download."
        ),
    ),
]


# ── Template expansion ────────────────────────────────────────────────────
#
# The fifteen cases above are the distinct *shapes*. A real queue carries
# each shape many times over with different hosts, accounts and times,
# and a corpus of fifteen cannot support a precision figure — the
# gradeability guard refuses a minority class under 5%.
#
# Expanded the same way the malicious corpus is (55 templates → 200
# incidents) so the two halves are built alike. The varied fields are
# the ones that genuinely vary between occurrences; **the evidence that
# decides the label is never varied**, because a case whose answer moves
# with its hostname is not the same case.

_HOSTS = (
    "WIN-FIN-03",
    "WIN-ENG-17",
    "LIN-APP-05",
    "WIN-HR-08",
    "LIN-DATA-11",
    "WIN-OPS-22",
    "LIN-EDGE-02",
    "WIN-LEG-14",
    "LIN-CI-09",
    "WIN-DB-31",
)
_ACTORS = (
    "a.hassan@example.com",
    "p.lindqvist@example.com",
    "s.oyelaran@example.com",
    "d.moreau@example.com",
    "k.bhattacharya@example.com",
)
_TICKETS = ("CHG0041420", "CHG0041455", "CHG0041487", "CHG0041502", "CHG0041533")


def _expanded() -> list[dict[str, Any]]:
    """Each shape, recurring with different incidental detail."""
    out: list[dict[str, Any]] = []
    for index, base in enumerate(BENIGN_CASES):
        # Four extra occurrences per shape, which takes the benign and
        # false-positive classes to roughly a quarter of the corpus —
        # still malicious-heavy, and far enough above the 5% floor that
        # precision means something.
        for occurrence in range(1, 5):
            host = _HOSTS[(index * 4 + occurrence) % len(_HOSTS)]
            actor = _ACTORS[(index + occurrence) % len(_ACTORS)]
            ticket = _TICKETS[(index + occurrence) % len(_TICKETS)]

            case = {
                **base,
                "id": f"{base['id']}-R{occurrence}",
                "title": base["title"].replace("WIN-DB-07", host).replace("LIN-IAM-SYNC01", host),
                "telemetry": [
                    {
                        **event,
                        **({"Computer": host} if "Computer" in event else {}),
                        **({"src_host": host} if "src_host" in event else {}),
                        **({"actor": actor} if "actor" in event else {}),
                        **({"change_ticket": ticket} if "change_ticket" in event else {}),
                    }
                    for event in base["telemetry"]
                ],
            }
            case["raw_alert"] = {"title": case["title"], "severity": case["severity"]}
            out.append(case)
    return out


def benign_corpus_records() -> list[dict[str, Any]]:
    """The benign corpus, with the analyst rationale withheld.

    The rationale is kept in the source so a reviewer can see what the
    label rests on, and stripped here because a corpus that hands the
    agent its own answer measures reading comprehension.
    """
    out: list[dict[str, Any]] = []
    for case in [*BENIGN_CASES, *_expanded()]:
        record = dict(case)
        record.pop("analyst_rationale", None)
        out.append(record)
    return out
