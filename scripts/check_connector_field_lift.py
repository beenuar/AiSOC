#!/usr/bin/env python3
"""CI gate: fields a detection rule needs survive the connector into the engine.

The engine flattens ``raw_event`` **exactly one level**. A vendor nests the
values that decide a verdict two and three levels down — Slack's signing-in
address is ``context.ip_address``, an OAuth app's scopes are
``entity.app.scopes``, a Cloud Audit method is ``protoPayload.methodName`` —
so unless the connector lifts them they are invisible to every rule, and a
rule clausing on one compares ``None`` and can never fire. Seven shipped Okta
rules were dead for exactly this reason (``outcome.result``), and the fix
belongs in the connector: special-casing the matcher would make one vendor's
nesting a property of the engine.

Nothing caught the next instance because the two halves are checked by
different things. ``check_detection_fields.py`` collects the field namespace
by *static analysis* of connector modules, so a key the connector mentions
anywhere — including one it only reads to build a description string — counts
as emitted. Fixture replay cannot see it either, because fixtures are
synthesised from the rule under test.

This gate runs the **real connector** over a **real-shaped vendor payload**
and asserts the lifted names are present in the namespace the engine would
build. It is deliberately narrow: it pins the fields the scenario-family
rules clause on, one entry per connector, and says nothing about rules.

Out of process, for the reason ``connector_normalize_worker.py`` documents:
``services/connectors`` and ``services/fusion`` both ship their code under the
package name ``app``, so only one is importable at a time.

Usage:
    python3 scripts/check_connector_field_lift.py
    python3 scripts/check_connector_field_lift.py --self-test
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

ROOT = repo_root()
WORKER = ROOT / "scripts" / "connector_normalize_worker.py"

#: One real-shaped payload per connector, in the vendor's own envelope, and
#: the names that must reach the engine namespace after normalization.
#:
#: The payload is what the vendor documents, **not** what a rule happens to
#: match — that is the whole point, and why a rule-derived sample would prove
#: nothing. Addresses are RFC 5737 documentation ranges.
LIFTS: dict[str, dict[str, Any]] = {
    "slack_audit": {
        "raw": {
            "id": "0123a45b-6c7d-8e90-1234-56789abcdef2",
            "date_create": 1791368400,
            "action": "app_installed",
            "actor": {"type": "user", "user": {"id": "WADMIN0001", "name": "admin", "email": "admin@example.com", "team": "T1234ABCD"}},
            "entity": {"type": "app", "app": {"id": "A0123ABCD", "name": "Unvetted Exporter", "is_distributed": False, "scopes": ["files:read", "channels:history"]}},
            "context": {"location": {"type": "enterprise", "id": "E1701", "name": "Example", "domain": "example"}, "ua": "Mozilla/5.0", "ip_address": "203.0.113.22"},
        },
        "require": {
            "event_type": "slack.app_installed",
            "action": "app_installed",
            "actor_email": "admin@example.com",
            "src_ip": "203.0.113.22",
            "entity_type": "app",
            "entity_name": "Unvetted Exporter",
            "app_scopes": ["files:read", "channels:history"],
            "app_is_distributed": False,
        },
    },
    "salesforce": {
        "raw": {
            "attributes": {"type": "SetupAuditTrail"},
            "Id": "0Ym000000000001",
            "Action": "PermSetAssign",
            "Section": "Manage Users",
            "Display": "Assigned permission set Modify All Data to user",
            "CreatedDate": "2026-11-01T10:00:00.000+0000",
            "CreatedById": "005000000000001",
            "DelegateUser": "admin@example.com",
        },
        "require": {
            "event_type": "salesforce.PermSetAssign",
            "action": "PermSetAssign",
            "section": "Manage Users",
            "delegate_user": "admin@example.com",
            "created_at": "2026-11-01T10:00:00.000+0000",
        },
    },
    "snowflake": {
        # No `_kind`: a row arriving by replay or through the ingest webhook
        # carries none, and the shape is recoverable from its own columns.
        "raw": {
            "EVENT_ID": "1234",
            "EVENT_TIMESTAMP": "2026-11-01T10:00:00Z",
            "USER_NAME": "SVC_ETL",
            "CLIENT_IP": "203.0.113.5",
            "REPORTED_CLIENT_TYPE": "JDBC_DRIVER",
            "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
            "SECOND_AUTHENTICATION_FACTOR": None,
            "IS_SUCCESS": "NO",
            "ERROR_CODE": "390100",
            "ERROR_MESSAGE": "Incorrect username or password was specified.",
        },
        "require": {
            "event_type": "snowflake.login",
            "actor": "SVC_ETL",
            "src_ip": "203.0.113.5",
            "is_success": False,
            "client_type": "JDBC_DRIVER",
            "first_auth_factor": "PASSWORD",
            "error_code": "390100",
        },
    },
    "onepassword": {
        "raw": {
            "uuid": "aaaa",
            "session_uuid": "bbbb",
            "timestamp": "2026-11-01T10:00:00Z",
            "category": "credentials_failed",
            "type": "credentials_failed",
            "country": "US",
            "target_user": {"uuid": "u1", "email": "user@example.com", "name": "User"},
            "client": {"app_name": "1Password for Mac", "app_version": "8.10.0", "platform_name": "macOS", "os_name": "macOS", "ip_address": "203.0.113.5"},
        },
        "require": {
            "event_type": "onepassword.signin.credentials_failed",
            "signin_category": "credentials_failed",
            "actor_email": "user@example.com",
            "src_country": "US",
            "client_app": "1Password for Mac",
            "session_id": "bbbb",
        },
    },
    "gcp_cloud_audit": {
        "raw": {
            "logName": "projects/example/logs/cloudaudit.googleapis.com%2Factivity",
            "insertId": "i1",
            "timestamp": "2026-11-01T10:00:00Z",
            "severity": "NOTICE",
            "resource": {"type": "project", "labels": {"project_id": "sys-01234567890123456789"}},
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "methodName": "CreateProject",
                "authenticationInfo": {"principalEmail": "user@example.com"},
                "requestMetadata": {"callerIp": "203.0.113.5", "callerSuppliedUserAgent": "Mozilla/5.0"},
                "resourceName": "projects/sys-01234567890123456789",
                "status": {},
            },
        },
        "require": {
            "method_name": "CreateProject",
            "service_name": "cloudresourcemanager.googleapis.com",
            "resource_name": "projects/sys-01234567890123456789",
            "project_id": "sys-01234567890123456789",
            "caller_user_agent": "Mozilla/5.0",
            "operation_succeeded": True,
        },
    },
    "box": {
        "raw": {
            "event_id": "e1",
            "created_at": "2026-11-01T10:00:00-00:00",
            "event_type": "SHARE",
            "ip_address": "203.0.113.5",
            "created_by": {"type": "user", "id": "11", "name": "User", "login": "user@example.com"},
            "source": {"item_type": "file", "item_id": "f1", "item_name": "salaries.xlsx", "parent": {"id": "0"}, "owned_by": {"login": "owner@example.com"}},
            "additional_details": {"shared_link": {"access": "open"}},
        },
        "require": {
            "item_type": "file",
            "item_id": "f1",
            "item_owner": "owner@example.com",
            "shared_link_access": "open",
        },
    },
}


def namespace(normalized: dict[str, Any]) -> dict[str, Any]:
    """The flat namespace the matcher sees: top level, then one level of raw_event.

    Mirrors `DetectionEngine`'s merge, which the engine does once and never
    recursively. Top-level keys win, exactly as they do there.
    """
    ns = {k: v for k, v in normalized.items() if k != "raw_event"}
    nested = normalized.get("raw_event")
    if isinstance(nested, dict):
        for key, value in nested.items():
            ns.setdefault(key, value)
    return ns


def _normalize(entries: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any] | None]:
    lines = "\n".join(json.dumps({"emitter": emitter, "raw": raw}) for emitter, raw in entries)
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(WORKER)],
        input=lines,
        capture_output=True,
        text=True,
        check=True,
    )
    out: list[dict[str, Any] | None] = []
    for line in done.stdout.strip().splitlines():
        if not line.strip():
            continue
        res = json.loads(line)
        out.append(res["normalized"] if res.get("ok") else None)
    if len(out) != len(entries):
        raise SystemExit(f"connector worker returned {len(out)} results for {len(entries)} inputs")
    return out


def check(lifts: dict[str, dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    emitters = sorted(lifts)
    results = _normalize([(e, lifts[e]["raw"]) for e in emitters])
    for emitter, normalized in zip(emitters, results, strict=True):
        if normalized is None:
            problems.append(f"{emitter}: the connector rejected its real-shaped payload")
            continue
        ns = namespace(normalized)
        for field, expected in lifts[emitter]["require"].items():
            if field not in ns:
                problems.append(f"{emitter}: {field!r} never reaches the engine namespace — a rule clausing on it reads None and cannot fire")
            elif ns[field] != expected:
                problems.append(f"{emitter}: {field!r} is {ns[field]!r}, expected {expected!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run the gate's own tests")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test_main(__file__)

    problems = check(LIFTS)
    if problems:
        print("connector field lift: FAILED\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nLift the field in the connector's normalize(), not in the matcher:\n"
            "the engine flattens raw_event one level and that is deliberate.\n",
            file=sys.stderr,
        )
        return 1
    total = sum(len(v["require"]) for v in LIFTS.values())
    print(f"connector field lift: OK — {total} fields across {len(LIFTS)} connectors reach the engine namespace")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
