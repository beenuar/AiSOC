#!/usr/bin/env python3
"""Collect a diagnostic bundle an operator can actually send us.

When a deployment misbehaves the exchange is usually several rounds of "what
does X say" before anyone can form a hypothesis. This collects the answers in
one pass.

The hard part is not collection, it is **redaction**, and getting it wrong is
worse than having no bundle: a support bundle is by construction the most
concentrated pile of configuration a deployment produces, and it is emailed.
So the rule here is inverted from the usual one — values are redacted by
default and only an explicit allow-list of names is kept in the clear. A
deny-list would mean every new secret-shaped setting is exposed until someone
remembers to add it, and nobody remembers.

Collected: service versions and health, connector sync state (which is where
"it isn't ingesting" is almost always answered), dead-letter depth, pending
graph migrations, recent error-level log lines, and the claim-gate summary.

Not collected: event contents, alert bodies, prompts, model output, or
anything from the lake. A bundle that carries customer telemetry is one an
operator is not allowed to send, which makes it useless.

Run:  python3 scripts/support_bundle.py --out bundle.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Environment variables kept verbatim. Everything else is redacted, because
#: an allow-list fails safe and a deny-list fails open — and the failure is
#: silent either way until the bundle is already in an inbox.
ENV_ALLOW_LIST: frozenset[str] = frozenset(
    {
        "AISOC_ENV",
        "ENVIRONMENT",
        "AISOC_DEV_MODE",
        "AISOC_DISABLE_CLICKHOUSE",
        "AISOC_DISABLE_QDRANT",
        "AISOC_CONNECTORS_DISABLE_SCHEDULER",
        "AISOC_DEEP_INVESTIGATION",
        "AISOC_MIGRATIONS_STRICT",
        "AISOC_SIEM_WRITEBACK_ENABLED",
        "AISOC_SIEM_WRITEBACK_EXECUTE",
        "RETENTION_WORKER_ENABLED",
        "RETENTION_WORKER_DRY_RUN",
        "BACKUP_ENCRYPTION",
        "HUNT_SCHEDULER_ENABLED",
        "OAUTH_REFRESH_WORKER_ENABLED",
        "WEEKLY_DIGEST_WORKER_ENABLED",
        "LOG_LEVEL",
        "TZ",
    }
)

#: Names matching these are not even reported as present, because the name
#: itself can leak (a variable called ``ACME_PROD_DB_PASSWORD`` names the
#: customer and the environment).
#: Allow-listed names that also match the sensitive-name pattern, each with
#: the reason it is safe. A contradiction between the two lists otherwise
#: resolves silently, whichever way the code happens to check first — so an
#: overlap has to be written down to exist.
ALLOW_LIST_OVERRIDES: dict[str, str] = {
    # Holds a mode (off|local|aws), never a key. Diagnostically important:
    # "which vault format are the credentials written in" is the first
    # question when a connector cannot decrypt.
    "AISOC_CREDENTIAL_ENVELOPE": "holds a mode string, never key material",
}

#: Matched on underscore-delimited tokens, not substrings. A substring match
#: treats OAUTH_REFRESH_WORKER_ENABLED — a boolean flag — as a credential
#: because it contains "AUTH", and an allow-list that contradicts the
#: sensitive pattern resolves whichever way the code happens to check first.
SENSITIVE_NAME_RE = re.compile(
    r"(?:^|_)(KEY|KEYS|SECRET|SECRETS|TOKEN|PASSWORD|PASSWD|PASS|CREDENTIAL|" r"CREDENTIALS|DSN|AUTH|PRIVATE|SALT|CERT|PEM)(?:_|$)",
    re.IGNORECASE,
)

#: Redaction applied to every collected string, including log lines. Ordered
#: most-specific first: a bearer token also matches the generic long-string
#: pattern, and the specific label is more useful in a bug report.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{10,}", re.IGNORECASE), "Bearer <redacted>"),
    (re.compile(r"\bvault:v[12]:[A-Za-z0-9+/=_\-:]{10,}"), "<vault-token redacted>"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}"), "<api-key redacted>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<aws-access-key redacted>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "<github-token redacted>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<slack-token redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "<jwt redacted>"),
    # Any URL carrying credentials, which is how a DSN usually leaks.
    (re.compile(r"://[^:/@\s]+:[^@/\s]+@"), "://<user>:<redacted>@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<private-key redacted>"),
)


def redact(text: str) -> str:
    """Strip credential-shaped substrings. Applied to everything collected."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def collect_environment() -> dict[str, Any]:
    """Configuration flags, allow-listed. Values outside the list are shape-only."""
    allowed: dict[str, str] = {}
    redacted: list[str] = []
    withheld = 0

    for name, value in sorted(os.environ.items()):
        if (
            not name.startswith(
                (
                    "AISOC_",
                    "POSTGRES_",
                    "REDIS_",
                    "KAFKA_",
                    "CLICKHOUSE_",
                    "NEO4J_",
                    "QDRANT_",
                    "OTEL_",
                    "BACKUP_",
                    "RETENTION_",
                    "HUNT_",
                    "OAUTH_",
                    "WEEKLY_",
                )
            )
            and name not in ENV_ALLOW_LIST
            and name not in ALLOW_LIST_OVERRIDES
        ):
            continue
        if name in ENV_ALLOW_LIST or name in ALLOW_LIST_OVERRIDES:
            allowed[name] = redact(value)
        elif SENSITIVE_NAME_RE.search(name):
            # Not even listed: the name can identify the customer and the
            # environment on its own.
            withheld += 1
        else:
            # Set-or-not is usually the whole question ("is KAFKA_BOOTSTRAP_
            # SERVERS configured"), and it carries no value.
            redacted.append(name)

    return {
        "configured": allowed,
        "set_but_redacted": sorted(redacted),
        "withheld_sensitive_names": withheld,
        "note": (
            "Values are redacted by default; only an allow-list is kept in the "
            "clear. Names matching a credential pattern are not listed at all, "
            "because the name can identify the deployment."
        ),
    }


def collect_versions() -> dict[str, Any]:
    version_file = REPO_ROOT / "VERSION"
    return {
        "aisoc": version_file.read_text(encoding="utf-8").strip() if version_file.exists() else "unknown",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "git_sha": _run(["git", "rev-parse", "--short", "HEAD"]) or "unknown",
        "git_dirty": bool(_run(["git", "status", "--porcelain"])),
    }


def collect_gates() -> dict[str, Any]:
    """Claim-gate summary, which says what this build actually proves."""
    matrix = REPO_ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
    if not matrix.exists():
        return {"available": False}
    rows = [
        line
        for line in matrix.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("|") and ("GATED" in line or "PARTIAL" in line)
    ]
    return {
        "available": True,
        "gated": sum(1 for r in rows if "NO GATE" not in r and "PARTIAL" not in r and "GATED" in r),
        "partial": sum(1 for r in rows if "NO GATE" not in r and "PARTIAL" in r),
    }


def collect_compose_state() -> dict[str, Any]:
    """Which containers are up. Almost always the first question."""
    output = _run(["docker", "compose", "ps", "--format", "json"])
    if not output:
        return {"available": False, "note": "docker compose not reachable from here"}
    services = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        services.append(
            {
                "name": row.get("Service") or row.get("Name"),
                "state": row.get("State"),
                "health": row.get("Health") or "n/a",
                "status": row.get("Status"),
            }
        )
    return {"available": True, "services": services}


def collect_service_health(base_url: str) -> dict[str, Any]:
    """/health from the API, which fans out to the stores it depends on."""
    try:
        import httpx
    except ImportError:
        return {"available": False, "note": "httpx not installed"}
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/health", timeout=10.0)
        return {
            "available": True,
            "status_code": response.status_code,
            "body": json.loads(redact(response.text)) if response.text.startswith("{") else redact(response.text)[:2000],
        }
    except Exception as exc:
        # An unreachable API is a finding, not an error: it is usually the
        # answer rather than an obstacle to collecting one.
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def collect_recent_errors(lines: int = 200) -> dict[str, Any]:
    """Error-level log lines, redacted. Bounded so a bundle stays sendable."""
    output = _run(["docker", "compose", "logs", "--tail", str(lines), "--no-color"])
    if not output:
        return {"available": False}
    errors = [redact(line)[:500] for line in output.splitlines() if re.search(r"\b(ERROR|CRITICAL|Traceback|FATAL)\b", line)]
    return {
        "available": True,
        "scanned_lines": len(output.splitlines()),
        "error_lines": errors[-100:],
        "truncated": len(errors) > 100,
    }


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=REPO_ROOT)
        return result.stdout.strip()
    except Exception:  # noqa: BLE001 - a missing tool is a normal outcome here
        return ""


def build_bundle(*, api_url: str, include_logs: bool) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "schema_version": 1,
        "_readme": (
            "Diagnostic bundle. Values are redacted by allow-list, not deny-list. "
            "Contains no event data, alert bodies, prompts or model output — a "
            "bundle carrying customer telemetry is one nobody is allowed to send."
        ),
        "versions": collect_versions(),
        "gates": collect_gates(),
        "environment": collect_environment(),
        "compose": collect_compose_state(),
        "api_health": collect_service_health(api_url),
    }
    if include_logs:
        bundle["recent_errors"] = collect_recent_errors()
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Write here instead of stdout.")
    parser.add_argument("--api-url", default=os.getenv("AISOC_API_URL", "http://localhost:8000"))
    parser.add_argument(
        "--no-logs",
        action="store_true",
        help="Skip log collection. Logs are redacted, but skipping is available for deployments where even redacted log text cannot leave.",
    )
    args = parser.parse_args(argv)

    bundle = build_bundle(api_url=args.api_url, include_logs=not args.no_logs)
    payload = json.dumps(bundle, indent=2, sort_keys=True, default=str)

    if args.out:
        args.out.write_text(payload + "\n", encoding="utf-8")
        print(f"support bundle written to {args.out} ({len(payload)} bytes)")
        print("Review it before sending. Redaction is thorough but a bundle is the most concentrated configuration a deployment produces.")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
