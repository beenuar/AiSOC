"""Give a new tenant something to look at, by running the real pipeline.

Why this is not a seed script
------------------------------
`app/scripts/seed_demo.py` exists and writes rows straight into Postgres.
It is the right tool for its job — a rich fixed corpus for demos and
evals — and the wrong tool for this one, for three reasons:

* It targets a **hardcoded demo tenant**, so a self-hoster who ran it
  would populate a tenant they are not signed in to.
* Inserting rows proves nothing about the product. A console full of
  seeded alerts looks identical whether ingest, fusion and triage work or
  are completely broken.
* It is CLI-only, and the operator we are serving here is looking at a
  browser.

So this pushes a handful of events through `POST /v1/ingest/batch` — the
same door a real connector uses — and lets them become alerts the way any
other event does: normalised, fused, correlated, triaged. **If the
pipeline is broken, this produces nothing and says so**, which is far more
useful on a first run than a populated console that proves nothing.

Honesty
-------
Every scenario is obviously synthetic by construction: RFC 5737
documentation IP ranges, RFC 2606 reserved domains, and hostnames that
read as examples. The connector id is `aisoc_sample` and the ingest
profile stamps the vendor as "AiSOC (sample data)", so the alert's own
source attribution says where it came from — a reader who never saw this
wizard can still tell. Nothing here is presented as real activity, a
benchmark, a customer, or an incident.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: The connector id every sample event carries. A dedicated id, not a
#: borrowed vendor one, so sample data can be told apart from — and
#: deleted without touching — anything real.
SAMPLE_CONNECTOR = "aisoc_sample"


@dataclass(frozen=True)
class Scenario:
    """One sample event, and why it is in the set."""

    key: str
    title: str
    description: str
    severity: str
    rationale: str
    fields: dict[str, Any]


#: Five scenarios, chosen to exercise different parts of the product
#: rather than to pad a console. Between them they produce a range of
#: severities, two entity types the Investigation Rail can pivot on, and
#: at least one case the triage agent should be able to call benign —
#: because a first run where everything is critical teaches an operator
#: nothing about how the product reasons.
SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        key="brute_force",
        title="Repeated failed sign-ins from a single address",
        description=("42 failed authentications for 3 accounts from 198.51.100.23 in 4 minutes, followed by one success."),
        severity="high",
        rationale="Password spraying that succeeds — the shape most worth catching early.",
        fields={
            "src_ip": "198.51.100.23",
            "user_name": "a.chen@example.com",
            "host": "sso-gateway-01",
            "event_name": "AuthenticationFailure",
            "failure_count": 42,
        },
    ),
    Scenario(
        key="impossible_travel",
        title="Sign-in from two countries 40 minutes apart",
        description=(
            "m.okafor@example.com authenticated from 203.0.113.9 and then from 198.51.100.77, a distance no traveller covers in 40 minutes."
        ),
        severity="high",
        rationale="Identity compromise that only a correlation across events can see.",
        fields={
            "src_ip": "203.0.113.9",
            "user_name": "m.okafor@example.com",
            "host": "sso-gateway-01",
            "event_name": "ImpossibleTravel",
        },
    ),
    Scenario(
        key="encoded_powershell",
        title="Encoded PowerShell launched by a document",
        description=("WINWORD.EXE spawned powershell.exe with -enc on WS-FINANCE-04. The decoded command fetches a second stage."),
        severity="critical",
        rationale="The classic initial-access chain, and a clear true positive.",
        fields={
            "host": "WS-FINANCE-04",
            "user_name": "j.doe@example.com",
            "process_name": "powershell.exe",
            "parent_process": "WINWORD.EXE",
            "event_name": "SuspiciousProcess",
        },
    ),
    Scenario(
        key="s3_public",
        title="Storage bucket made public",
        description=(
            "A bucket policy on example-corp-backups was changed to allow public reads "
            "by a service principal that has never changed a policy before."
        ),
        severity="medium",
        rationale="Cloud posture, and a different connector category from the rest.",
        fields={
            "user_name": "svc-terraform@example.com",
            "resource": "example-corp-backups",
            "event_name": "PutBucketPolicy",
            "cloud_platform": "aws",
        },
    ),
    Scenario(
        key="scanner_noise",
        title="Vulnerability scanner sweeping the estate",
        description=(
            "The authorised scanner at 198.51.100.5 touched 240 hosts in sequence, which is what it is scheduled to do every Sunday."
        ),
        severity="low",
        rationale=(
            "Deliberately benign. A first run where every alert is critical teaches an "
            "operator nothing about how the product separates signal from routine."
        ),
        fields={
            "src_ip": "198.51.100.5",
            "host": "scanner-01",
            "event_name": "PortScan",
            "hosts_touched": 240,
        },
    ),
)


class SampleDataError(RuntimeError):
    """Something the operator needs told about, without a traceback."""


def _ingest_url() -> str:
    base = (os.getenv("INGEST_PUBLIC_URL") or os.getenv("INGEST_SERVICE_URL") or "").rstrip("/")
    return f"{base}/v1/ingest/batch" if base else "http://ingest-worker:8080/v1/ingest/batch"


def _service_token() -> str:
    return os.getenv("AISOC_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_INGEST_TOKEN", "").strip()


def build_events(*, now: datetime | None = None) -> list[dict[str, Any]]:
    """The sample batch, spread over the last hour.

    Spread rather than stamped with one timestamp so the alert list, the
    volume chart and the correlation window all have something to show —
    five events at an identical instant look like a bug.
    """
    base = now or datetime.now(UTC)
    events = []
    for index, scenario in enumerate(SCENARIOS):
        when = base - timedelta(minutes=(len(SCENARIOS) - index) * 11)
        events.append(
            {
                "source": SAMPLE_CONNECTOR,
                "external_id": f"sample-{scenario.key}-{int(when.timestamp())}",
                "title": scenario.title,
                "description": scenario.description,
                "severity": scenario.severity,
                "created_at": when.isoformat(),
                "raw_event": {
                    **scenario.fields,
                    # Carried into the lake so a reader inspecting the raw
                    # event — not just the alert — can still tell.
                    "aisoc_sample_data": True,
                    "aisoc_sample_scenario": scenario.key,
                },
                **scenario.fields,
            }
        )
    return events


async def load(*, tenant_id: str, timeout: float = 30.0) -> dict[str, Any]:
    """Push the sample batch into the caller's own tenant.

    Returns what ingest accepted. Raises `SampleDataError` with something
    an operator can act on — a first run is the worst possible moment for
    a stack trace.
    """
    token = _service_token()
    if not token:
        raise SampleDataError(
            "No service token is configured, so the API cannot post to ingest. "
            "AISOC_SERVICE_TOKEN is generated by `make up`; if this deployment was "
            "assembled by hand, set it in .env and restart the api service."
        )

    events = build_events()
    payload = {
        "connector_id": SAMPLE_CONNECTOR,
        "connector_type": SAMPLE_CONNECTOR,
        "events": events,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                _ingest_url(),
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": tenant_id,
                    "Content-Type": "application/json",
                },
            )
    except httpx.HTTPError as exc:
        raise SampleDataError(
            f"Could not reach the ingest service at {_ingest_url()}: {exc}. "
            "Sample data goes through the same door a real connector uses, so this "
            "means the pipeline itself is not reachable — `make doctor` will say why."
        ) from exc

    if response.status_code >= 400:
        raise SampleDataError(f"Ingest refused the sample batch with HTTP {response.status_code}: {response.text[:300]}")

    body = response.json() if response.content else {}
    accepted = int(body.get("accepted", 0))
    logger.info(
        "sample_data.loaded",
        tenant_id=tenant_id,
        accepted=accepted,
        rejected=body.get("rejected", 0),
    )
    return {
        "accepted": accepted,
        "rejected": int(body.get("rejected", 0)),
        "scenarios": [
            {
                "key": s.key,
                "title": s.title,
                "severity": s.severity,
                "why": s.rationale,
            }
            for s in SCENARIOS
        ],
        # Said plainly, because the wizard shows it and the gap between
        # "accepted" and "visible as an alert" is where a first-run
        # operator would otherwise conclude the product is broken.
        "note": (
            "These went through the same ingest endpoint a real connector uses. "
            "They take a few seconds to appear as alerts, because they are being "
            "normalised, correlated and triaged exactly like real telemetry."
        ),
    }
