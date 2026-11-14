"""Ack-clock escalation bridge.

The platform's outbound webhook subsystem (services/api/app/services/
outbound_webhooks.py) is complete but not yet wired: enqueue_event has no
production callers. Until it is, this service fills the gap by watching the
platform's OWN ack clock (aisoc_cases.acknowledged_at) and
posting escalations to a Microsoft Teams Power Automate workflow (or any
generic JSON webhook):

  * CRITICAL cases unacknowledged for >= ACK_GRACE_MINUTES escalate
    immediately, re-nagging every CRIT_NAG_HOURS up to CRIT_MAX_NAGS times.
  * unacknowledged HIGH cases arrive in one daily digest at DIGEST_HOUR_UTC
    (first tick at or after that hour), with a one-line pipeline health
    summary (failed investigations / dead-letters in the last 24h).

Dedup and nag state live in a JSON file so restarts never double-send.

Two deliberate semantics, stated so nobody infers better ones:

* **"Acknowledged" means `acknowledged_at` was written** — today the console's
  acknowledge action and a war-room join write it (`war_room.py` stamps it
  with COALESCE). A case merely being edited, assigned or moved along the
  status ladder does NOT stop the clock; that is the point of an ack clock.
* **The sweep is deployment-wide, not per-tenant.** Every tenant's
  unacknowledged cases escalate to the one operator-configured webhook,
  because this bridge is a deployment-level pager, not a tenant notification
  channel — per-tenant routing is exactly what the native outbound-webhook
  subsystem does once its emitters are wired, and what this service retires
  into. On a multi-tenant deployment that means case titles from every tenant
  reach one channel: run it only where the operators of that channel are
  cleared to see every tenant, or not at all. The cross-tenant reads are
  recorded on `scripts/check_tenant_query_predicates.py`'s ratchet with this
  reasoning.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime

import psycopg
from psycopg.rows import dict_row

# --- configuration (env) ------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
TEAMS_URL = os.environ.get("AISOC_ESCALATION_TEAMS_URL", "")
# Deployment-neutral default: the console's own default address. A specific
# deployment's hostname here is how one install's URL ends up inside
# another's escalation cards.
CONSOLE_URL = os.environ.get("AISOC_CONSOLE_URL", "http://localhost:3000")
TICK_SECONDS = int(os.environ.get("ESC_TICK_SECONDS", "900"))
ACK_GRACE_MINUTES = int(os.environ.get("ESC_CRITICAL_GRACE_MINUTES", "30"))
CRIT_NAG_HOURS = int(os.environ.get("ESC_CRITICAL_NAG_HOURS", "4"))
CRIT_MAX_NAGS = int(os.environ.get("ESC_CRITICAL_MAX_NAGS", "3"))
DIGEST_HOUR_UTC = int(os.environ.get("ESC_DIGEST_HOUR_UTC", "8"))
STATE_FILE = os.environ.get("ESC_STATE_FILE", "/data/escalation-state.json")

# Exactly the non-terminal members of aisoc_cases' status CHECK constraint
# (migration 012_case_management.sql:
# new|triaged|investigating|contained|resolved|closed).
# "open" is not in that vocabulary — a filter member that can never match —
# and "contained" is included deliberately: containment can be automated,
# and the ack clock measures whether a human has acknowledged, not whether
# automation has acted. test_ladder.py pins this tuple against the
# migration's own CHECK clause so the two cannot drift apart silently.
OPEN_STATUSES = ("new", "triaged", "investigating", "contained")


def log(msg: str) -> None:
    print(f"{datetime.now(UTC).isoformat(timespec='seconds')} {msg}", flush=True)


# --- pure decision logic (unit-tested) --------------------------------------
@dataclass
class Case:
    id: str
    case_number: str
    title: str
    severity: str
    opened_at: datetime

    @property
    def url(self) -> str:
        return f"{CONSOLE_URL}/cases/{self.id}"

    @property
    def ref(self) -> str:
        return self.case_number or self.id[:8]


@dataclass
class NagState:
    count: int = 0
    last: str = ""


def should_escalate_critical(case: Case, nag: NagState | None, now: datetime) -> bool:
    """A CRITICAL case escalates once past the ack grace period, then at
    most every CRIT_NAG_HOURS, up to CRIT_MAX_NAGS total sends."""
    if (now - case.opened_at).total_seconds() < ACK_GRACE_MINUTES * 60:
        return False
    if nag is None or not nag.last:
        return True
    last = datetime.fromisoformat(nag.last)
    if (now - last).total_seconds() < CRIT_NAG_HOURS * 3600:
        return False
    return nag.count < CRIT_MAX_NAGS


def should_send_digest(digest_last: str, now: datetime) -> bool:
    return now.hour >= DIGEST_HOUR_UTC and digest_last != now.strftime("%Y-%m-%d")


def crit_payload(case: Case, age_minutes: float, nag_number: int) -> dict:
    return {
        "severity": "CRITICAL",
        "title": case.title or "Critical case unacknowledged",
        "summary": (f"Unacknowledged for {int(age_minutes)} min. Escalation {nag_number}/{CRIT_MAX_NAGS}."),
        "case_id": case.ref,
        "opened_at": case.opened_at.strftime("%Y-%m-%d %H:%M UTC"),
        "url": case.url,
    }


def digest_payload(cases: list[Case], health: str, now: datetime) -> dict:
    listed = "\n".join(f"- {c.ref}: {c.title}" for c in cases[:8])
    more = f"\n…and {len(cases) - 8} more" if len(cases) > 8 else ""
    return {
        "severity": "DIGEST",
        "title": f"AiSOC daily digest — {len(cases)} HIGH unacked",
        "summary": f"{listed}{more}\n\nPipeline health: {health}",
        "case_id": f"{len(cases)} HIGH open",
        "opened_at": now.strftime("%Y-%m-%d %H:%M UTC"),
        "url": f"{CONSOLE_URL}/cases",
    }


# --- state -------------------------------------------------------------------
def load_state() -> dict:
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"escalations": {}, "digest_last": ""}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, STATE_FILE)


# --- IO ----------------------------------------------------------------------
def post(url: str, payload: dict) -> int:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    # The URL is operator-supplied configuration (AISOC_ESCALATION_TEAMS_URL),
    # validated https-only at startup by require_https_webhook() — never
    # tenant- or request-derived, so the SSRF surface the audit rule
    # (python.lang.security.audit.dynamic-urllib-use-detected) exists for does
    # not apply. Bare nosemgrep because the fully-qualified id exceeds the
    # line limit; this is the module's only urlopen.
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep
        return resp.status


def require_https_webhook(url: str) -> str:
    """Refuse a webhook target that is not https.

    The value is operator-set, but a typo'd `http://` would send case titles
    in cleartext and a `file://`/`ftp://` scheme would make urlopen do
    something else entirely. Failing at startup names the problem while the
    operator is still looking at the deployment.
    """
    if not url.startswith("https://"):
        raise SystemExit(f"AISOC_ESCALATION_TEAMS_URL must be https:// (got scheme of {url.split(':', 1)[0]!r})")
    return url


def fetch_unacked(cur, severity: str) -> list[Case]:
    rows = cur.execute(
        "SELECT id, case_number, title, severity, opened_at FROM aisoc_cases "
        "WHERE acknowledged_at IS NULL AND lower(severity) = %s AND status = ANY(%s) "
        "ORDER BY opened_at ASC LIMIT 50",
        (severity, list(OPEN_STATUSES)),
    ).fetchall()
    out = []
    for r in rows:
        opened = r["opened_at"]
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=UTC)
        out.append(Case(str(r["id"]), r["case_number"] or "", r["title"] or "", r["severity"], opened))
    return out


def pipeline_health(cur) -> str:
    bits = []
    try:
        n = cur.execute(
            # The ledger table is `investigation_runs` (migration 008) — there
            # is no `aisoc_`-prefixed variant, and the first draft queried one,
            # which this try/except would have converted into a permanent
            # "n/a" that read like a healthy pipeline with no failures.
            "SELECT count(*) AS n FROM investigation_runs WHERE status = 'failed' AND created_at > now() - interval '24 hours'"
        ).fetchone()["n"]
        bits.append(f"investigation failures 24h: {n}")
    except Exception:
        bits.append("investigation failures 24h: n/a")
    try:
        n = cur.execute("SELECT count(*) AS n FROM aisoc_dead_letters WHERE created_at > now() - interval '24 hours'").fetchone()["n"]
        bits.append(f"dead-letters 24h: {n}")
    except Exception:
        bits.append("dead-letters 24h: n/a")
    return "; ".join(bits)


# --- main loop ---------------------------------------------------------------
def tick(state: dict) -> None:
    now = datetime.now(UTC)
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        cur = conn.cursor()
        for case in fetch_unacked(cur, "critical"):
            nag_d = state["escalations"].get(case.id)
            nag = NagState(**nag_d) if nag_d else None
            if not should_escalate_critical(case, nag, now):
                continue
            nag = nag or NagState()
            age = (now - case.opened_at).total_seconds() / 60
            code = post(TEAMS_URL, crit_payload(case, age, nag.count + 1))
            log(f"critical escalation {case.ref} HTTP {code}")
            nag.count += 1
            nag.last = now.isoformat()
            state["escalations"][case.id] = nag.__dict__

        if should_send_digest(state.get("digest_last", ""), now):
            highs = fetch_unacked(cur, "high")
            if highs:
                code = post(TEAMS_URL, digest_payload(highs, pipeline_health(cur), now))
                log(f"daily digest HTTP {code} highs={len(highs)}")
            state["digest_last"] = now.strftime("%Y-%m-%d")
    save_state(state)


def main() -> None:
    if not TEAMS_URL:
        raise SystemExit("AISOC_ESCALATION_TEAMS_URL is required")
    require_https_webhook(TEAMS_URL)
    if not DATABASE_URL:
        raise SystemExit("DATABASE_URL is required")
    log(f"escalation bridge up: tick={TICK_SECONDS}s grace={ACK_GRACE_MINUTES}m digest_hour={DIGEST_HOUR_UTC}Z console={CONSOLE_URL}")
    state = load_state()
    while True:
        try:
            tick(state)
        except Exception as exc:  # never let one bad tick kill the loop
            log(f"ERROR tick: {type(exc).__name__}: {exc}")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    main()
