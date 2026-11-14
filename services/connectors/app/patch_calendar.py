"""The org's patch-window calendar — one source of truth for patch due dates.

Codifies ``docs/cve-patch-policy.md``:

* ``patch_tuesday``   — Microsoft Patch Tuesday, the second Tuesday of the
  month (the Linux advisory window lands on the same day).
* TEST environment    — due the first Wednesday on-or-after Patch Tuesday.
* PROD environment    — due exactly seven days after the TEST window, so
  every production patch is observed on test hardware first.

Verified against the calendar the policy doc committed with:

    TEST: Oct 14, Nov 11, Dec 9 (2026)   PROD: Oct 21, Nov 18, Dec 16 (2026)

Why a module and not a prompt: the policy is enforced by ingest, inventory
and the promotion worker. An agent prompt can restate the policy; it cannot
be what computes ``patch_due_date`` (the policy doc's own enforcement
table). Hostname classification lives here too so every writer buckets hosts
identically — and it is conservative on purpose: an unknown host is PROD,
because a missed urgent patch on a production box is the expensive failure,
while a patch moved a week earlier costs nothing.
"""

from __future__ import annotations

import calendar
from datetime import UTC, date, datetime, timedelta

#: Environment buckets the patch windows are defined for.
ENV_TEST = "test"
ENV_PROD = "prod"

#: Hostname tokens that mark a host as TEST. Substring match, lowercase.
#: Everything else — including names we don't recognise — is PROD.
_TEST_HOSTNAME_TOKENS: tuple[str, ...] = ("dev", "test", "uat", "staging", "stage", "sandbox", "qa")


def patch_tuesday(year: int, month: int) -> date:
    """The second Tuesday of ``year``-``month`` (Microsoft Patch Tuesday).

    ``calendar.monthcalendar`` weeks start Monday, so Tuesday is column 1.
    The row containing day 8 is by construction the row containing the
    second Tuesday — every month has exactly one day 8, and the first week
    holds at most days 1-7.
    """
    for week in calendar.monthcalendar(year, month):
        day = week[calendar.TUESDAY]
        if day != 0 and day >= 8:
            return date(year, month, day)
    # monthcalendar cannot yield no Tuesday; unreachable but explicit.
    raise ValueError(f"no Tuesday found in {year}-{month}")


def test_patch_due_for(found_on: date) -> date:
    """The TEST window a finding seen on ``found_on`` is due in.

    The window is the first Wednesday on-or-after that month's Patch
    Tuesday. A finding discovered *after* the window has passed — e.g.
    scanned into inventory late — is due in the NEXT month's window; we
    never mint a due date in the past, because an instantly-overdue finding
    would fire the promotion worker for findings the operators have simply
    not been scanned yet. A finding discovered ON Patch Tuesday or ON the
    window Wednesday itself is due that same Wednesday: the window is open.
    """
    tuesday = patch_tuesday(found_on.year, found_on.month)
    wednesday = tuesday + timedelta(days=1)
    if wednesday < found_on:
        # The window already closed; roll to the next month (December ->
        # January carries the year).
        if found_on.month == 12:
            return test_patch_due_for(date(found_on.year + 1, 1, 1))
        return test_patch_due_for(date(found_on.year, found_on.month + 1, 1))
    return wednesday


def prod_patch_due_for(test_due: date) -> date:
    """PROD window = TEST window + 7 days."""
    return test_due + timedelta(days=7)


def patch_due_for(found_on: datetime | date, environment: str) -> date:
    """The patch due date for a finding seen on ``found_on`` in ``environment``.

    Accepts aware or naive datetimes; naive is assumed UTC. The date is
    computed once, at materialization, from the date the scan first reported
    the finding, so the clock a patch SLA is measured against never moves
    (mirrors ``first_found`` never being touched by a re-poll).
    """
    if isinstance(found_on, datetime):
        day = found_on.astimezone(UTC).date() if found_on.tzinfo else found_on.date()
    else:
        day = found_on
    env = (environment or ENV_PROD).strip().lower()
    test_due = test_patch_due_for(day)
    return test_due if env == ENV_TEST else prod_patch_due_for(test_due)


def classify_environment(hostname: str | None) -> str:
    """Bucket a hostname into ``test`` or ``prod`` for patch-window purposes.

    Fail closed toward PROD: an unrecognised host gets the production window
    so a real production box can never inherit the test host's extra slack.
    """
    if not hostname:
        return ENV_PROD
    lowered = hostname.lower()
    return ENV_TEST if any(token in lowered for token in _TEST_HOSTNAME_TOKENS) else ENV_PROD


__all__ = [
    "ENV_TEST",
    "ENV_PROD",
    "patch_tuesday",
    "test_patch_due_for",
    "prod_patch_due_for",
    "patch_due_for",
    "classify_environment",
]
