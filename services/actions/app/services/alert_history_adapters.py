"""Reader rows in the shape the production connector ``normalize()`` reads.

Fix-pass item 3.3.

:class:`~app.services.alert_history.ClosedFinding` carries ``raw`` so the
replay runner can hand it to the same ``normalize()`` production uses, rather
than normalizing a second way and grading the agent on an input shape it never
sees. That only works if the two agree about the row, and for two vendors they
did not: a reader and its connector read **different endpoints of the same
product**, and the connector's field lookups all missed.

The failure is silent, which is what makes it worth a module. Nothing raises —
every ``raw.get(...)`` simply returns ``None``, so the finding reaches triage
with a placeholder title, the connector's default severity and no host or
user, and the agent is graded on an alert that describes nobody.

Where the two endpoints differ, and where they do not
-----------------------------------------------------
======== ===================================== =====================================
Source   Reader endpoint                       Connector endpoint
======== ===================================== =====================================
splunk   ``/services/search/jobs`` review SPL   the deployment's saved search
sentinel ARM ``…/incidents``                    ARM ``…/incidents``
elastic  ``<index>/_search`` (hits)             ES|QL over the alerts index
qradar   ``/api/siem/offenses``                 ``/api/siem/offenses``
defender ``api.securitycenter…/api/alerts``     Graph ``alerts_v2``
======== ===================================== =====================================

Three of the five read the same resource their connector polls, so their
adapters pass the row through and say so. Writing a translation where none is
needed would be a second mapping to keep in step with the first, which is the
duplication :mod:`app.services.alert_history` exists to avoid. The two that do
translate are the two the fix-pass names.

What an adapter will not do
---------------------------
It will not add a field the vendor did not send. An adapter renames, lifts and
restructures what the reader read; a value that is absent stays absent, and
the triage input carries an empty host rather than a plausible one. A
fabricated entity on a record an analyst uses to decide containment is worse
than a missing one, because only one of the two is visible.

Vendor references, read before these mappings were written:

* Defender for Endpoint alert resource
  — https://learn.microsoft.com/en-us/defender-endpoint/api/alerts
* Microsoft Graph ``alerts_v2`` alert, ``userEvidence`` and ``deviceEvidence``
  — https://learn.microsoft.com/en-us/graph/api/resources/security-alert
* Elastic Security detection alert schema
  — https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "ADAPTERS",
    "adapt_defender_alert",
    "adapt_elastic_signal",
    "adapt_qradar_offense",
    "adapt_sentinel_incident",
    "adapt_splunk_notable",
]

#: Every alert on the Defender for Endpoint alerts endpoint came from Defender
#: for Endpoint, so Graph's ``serviceSource`` is a property of the endpoint the
#: reader called rather than something inferred from the row.
_MDE_SERVICE_SOURCE = "microsoftDefenderForEndpoint"

#: Graph spells its evidence subtypes in ``@odata.type``; Defender for Endpoint
#: spells them in ``entityType``. Only these two are translated because they
#: are the two the connector reads. The rest are carried verbatim below.
_USER_EVIDENCE = "#microsoft.graph.security.userEvidence"
_DEVICE_EVIDENCE = "#microsoft.graph.security.deviceEvidence"


def _first(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def adapt_splunk_notable(row: Mapping[str, Any]) -> dict[str, Any]:
    """Name the notable's title the way a saved-search row names it.

    Both endpoints return a Splunk search result, so the row is already the
    right kind of thing. One column disagrees: Enterprise Security's review
    data calls the correlation search ``rule_name`` while a saved-search feed
    calls it ``search_name``, which is what the connector reads — so without
    this every replayed notable was titled "Splunk Notable Event".

    The asset and identity columns are left exactly as Splunk sent them. They
    are standard notable fields and the connector reads them directly.
    """
    adapted = dict(row)
    if not adapted.get("search_name") and adapted.get("rule_name"):
        adapted["search_name"] = adapted["rule_name"]
    return adapted


def adapt_sentinel_incident(row: Mapping[str, Any]) -> dict[str, Any]:
    """Pass through: the reader and the connector both read ARM incidents.

    ``entities`` rides along when the reader resolved it. It is not a property
    of the incident resource — it is the response of the incident's entities
    endpoint — so it is absent on a plain incident read and the connector
    treats it as optional.
    """
    return dict(row)


def adapt_elastic_signal(row: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten a ``_search`` hit into the document the connector reads.

    The reader keeps whole hits because ``_id`` is the signal's identity and
    lives on the envelope, not in ``_source``. The connector reads a flat
    document, so against a hit every lookup missed: the rule name, the
    severity and the timestamp are all one level down.

    Severity is the one that mattered most. ``normalize()`` falls back to
    ``medium`` when it cannot find a value, so a ``critical`` signal reached
    triage as a mid-grade one and nothing in the record said it had been
    downgraded.

    ``_id`` and ``_index`` are kept alongside the flattened source rather than
    dropped: the connector's identity fallback is ``_id``, and an operator
    reading ``raw_event`` needs to know which index the signal came from.
    """
    source = row.get("_source")
    flat: dict[str, Any] = dict(source) if isinstance(source, Mapping) else {}
    for envelope_key in ("_id", "_index"):
        if row.get(envelope_key) is not None:
            flat.setdefault(envelope_key, row[envelope_key])
    return flat


def adapt_qradar_offense(row: Mapping[str, Any]) -> dict[str, Any]:
    """Pass through: the reader and the connector both read ``/siem/offenses``.

    ``closing_reason_name`` and ``offense_type_name`` ride along. Neither is an
    offense field — an offense carries only the numeric ids, and the reader
    resolves both against the appliance because QRadar lets a site define its
    own closing reasons and offense types.
    """
    return dict(row)


def adapt_defender_alert(row: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild a Defender for Endpoint alert in the Graph ``alerts_v2`` shape.

    The two APIs describe the same alert and disagree about almost every name
    that matters here. The timestamps are the simple half
    (``alertCreationTime`` against ``createdDateTime``); evidence is the half
    that lost the host and the user. Defender for Endpoint tags an evidence
    entry with ``entityType`` and puts the account fields on the entry itself;
    Graph tags it with ``@odata.type`` and nests the account under
    ``userAccount``. The connector matches on ``@odata.type``, so no entry ever
    matched and both ``actor`` and ``host`` came out ``None``.

    The device entry is built from ``computerDnsName`` rather than from
    evidence. Defender for Endpoint reports the alert's machine on the alert
    itself, and an alert can carry file and process evidence without carrying a
    device entity at all.

    Evidence entries that are neither a user nor a device are carried through
    **unchanged**, keeping their Defender for Endpoint shape. The connector
    ignores them, they remain readable in ``raw_event``, and transliterating
    them would mean asserting per-type field mappings nothing here reads.
    ``classification`` and ``determination`` are carried verbatim for the same
    reason: the two vocabularies are not a lexical transform of one another
    (Defender for Endpoint's "Informational, expected activity" against
    Graph's ``informationalExpectedActivity``), and inventing the translation
    would put a guessed verdict next to the analyst's real one.
    """
    adapted = {k: v for k, v in row.items() if k not in {"evidence", "relatedUser", "incidentId"}}

    adapted["serviceSource"] = _MDE_SERVICE_SOURCE
    if row.get("incidentId") is not None:
        adapted["incidentId"] = str(row["incidentId"])
    for mde_key, graph_key in (
        ("alertCreationTime", "createdDateTime"),
        ("lastUpdateTime", "lastUpdateDateTime"),
        ("resolvedTime", "resolvedDateTime"),
        ("firstEventTime", "firstActivityDateTime"),
        ("lastEventTime", "lastActivityDateTime"),
    ):
        if row.get(mde_key) is not None:
            adapted[graph_key] = row[mde_key]

    evidence: list[dict[str, Any]] = []
    user_account = _mde_user_account(row)
    if user_account:
        evidence.append({"@odata.type": _USER_EVIDENCE, "userAccount": user_account})
    device = _mde_device(row)
    if device:
        evidence.append(device)
    evidence.extend(entry for entry in row.get("evidence") or [] if isinstance(entry, dict) and not _is_user_entity(entry))
    if evidence:
        adapted["evidence"] = evidence
    return adapted


def _is_user_entity(entry: Mapping[str, Any]) -> bool:
    return str(entry.get("entityType") or "").lower() == "user"


def _mde_user_account(row: Mapping[str, Any]) -> dict[str, Any]:
    """Collect the account fields Graph nests under ``userEvidence.userAccount``.

    ``relatedUser`` is the alert's own account and carries only a name and a
    domain; the ``User`` evidence entry carries the UPN and the SID. Both are
    read because a Defender for Endpoint alert can have either, and a merge
    rather than a choice avoids an alert losing its UPN because it also had a
    ``relatedUser``.
    """
    related = row.get("relatedUser")
    related = related if isinstance(related, Mapping) else {}
    entry: Mapping[str, Any] = next(
        (e for e in row.get("evidence") or [] if isinstance(e, Mapping) and _is_user_entity(e)),
        {},
    )

    account_name = _first(related, "userName") or _first(entry, "accountName")
    if not account_name and not _first(entry, "userPrincipalName"):
        return {}
    account = {
        "accountName": account_name,
        "domainName": _first(related, "domainName") or _first(entry, "domainName"),
        "userPrincipalName": _first(entry, "userPrincipalName"),
        "userSid": _first(entry, "userSid"),
        "azureAdUserId": _first(entry, "aadUserId"),
    }
    # Graph's own `displayName` has no Defender for Endpoint counterpart; the
    # connector prefers it over `accountName`, so leaving it unset keeps the
    # account name the connector reports rather than inventing a display name.
    return {k: v for k, v in account.items() if v}


def _mde_device(row: Mapping[str, Any]) -> dict[str, Any]:
    dns_name = _first(row, "computerDnsName")
    machine_id = _first(row, "machineId")
    if not dns_name and not machine_id:
        return {}
    device: dict[str, Any] = {"@odata.type": _DEVICE_EVIDENCE}
    if dns_name:
        device["deviceDnsName"] = dns_name
        # Graph's `hostName` is the label without the domain suffix.
        device["hostName"] = str(dns_name).split(".", 1)[0]
    if machine_id:
        device["mdeDeviceId"] = machine_id
    if row.get("rbacGroupName"):
        device["rbacGroupName"] = row["rbacGroupName"]
    return device


#: Keyed by the vendor name :class:`~app.services.alert_history.ClosedFinding`
#: records, so a vendor added to the readers without an adapter is a
#: ``KeyError`` at the one call site rather than a row that reaches triage
#: shaped for nobody.
ADAPTERS = {
    "splunk": adapt_splunk_notable,
    "sentinel": adapt_sentinel_incident,
    "elastic": adapt_elastic_signal,
    "qradar": adapt_qradar_offense,
    "defender": adapt_defender_alert,
}
