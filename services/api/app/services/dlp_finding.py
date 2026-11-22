"""The normalized DLP finding: one vocabulary over three vendors (WS4.1).

Netskope's DLP alert feed, Purview DLP and insider-risk alerts riding
Defender's ``alerts_v2``, and the M365 audit trail's ``DlpRuleMatch`` events
each arrive as their vendor shaped them, readable only through ``raw_event``.
This module derives the one domain object a triage prompt, the data-handling
strategy and a console panel can share: policy and rule, the data classes or
sensitivity labels involved, the file (name, hash, size), the channel, the
destination and its class, **what the DLP product itself already did**, and
the user and device.

Two rules, inherited verbatim from the phishing intake module (the house
precedent for "a domain object derived from several vendors' payloads"):

* **A field that was not in the payload is empty, never invented.** In
  particular ``destination_class`` is derived only from explicit vendor
  facts (Netskope's ``managed_app``); a vendor that said nothing yields
  ``None`` — "unmanaged" is a claim, not a default.
* **The vendor's own shape is the input.** Each profile maps fields the
  vendor documents: Netskope's DLP alert export (the fields below appear in
  Netskope's own published sample), the Office 365 Management Activity API's
  DLP schema (``PolicyDetails[].Rules[]``, the metadata complex types, and
  the EnforcementMode ladder the schema defines as 1=audit, 2=warn with
  override, 3=warn and bypass, 4=block, 5=allow), and Microsoft Graph
  ``security/alerts_v2`` evidence objects.

Enforcement collapses onto ``blocked | warned | allowed | audited``; an
outcome the vendor did not state stays ``None``. Purview's ``alerts_v2``
alert names the policy but not the per-event outcome — that is a ``None``,
not a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Enforcement = Literal["blocked", "warned", "allowed", "audited"]

DestinationClass = Literal[
    "corporate_tenant",
    "personal_account",
    "unmanaged_saas",
    "removable_media",
    "ai_app",
]


@dataclass(frozen=True)
class DlpFinding:
    """One DLP event in one vocabulary. Absent vendor facts are ``None``."""

    source: str
    policy: str | None = None
    rule: str | None = None
    severity: str | None = None
    data_classes: tuple[str, ...] = field(default_factory=tuple)
    file_name: str | None = None
    file_hash: str | None = None
    file_size: int | None = None
    channel: str | None = None
    destination: str | None = None
    destination_class: DestinationClass | None = None
    enforcement: Enforcement | None = None
    user: str | None = None
    device: str | None = None
    incident_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "policy": self.policy,
            "rule": self.rule,
            "severity": self.severity,
            "data_classes": list(self.data_classes),
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "channel": self.channel,
            "destination": self.destination,
            "destination_class": self.destination_class,
            "enforcement": self.enforcement,
            "user": self.user,
            "device": self.device,
            "incident_ref": self.incident_ref,
        }


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


# --- Netskope -------------------------------------------------------------

#: Netskope's enforcement vocabulary onto ours. ``alert`` is Netskope's
#: audit-only outcome; ``useralert`` warns the user and lets them proceed.
_NETSKOPE_ENFORCEMENT: dict[str, Enforcement] = {
    "block": "blocked",
    "allow": "allowed",
    "alert": "audited",
    "useralert": "warned",
    "user_alert": "warned",
}


def from_netskope(raw: dict[str, Any]) -> DlpFinding | None:
    """Netskope DLP alert → finding. Non-DLP alert types are not findings."""
    if _text(raw.get("alert_type")) not in ("DLP", "dlp"):
        return None

    data_classes: list[str] = []
    for label in raw.get("ext_labels") or []:
        name = _text(label.get("name")) if isinstance(label, dict) else None
        if name:
            data_classes.append(name)
    profile = _text(raw.get("dlp_profile"))
    if profile:
        data_classes.append(profile)

    managed = _text(raw.get("managed_app"))
    destination_class: DestinationClass | None = None
    if managed is not None:
        lowered = managed.lower()
        if lowered in ("yes", "true", "1"):
            destination_class = "corporate_tenant"
        elif lowered in ("no", "false", "0"):
            destination_class = "unmanaged_saas"

    action = (_text(raw.get("action")) or "").lower()

    return DlpFinding(
        source="netskope",
        policy=_text(raw.get("policy")) or _text(raw.get("alert_name")),
        rule=_text(raw.get("dlp_rule")),
        severity=_text(raw.get("dlp_rule_severity")),
        data_classes=tuple(dict.fromkeys(data_classes)),
        file_name=_text(raw.get("object")),
        file_hash=_text(raw.get("local_sha256")) or _text(raw.get("md5")),
        file_size=_int(raw.get("file_size")),
        channel=_text(raw.get("appcategory")) or _text(raw.get("traffic_type")),
        destination=_text(raw.get("app")) or _text(raw.get("url")),
        destination_class=destination_class,
        enforcement=_NETSKOPE_ENFORCEMENT.get(action),
        user=_text(raw.get("user")),
        device=_text(raw.get("device")),
        incident_ref=_text(raw.get("dlp_incident_id")),
    )


# --- Office 365 Management Activity (DLP.All / Audit.*) --------------------

#: The schema's own EnforcementMode ladder: "1/2/3/4/5 depicting
#: audit / warn (block with override) / warn and bypass / block / allow
#: (audit without alerts) respectively".
_M365_ENFORCEMENT_MODE: dict[int, Enforcement] = {
    1: "audited",
    2: "warned",
    3: "warned",
    4: "blocked",
    5: "allowed",
}

#: Rule Actions that state a blocking outcome in the DlpRuleMatch shape.
_M365_BLOCKING_ACTIONS = frozenset({"blockaccess", "blockemail", "restrictaccess"})

_DLP_OPERATIONS = frozenset({"dlprulematch", "dlpruleundo", "dlpinfo"})


def from_m365_audit(raw: dict[str, Any]) -> DlpFinding | None:
    """O365 Management Activity DLP event → finding."""
    operation = (_text(raw.get("Operation")) or "").lower()
    if operation not in _DLP_OPERATIONS:
        return None

    policies = raw.get("PolicyDetails") or []
    first_policy = policies[0] if policies and isinstance(policies[0], dict) else {}
    rules = first_policy.get("Rules") or []
    first_rule = rules[0] if rules and isinstance(rules[0], dict) else {}

    data_classes: list[str] = []
    for policy in policies:
        for rule in policy.get("Rules") or []:
            matched = (rule.get("ConditionsMatched") or {}).get("SensitiveInformation") or []
            for info in matched:
                name = _text(info.get("SensitiveInformationTypeName")) if isinstance(info, dict) else None
                if name:
                    data_classes.append(name)

    sharepoint = raw.get("SharePointMetaData") or {}
    exchange = raw.get("ExchangeMetaData") or {}
    endpoint = raw.get("EndpointMetaData") or {}
    for info in endpoint.get("SensitiveInformation") or []:
        name = _text(info.get("SensitiveInformationTypeName")) if isinstance(info, dict) else None
        if name:
            data_classes.append(name)

    enforcement: Enforcement | None = None
    mode = _int(endpoint.get("EnforcementMode"))
    if mode is not None:
        enforcement = _M365_ENFORCEMENT_MODE.get(mode)
    else:
        actions = {str(a).lower() for a in (first_rule.get("Actions") or [])}
        if actions & _M365_BLOCKING_ACTIONS:
            enforcement = "blocked"

    file_name = _text(sharepoint.get("FileName"))
    destination = _text(sharepoint.get("SiteCollectionUrl"))
    if not destination and exchange:
        recipients = [str(r) for r in (exchange.get("To") or [])]
        destination = ", ".join(recipients) or None
    if not file_name and exchange:
        file_name = _text(exchange.get("Subject"))

    return DlpFinding(
        source="m365_audit",
        policy=_text(first_policy.get("PolicyName")),
        rule=_text(first_rule.get("RuleName")),
        severity=_text(first_rule.get("Severity")),
        data_classes=tuple(dict.fromkeys(data_classes)),
        file_name=file_name,
        file_hash=None,  # the DLP schema carries no content hash
        file_size=None,
        channel=_text(raw.get("Workload")),
        destination=destination,
        destination_class=None,  # the schema states no managed/unmanaged fact
        enforcement=enforcement,
        user=_text(raw.get("UserId")),
        device=_text(endpoint.get("DeviceName")),
        incident_ref=_text(raw.get("Id")),
    )


# --- Microsoft Graph security/alerts_v2 (Purview DLP / insider risk) -------

_DEFENDER_DLP_SOURCES = frozenset({"microsoftdatalossprevention", "microsoftinsiderriskmanagement", "microsoftpurview"})


def from_defender(raw: dict[str, Any]) -> DlpFinding | None:
    """Purview DLP / insider-risk alert from ``alerts_v2`` → finding."""
    source = (_text(raw.get("serviceSource")) or "").lower()
    if source not in _DEFENDER_DLP_SOURCES:
        return None

    file_name = file_path = file_hash = None
    file_size = None
    user = device = None
    for item in raw.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        odata = str(item.get("@odata.type", ""))
        if odata.endswith("fileEvidence"):
            details = item.get("fileDetails") or {}
            file_name = file_name or _text(details.get("fileName"))
            file_path = file_path or _text(details.get("filePath"))
            file_hash = file_hash or _text(details.get("sha256")) or _text(details.get("sha1"))
            file_size = file_size if file_size is not None else _int(details.get("fileSize"))
        elif odata.endswith("userEvidence"):
            account = item.get("userAccount") or {}
            user = user or _text(account.get("userPrincipalName")) or _text(account.get("accountName"))
        elif odata.endswith("deviceEvidence"):
            device = device or _text(item.get("deviceDnsName"))

    return DlpFinding(
        source="azure_defender",
        policy=_text(raw.get("title")),
        rule=None,  # alerts_v2 does not carry the DLP rule name
        severity=_text(raw.get("severity")),
        data_classes=(),  # sensitive-type names do not ride the alert
        file_name=file_name,
        file_hash=file_hash,
        file_size=file_size,
        channel=_text(raw.get("category")),
        destination=file_path,
        destination_class=None,
        # The alerts_v2 record names the policy, not the per-event outcome.
        enforcement=None,
        user=user,
        device=device,
        incident_ref=_text(raw.get("id")),
    )


# --- Dispatch ---------------------------------------------------------------

_PROFILES = {
    "netskope": from_netskope,
    "m365_audit": from_m365_audit,
    "azure_defender": from_defender,
}


def normalise(connector_type: str, raw_event: dict[str, Any]) -> DlpFinding | None:
    """The finding for this alert, or ``None`` — never a guess.

    Keyed on the connector that raised the alert: a source without a profile
    yields ``None`` rather than a best-effort parse, because a finding that
    might describe a different vendor's field is worse than no finding.
    """
    profile = _PROFILES.get((connector_type or "").lower())
    if profile is None or not isinstance(raw_event, dict):
        return None
    return profile(raw_event)
