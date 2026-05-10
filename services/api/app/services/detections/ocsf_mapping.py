"""OCSF v1.1 mapping for Sigma rules (WS-B1).

When we import a Sigma rule we want to record, alongside the rule itself,
the OCSF event class it most likely fires against. That lets the rest of
AiSOC reason about coverage in OCSF terms ("how many Authentication
findings can we generate today?") without re-parsing the rule body.

The mapping is intentionally conservative:

* We map ``logsource`` (the canonical Sigma classifier) to a single OCSF
  ``class_uid``/``category_uid`` pair. Sigma's logsource taxonomy is
  more fine-grained than OCSF's class taxonomy, so a one-to-many spread
  would create ambiguity in coverage reporting.
* When a Sigma rule's logsource doesn't fit anywhere obvious we fall
  back to ``DETECTION_FINDING`` (class_uid 2004), which is the OCSF
  catch-all for "a detection rule fired and we don't have a more
  specific class".

These constants mirror the TypeScript enums in
``packages/ocsf/src/types.ts``. Keep them in sync if OCSF ever adds new
class UIDs we care about.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# ─── Class / Category UIDs (mirrors packages/ocsf/src/types.ts) ──────────────


class OcsfClassUid:
    """OCSF v1.1 class UIDs we currently auto-map to."""

    FILE_ACTIVITY: Final[int] = 1001
    PROCESS_ACTIVITY: Final[int] = 1007
    SECURITY_FINDING: Final[int] = 2001
    VULNERABILITY_FINDING: Final[int] = 2002
    COMPLIANCE_FINDING: Final[int] = 2003
    DETECTION_FINDING: Final[int] = 2004
    AUTHENTICATION: Final[int] = 3002
    NETWORK_ACTIVITY: Final[int] = 4001
    HTTP_ACTIVITY: Final[int] = 4002
    DNS_ACTIVITY: Final[int] = 4003


class OcsfCategoryUid:
    """OCSF v1.1 category UIDs."""

    SYSTEM_ACTIVITY: Final[int] = 1
    FINDINGS: Final[int] = 2
    IDENTITY_ACTIVITY: Final[int] = 3
    NETWORK_ACTIVITY: Final[int] = 4
    DISCOVERY: Final[int] = 5
    APPLICATION_ACTIVITY: Final[int] = 6


@dataclass(frozen=True, slots=True)
class OcsfClassRef:
    """Compact OCSF class reference attached to an imported rule.

    We store this on the rule (under ``provenance['ocsf']``) rather than
    deriving it on every coverage query — the mapping is stable across
    rule edits and the lookup is otherwise O(rules) per UI render.
    """

    class_uid: int
    class_name: str
    category_uid: int
    category_name: str

    def to_dict(self) -> dict[str, int | str]:
        return {
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "category_uid": self.category_uid,
            "category_name": self.category_name,
        }


# ─── Class metadata (UID → human label) ──────────────────────────────────────

_CLASS_METADATA: Final[dict[int, tuple[str, int, str]]] = {
    # class_uid: (class_name, category_uid, category_name)
    OcsfClassUid.FILE_ACTIVITY: ("File Activity", OcsfCategoryUid.SYSTEM_ACTIVITY, "System Activity"),
    OcsfClassUid.PROCESS_ACTIVITY: ("Process Activity", OcsfCategoryUid.SYSTEM_ACTIVITY, "System Activity"),
    OcsfClassUid.SECURITY_FINDING: ("Security Finding", OcsfCategoryUid.FINDINGS, "Findings"),
    OcsfClassUid.DETECTION_FINDING: ("Detection Finding", OcsfCategoryUid.FINDINGS, "Findings"),
    OcsfClassUid.AUTHENTICATION: ("Authentication", OcsfCategoryUid.IDENTITY_ACTIVITY, "Identity & Access Management"),
    OcsfClassUid.NETWORK_ACTIVITY: ("Network Activity", OcsfCategoryUid.NETWORK_ACTIVITY, "Network Activity"),
    OcsfClassUid.HTTP_ACTIVITY: ("HTTP Activity", OcsfCategoryUid.NETWORK_ACTIVITY, "Network Activity"),
    OcsfClassUid.DNS_ACTIVITY: ("DNS Activity", OcsfCategoryUid.NETWORK_ACTIVITY, "Network Activity"),
}


def _make_ref(class_uid: int) -> OcsfClassRef:
    name, cat_uid, cat_name = _CLASS_METADATA[class_uid]
    return OcsfClassRef(class_uid=class_uid, class_name=name, category_uid=cat_uid, category_name=cat_name)


# ─── Sigma logsource → OCSF class lookup tables ──────────────────────────────
#
# The Sigma logsource block has up to three keys:
#
#     product:  the product family   (windows, linux, macos, aws, azure, ...)
#     category: what kind of event   (process_creation, file_event, ...)
#     service:  the specific source  (security, sysmon, sshd, cloudtrail, ...)
#
# We resolve in this order: (product, category) → (product, service) →
# (category alone) → fallback. Most Sigma rules carry product+category;
# cloud rules tend to use product+service (service=cloudtrail, etc.).

# (product, category) → class_uid. Most-specific match.
_PRODUCT_CATEGORY: Final[dict[tuple[str, str], int]] = {
    ("windows", "process_creation"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "process_access"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "process_termination"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "image_load"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "file_event"): OcsfClassUid.FILE_ACTIVITY,
    ("windows", "file_change"): OcsfClassUid.FILE_ACTIVITY,
    ("windows", "file_delete"): OcsfClassUid.FILE_ACTIVITY,
    ("windows", "file_rename"): OcsfClassUid.FILE_ACTIVITY,
    ("windows", "registry_event"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "registry_set"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "registry_add"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "registry_delete"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "network_connection"): OcsfClassUid.NETWORK_ACTIVITY,
    ("windows", "dns_query"): OcsfClassUid.DNS_ACTIVITY,
    ("windows", "pipe_created"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "wmi_event"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "create_remote_thread"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "raw_access_thread"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "driver_load"): OcsfClassUid.SECURITY_FINDING,
    ("linux", "process_creation"): OcsfClassUid.PROCESS_ACTIVITY,
    ("linux", "file_event"): OcsfClassUid.FILE_ACTIVITY,
    ("linux", "network_connection"): OcsfClassUid.NETWORK_ACTIVITY,
    ("macos", "process_creation"): OcsfClassUid.PROCESS_ACTIVITY,
    ("macos", "file_event"): OcsfClassUid.FILE_ACTIVITY,
    ("macos", "network_connection"): OcsfClassUid.NETWORK_ACTIVITY,
}

# (product, service) → class_uid. Used when category is missing (cloud rules).
_PRODUCT_SERVICE: Final[dict[tuple[str, str], int]] = {
    ("aws", "cloudtrail"): OcsfClassUid.SECURITY_FINDING,
    ("aws", "guardduty"): OcsfClassUid.SECURITY_FINDING,
    ("aws", "s3"): OcsfClassUid.SECURITY_FINDING,
    ("azure", "auditlogs"): OcsfClassUid.SECURITY_FINDING,
    ("azure", "signinlogs"): OcsfClassUid.AUTHENTICATION,
    ("azure", "activitylogs"): OcsfClassUid.SECURITY_FINDING,
    ("azure", "riskydetection"): OcsfClassUid.AUTHENTICATION,
    ("azure", "operationalmetrics"): OcsfClassUid.SECURITY_FINDING,
    ("gcp", "google_workspace.admin"): OcsfClassUid.SECURITY_FINDING,
    ("gcp", "gcp.audit"): OcsfClassUid.SECURITY_FINDING,
    ("okta", "okta"): OcsfClassUid.AUTHENTICATION,
    ("microsoft365", "exchange"): OcsfClassUid.SECURITY_FINDING,
    ("microsoft365", "threat_management"): OcsfClassUid.SECURITY_FINDING,
    ("github", "audit"): OcsfClassUid.SECURITY_FINDING,
    ("kubernetes", "audit"): OcsfClassUid.SECURITY_FINDING,
    ("windows", "security"): OcsfClassUid.AUTHENTICATION,  # 4624/4625/4672
    ("windows", "sysmon"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "powershell"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "powershell-classic"): OcsfClassUid.PROCESS_ACTIVITY,
    ("windows", "system"): OcsfClassUid.SECURITY_FINDING,
    ("linux", "auditd"): OcsfClassUid.PROCESS_ACTIVITY,
    ("linux", "auth"): OcsfClassUid.AUTHENTICATION,
    ("linux", "syslog"): OcsfClassUid.SECURITY_FINDING,
    ("linux", "sshd"): OcsfClassUid.AUTHENTICATION,
}

# Category-only fallback. Used when product is unknown but the category
# itself is descriptive enough to commit to a class.
_CATEGORY_ONLY: Final[dict[str, int]] = {
    "process_creation": OcsfClassUid.PROCESS_ACTIVITY,
    "process_access": OcsfClassUid.PROCESS_ACTIVITY,
    "image_load": OcsfClassUid.PROCESS_ACTIVITY,
    "file_event": OcsfClassUid.FILE_ACTIVITY,
    "file_change": OcsfClassUid.FILE_ACTIVITY,
    "file_delete": OcsfClassUid.FILE_ACTIVITY,
    "network_connection": OcsfClassUid.NETWORK_ACTIVITY,
    "dns": OcsfClassUid.DNS_ACTIVITY,
    "dns_query": OcsfClassUid.DNS_ACTIVITY,
    "webserver": OcsfClassUid.HTTP_ACTIVITY,
    "proxy": OcsfClassUid.HTTP_ACTIVITY,
    "firewall": OcsfClassUid.NETWORK_ACTIVITY,
    "antivirus": OcsfClassUid.SECURITY_FINDING,
    "authentication": OcsfClassUid.AUTHENTICATION,
}


def map_logsource_to_ocsf(logsource: dict | None) -> OcsfClassRef:
    """Map a Sigma ``logsource`` block to an OCSF class reference.

    Falls back to :pyattr:`OcsfClassUid.DETECTION_FINDING` when the
    logsource is empty or doesn't match any known taxonomy. We never
    raise — a missing/odd logsource is *common* in community rules and
    should not break a bulk import.

    Lookup precedence:

    1. ``(product, category)`` — the most specific signal. Covers the
       bulk of Windows/Linux/macOS endpoint rules.
    2. ``(product, service)`` — used when category is missing, which
       is the norm for cloud rules (``service: cloudtrail`` etc.).
    3. ``category`` alone — covers product-agnostic rules.
    4. Detection Finding fallback.
    """
    if not isinstance(logsource, dict):
        return _make_ref(OcsfClassUid.DETECTION_FINDING)

    product = (logsource.get("product") or "").strip().lower() or None
    category = (logsource.get("category") or "").strip().lower() or None
    service = (logsource.get("service") or "").strip().lower() or None

    if product and category:
        class_uid = _PRODUCT_CATEGORY.get((product, category))
        if class_uid is not None:
            return _make_ref(class_uid)

    if product and service:
        class_uid = _PRODUCT_SERVICE.get((product, service))
        if class_uid is not None:
            return _make_ref(class_uid)

    if category:
        class_uid = _CATEGORY_ONLY.get(category)
        if class_uid is not None:
            return _make_ref(class_uid)

    return _make_ref(OcsfClassUid.DETECTION_FINDING)


__all__ = [
    "OcsfCategoryUid",
    "OcsfClassRef",
    "OcsfClassUid",
    "map_logsource_to_ocsf",
]
