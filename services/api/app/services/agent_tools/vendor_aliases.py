"""How a read executor's vendor id maps to the connectors a tenant saves.

Why the two differ at all
-------------------------
A read executor is named for the **product** it drives: ``defender``,
``entra``, ``aws``. A connector is named for the **integration** a tenant
configures, which is more specific because one vendor ships several: Microsoft
has ``azure_defender`` and ``azure_entra``, AWS has ``aws_cloudtrail``,
``aws_guardduty``, ``aws_securityhub`` and ``aws_vpc_flow_logs``.

Both namings are reasonable and neither is going to win, so the mapping is
written down instead of assumed.

What went wrong without it
--------------------------
``vendor_reads.available_reads`` resolved the two with ``by_type.get(vendor_id)``.
For four of the seven executors the strings happened to be identical and it
worked. For ``defender``, ``entra`` and ``aws`` it returned ``None`` on every
tenant, so the tool was never bound and a model investigating a Defender host,
an Entra identity or a CloudTrail event was told the tenant had no integration
for it. Three of the five vendors added in gap-closure 4.2 had never once been
offered.

The lookup that missed is the same expression as the lookup that hits, which is
why nothing failed. ``scripts/check_vendor_catalog_ids.py`` now fails CI when a
vendor id resolves to no saveable connector type, in both directions.

Order matters
-------------
The tuples are in preference order. ``aws`` reads a cloud audit trail, so
``aws_cloudtrail`` comes first; a tenant with both CloudTrail and GuardDuty
gets the one that answers the question the capability asks.
"""

from __future__ import annotations

from typing import TypeVar

#: Generic over the mapping's value so a caller keeps its own row type. A
#: bare ``object`` here made every attribute read on the result an error at
#: the call site, which is the type system correctly objecting to a helper
#: that threw away what it was given.
_T = TypeVar("_T")

#: ``executor vendor id -> catalog connector types, most preferred first``.
#:
#: An entry is only needed where the two names differ. The four that already
#: agree (``crowdstrike``, ``okta``, ``sentinelone``, ``google_workspace``)
#: are deliberately absent, so this map stays a list of exceptions rather than
#: a second copy of the catalog that drifts from it.
VENDOR_CONNECTOR_TYPES: dict[str, tuple[str, ...]] = {
    "defender": ("azure_defender",),
    "entra": ("azure_entra",),
    "aws": ("aws_cloudtrail", "aws_guardduty", "aws_security_hub"),
}


def connector_types_for(vendor_id: str) -> tuple[str, ...]:
    """Every connector type that can serve this executor, most preferred first.

    A vendor with no alias resolves to itself, which is the common case and
    keeps the map to exceptions only.
    """
    return VENDOR_CONNECTOR_TYPES.get(vendor_id, (vendor_id,))


def resolve(vendor_id: str, by_type: dict[str, _T]) -> _T | None:
    """The tenant's connector for this executor, or ``None``.

    One helper rather than the same two lines at each of the three call sites
    that need it: ``vendor_reads.available_reads``,
    ``playbook_step_dispatch._pick_connector`` and live-action dispatch. The
    reason this module exists is that a lookup was written three times and got
    it wrong in the same way each time.
    """
    for connector_type in connector_types_for(vendor_id):
        found = by_type.get(connector_type)
        if found is not None:
            return found
    return None
