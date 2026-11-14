"""MSSP white-label platform (t5-mssp-whitelabel).

Public surface:

  - :class:`FleetEntry`              one row in an MSSP's fleet view
  - :class:`MsspBranding`            white-label config for the console
  - :func:`fleet_for_mssp`           fan out aggregates across child tenants
  - :func:`upsert_partner`           idempotently create/update the MSSP row
  - :func:`add_tenant_link`          hook a customer tenant under an MSSP
  - :func:`branding_for`             resolve white-label payload for a request

The service is read-mostly; writes happen via the platform admin
console (or the bootstrap script in dev). The aggregation path (the
fleet view) is what runs every time an MSSP analyst loads their
landing page, so it stays cheap and scoped to the MSSP's own
``allowed_tenants``.
"""
from app.mssp.service import (
    FleetEntry,
    MsspBranding,
    add_tenant_link,
    branding_for,
    fleet_for_mssp,
    list_links,
    remove_tenant_link,
    set_feature_flag,
    upsert_partner,
)

__all__ = [
    "FleetEntry",
    "MsspBranding",
    "add_tenant_link",
    "branding_for",
    "fleet_for_mssp",
    "list_links",
    "remove_tenant_link",
    "set_feature_flag",
    "upsert_partner",
]
