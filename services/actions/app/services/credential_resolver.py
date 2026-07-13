"""Map connector credentials onto SOAR executor parameters (Phase B2).

The reality audit's SOAR wiring gap: the response executors read
vendor-prefixed keys from ``ActionRequest.parameters`` (CrowdStrike wants
``cs_client_id``; Okta wants ``okta_domain``; Splunk wants ``splunk_url`` …),
but a tenant configures a connector with *schema* field names (``client_id``,
``domain``, ``base_url`` …). Nothing translated one to the other, so even a
fully-configured connector's credentials never reached the executor and every
action fell back to ``Simulation mode``.

This module is that translation layer. Given a live ``vendor_id``, a connector's
decrypted ``auth_config``, and any per-action operational params (target host,
AWS security-group id, PAN-OS tag …), :func:`resolve_params` produces the
prefixed parameter dict the executor expects.

The map is intentionally explicit (not a heuristic): a wrong credential mapping
is a silent security/reliability bug, so every vendor's field translation is
written out and unit-tested. Connector-id → live-vendor-id aliases handle the
cases where they differ (``aws_security_hub`` connector → ``aws_security_groups``
live vendor; ``azure_defender`` → ``defender``).
"""

from __future__ import annotations

from typing import Any

# Connector ``connector_id`` -> live-actions ``vendor_id`` when they differ.
CONNECTOR_TO_VENDOR: dict[str, str] = {
    "aws_security_hub": "aws_security_groups",
    "aws_guardduty": "aws_security_groups",
    "azure_defender": "defender",
}

# live vendor_id -> {connector auth_config field : executor param key}.
# Only credential/config fields; per-action operational params are merged
# separately in resolve_params (e.g. target host, aws_security_group_id).
VENDOR_CREDENTIAL_MAP: dict[str, dict[str, str]] = {
    "crowdstrike": {
        "client_id": "cs_client_id",
        "client_secret": "cs_client_secret",
        "base_url": "cs_base_url",
    },
    "defender": {
        "tenant_id": "mde_tenant_id",
        "client_id": "mde_client_id",
        "client_secret": "mde_client_secret",
    },
    "sentinelone": {
        "api_token": "s1_api_token",
        "base_url": "s1_console_url",
    },
    "okta": {
        "domain": "okta_domain",
        "api_token": "okta_api_token",
    },
    "azure_entra": {
        "tenant_id": "azure_tenant_id",
        "client_id": "azure_client_id",
        "client_secret": "azure_client_secret",
    },
    "google_workspace": {
        "service_account_json": "gws_service_account_key",
        "admin_email": "gws_subject_email",
    },
    "aws_security_groups": {
        "access_key": "aws_access_key_id",
        "secret_key": "aws_secret_access_key",
        "region": "aws_region",
        "role_arn": "aws_role_arn",
    },
    "panos": {
        "host": "panos_host",
        "api_key": "panos_api_key",
        "tag": "panos_tag",
    },
    "fortigate": {
        "host": "fgt_host",
        "api_token": "fgt_api_token",
        "address_group": "fgt_address_group",
    },
    "cloudflare": {
        "api_token": "cf_api_token",
        "zone_id": "cf_zone_id",
        "account_id": "cf_account_id",
    },
    "splunk": {
        "base_url": "splunk_url",
        "token": "splunk_token",
        "username": "splunk_username",
        "password": "splunk_password",
        "ssl_verify": "splunk_verify_ssl",
    },
    "elastic": {
        "base_url": "elastic_url",
        "api_key": "elastic_api_key",
        "username": "elastic_username",
        "password": "elastic_password",
        "kibana_url": "kibana_url",
    },
    "jira": {
        "base_url": "jira_base_url",
        "email": "jira_email",
        "api_token": "jira_api_token",
        "project_key": "jira_project_key",
    },
    "servicenow": {
        "instance_url": "snow_instance_url",
        "username": "snow_username",
        "password": "snow_password",
    },
    "pagerduty": {
        # The connector stores a REST api_key; the executor needs the Events
        # API v2 routing key. They are different secrets — a tenant that wants
        # live PagerDuty ticketing must supply `routing_key` in auth_config.
        "routing_key": "pd_routing_key",
    },
}


def canonical_vendor(vendor_or_connector_id: str) -> str:
    """Resolve a connector_id or vendor_id to the live-actions vendor_id."""
    v = (vendor_or_connector_id or "").strip().lower()
    return CONNECTOR_TO_VENDOR.get(v, v)


def resolve_params(
    vendor_id: str,
    auth_config: dict[str, Any] | None,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate connector ``auth_config`` into executor parameters.

    Parameters
    ----------
    vendor_id:
        A live ``vendor_id`` or a connector ``connector_id`` (aliased via
        :data:`CONNECTOR_TO_VENDOR`).
    auth_config:
        The connector's decrypted credential dict (schema field names).
    extra:
        Per-action operational params already in executor-key form (e.g.
        ``aws_security_group_id``, ``panos_tag``, ``jira_project_key``,
        ``target``). Merged on top of the translated credentials; a key here
        overrides a translated one.

    Returns
    -------
    dict
        Executor-ready parameters. Fields not in the vendor map are dropped
        (an unknown credential field is never blindly forwarded), except that
        already-prefixed passthrough keys in ``auth_config`` (those matching an
        executor target key) are preserved so a caller can supply raw params.
    """
    vendor = canonical_vendor(vendor_id)
    mapping = VENDOR_CREDENTIAL_MAP.get(vendor, {})
    out: dict[str, Any] = {}
    target_keys = set(mapping.values())

    for field, value in (auth_config or {}).items():
        if value is None:
            continue
        if field in mapping:
            out[mapping[field]] = value
        elif field in target_keys:
            # Caller already supplied a prefixed key — pass it through.
            out[field] = value

    for key, value in (extra or {}).items():
        if value is not None:
            out[key] = value
    return out


def known_vendors() -> list[str]:
    return sorted(VENDOR_CREDENTIAL_MAP)
