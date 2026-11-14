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
    # The SIEM connectors publish longer ids than the live-action vendor ids.
    # Without these aliases a tenant's Sentinel or QRadar credentials resolve
    # to an empty map and the writeback silently simulates.
    "microsoft_sentinel": "sentinel",
    "azure_sentinel": "sentinel",
    "ibm_qradar": "qradar",
    "splunk_enterprise": "splunk",
    "elasticsearch": "elastic",
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
    "sentinel": {
        # Sentinel addresses an incident by its full ARM path, so the
        # workspace coordinates are credentials in the sense that matters
        # here: without all six the client cannot be built at all.
        "tenant_id": "sentinel_tenant_id",
        "client_id": "sentinel_client_id",
        "client_secret": "sentinel_client_secret",
        "subscription_id": "sentinel_subscription_id",
        "resource_group": "sentinel_resource_group",
        "workspace_name": "sentinel_workspace_name",
    },
    "qradar": {
        "base_url": "qradar_url",
        "api_token": "qradar_token",
        "ssl_verify": "qradar_verify_ssl",
        # Deployment-specific and not guessable: QRadar refuses a close
        # without one, and every console defines its own set.
        "closing_reason_id": "qradar_closing_reason_id",
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


# Connector fields that decide **where** a request goes or **what secret** it
# presents. A caller may not supply the executor key translated from one of
# these: the tenant's stored configuration is the only source for them.
#
# The split is the whole control, so it is written out rather than guessed at
# by matching on substrings like "url" or "token" — `test_every_mapped_field_
# is_classified` fails the build when a field is added to VENDOR_CREDENTIAL_MAP
# without appearing in exactly one of these two sets. That gate is the half
# that matters: `_SPLUNK_KEYS` once listed `splunk_host`/`token`/`index` while
# the client factory read `splunk_url` plus basic-auth credentials, so a "dry
# run" called the customer's production Splunk. A hand-maintained list drifts;
# a hand-maintained list with an exhaustiveness gate cannot.
#
# `ssl_verify` is here because downgrading TLS verification is a redirection
# primitive in slow motion, and the scope locators (`zone_id`, `account_id`,
# `subscription_id`, `resource_group`, `workspace_name`, `region`) are here
# because they choose *whose* estate the tenant's credential acts on.
CONNECTION_OR_CREDENTIAL_FIELDS: frozenset[str] = frozenset(
    {
        # endpoints
        "base_url",
        "instance_url",
        "kibana_url",
        "domain",
        "host",
        # secrets
        "api_key",
        "api_token",
        "token",
        "client_id",
        "client_secret",
        "username",
        "password",
        "email",
        "access_key",
        "secret_key",
        "role_arn",
        "routing_key",
        "service_account_json",
        "admin_email",
        # transport trust
        "ssl_verify",
        # scope locators: which tenant/subscription/zone the credential acts on
        "tenant_id",
        "subscription_id",
        "resource_group",
        "workspace_name",
        "region",
        "zone_id",
        "account_id",
    }
)

# Connector fields that choose *what* an action does rather than where it goes
# or whose secret it spends. These are the reason ``extra`` exists at all, and
# a playbook step is entitled to pick them per run: which Jira project to file
# in, which PAN-OS tag to apply, which QRadar closing reason to record.
OPERATIONAL_FIELDS: frozenset[str] = frozenset(
    {
        "tag",
        "address_group",
        "project_key",
        "closing_reason_id",
    }
)


class ProtectedParameterOverride(ValueError):
    """A caller tried to supply a stored connection or credential field.

    Raised rather than silently dropped. Dropping would send the request to
    the vendor's default endpoint and report success — the "escaped value
    reaches the endpoint, matches nothing, reports success" failure this
    repository has shipped before, and the quieter of the two.
    """


def canonical_vendor(vendor_or_connector_id: str) -> str:
    """Resolve a connector_id or vendor_id to the live-actions vendor_id."""
    v = (vendor_or_connector_id or "").strip().lower()
    return CONNECTOR_TO_VENDOR.get(v, v)


def protected_param_keys(vendor_or_connector_id: str) -> frozenset[str]:
    """Executor param keys only the tenant's stored configuration may set.

    Derived from :data:`VENDOR_CREDENTIAL_MAP` rather than listed separately,
    so a vendor added to the map is covered without anyone remembering to
    extend a second list — which is exactly how the two halves of a pair like
    this drift apart.
    """
    mapping = VENDOR_CREDENTIAL_MAP.get(canonical_vendor(vendor_or_connector_id), {})
    return frozenset(key for field, key in mapping.items() if field in CONNECTION_OR_CREDENTIAL_FIELDS)


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
        ``target``). Merged on top of the translated credentials — but it may
        **not** carry a connection or credential key: see
        :func:`protected_param_keys`.

    Returns
    -------
    dict
        Executor-ready parameters. Fields not in the vendor map are dropped
        (an unknown credential field is never blindly forwarded), except that
        already-prefixed passthrough keys in ``auth_config`` (those matching an
        executor target key) are preserved so a caller can supply raw params.

    Raises
    ------
    ProtectedParameterOverride
        If ``extra`` names a key that decides the endpoint or the credential.
        ``extra`` reaches here from ``POST /playbook-steps/dispatch``, whose
        ``params`` dict any session holding ``actions:execute`` can fill, so
        letting it win over a translated field made the platform decrypt the
        tenant's secret and present it to a host the caller chose
        (GHSA-78jg-x2ch-638f). The stored value is authoritative, and the
        attempt is refused rather than dropped.
    """
    vendor = canonical_vendor(vendor_id)
    mapping = VENDOR_CREDENTIAL_MAP.get(vendor, {})
    out: dict[str, Any] = {}
    target_keys = set(mapping.values())

    protected = protected_param_keys(vendor)
    refused = sorted(key for key in (extra or {}) if key in protected)
    if refused:
        # The keys, never the values: `extra` is attacker-influenced and this
        # message is rendered into a dispatch report the console reads back.
        raise ProtectedParameterOverride(
            f"{', '.join(refused)} name{'s' if len(refused) == 1 else ''} stored "
            f"{vendor} connection or credential settings and cannot be supplied per action; "
            "the tenant's saved integration decides where an action goes and which credential it uses"
        )

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
