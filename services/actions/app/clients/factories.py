"""Credential → vendor-client factories, shared by executors and rollback.

These lived in `executors/endpoint.py`, `identity.py` and `network.py`. That
put them on the wrong side of a dependency edge: `app.services.rollback` needs
them to perform a real reverse action, and the executors need
`reverse_via_rollback_service` from `rollback` so a `rollback()` call actually
contacts the vendor instead of logging an intent and returning True. The result
was a cycle that had to be papered over with inline imports inside each
`rollback()` method, which CodeQL correctly flagged as `py/cyclic-import`.

There is nothing executor-specific about them — each one reads a resolved
credential bag and returns a configured client, or `None` when the credentials
are absent so the caller can take its simulation path. Moving them here points
both sides at a leaf module and lets every import sit at module scope.

The executor modules re-export these names, because `app.services.rollback` and
`app.services.verification` import them from there and tests monkeypatch e.g.
`verification._cs_client`. Keeping the old paths working means the refactor
does not move anyone's patch target.
"""

from __future__ import annotations

from app.clients.aws_security_groups import AWSSecurityGroupsClient
from app.clients.azure_entra_client import AzureEntraClient
from app.clients.cloudflare_client import CloudflareClient
from app.clients.cortex_xdr_client import CortexXdrClient
from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.clients.defender_client import DefenderClient
from app.clients.fortigate_client import FortiGateClient
from app.clients.google_workspace_client import GoogleWorkspaceClient
from app.clients.okta_client import OktaClient
from app.clients.panos_client import PanOsClient
from app.clients.sentinelone_client import SentinelOneClient


def _aws_client(params: dict) -> AWSSecurityGroupsClient | None:
    access_key = params.get("aws_access_key_id")
    secret_key = params.get("aws_secret_access_key")
    sg_id = params.get("aws_security_group_id")
    if not sg_id:
        return None
    return AWSSecurityGroupsClient(
        access_key_id=access_key,
        secret_access_key=secret_key,
        region=params.get("aws_region", "us-east-1"),
        role_arn=params.get("aws_role_arn"),
        session_name=params.get("aws_session_name", "aisoc-action"),
    )


def _cloudflare_client(params: dict) -> CloudflareClient | None:
    token = params.get("cf_api_token")
    if not token:
        return None
    return CloudflareClient(api_token=token)


def _cortex_client(params: dict) -> CortexXdrClient | None:
    """Build a Cortex XDR client from request-scoped credentials.

    Returns ``None`` when any field is missing so the executor falls through to
    the next vendor / simulation.
    """
    api_key_id = params.get("cortex_api_key_id")
    api_key = params.get("cortex_api_key")
    fqdn = params.get("cortex_fqdn")
    if not (api_key_id and api_key and fqdn):
        return None
    return CortexXdrClient(api_key_id=api_key_id, api_key=api_key, fqdn=fqdn)


def _cs_client(params: dict) -> CrowdStrikeRTRClient | None:
    client_id = params.get("cs_client_id")
    client_secret = params.get("cs_client_secret")
    if not (client_id and client_secret):
        return None
    return CrowdStrikeRTRClient(
        client_id=client_id,
        client_secret=client_secret,
        base_url=params.get("cs_base_url", "https://api.crowdstrike.com"),
    )


def _entra_client(params: dict) -> AzureEntraClient | None:
    tenant_id = params.get("azure_tenant_id")
    client_id = params.get("azure_client_id")
    client_secret = params.get("azure_client_secret")
    if not (tenant_id and client_id and client_secret):
        return None
    return AzureEntraClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def _fortigate_client(params: dict) -> FortiGateClient | None:
    host = params.get("fgt_host")
    token = params.get("fgt_api_token")
    group = params.get("fgt_address_group")
    if not (host and token and group):
        return None
    return FortiGateClient(
        host=host,
        api_token=token,
        vdom=params.get("fgt_vdom", "root"),
        verify_tls=bool(params.get("fgt_verify_tls", True)),
    )


def _gws_client(params: dict) -> GoogleWorkspaceClient | None:
    key = params.get("gws_service_account_key")
    subject = params.get("gws_subject_email")
    if not (key and subject):
        return None
    return GoogleWorkspaceClient(service_account_key=key, subject_email=subject)


def _mde_client(params: dict) -> DefenderClient | None:
    tenant_id = params.get("mde_tenant_id")
    client_id = params.get("mde_client_id")
    client_secret = params.get("mde_client_secret")
    if not (tenant_id and client_id and client_secret):
        return None
    return DefenderClient(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)


def _okta_client(params: dict) -> OktaClient | None:
    domain = params.get("okta_domain")
    api_token = params.get("okta_api_token")
    if not (domain and api_token):
        return None
    return OktaClient(domain=domain, api_token=api_token)


def _panos_client(params: dict) -> PanOsClient | None:
    """Build a PAN-OS client. Returns None if the minimum
    credentials are missing so the executor can fall through.
    """
    host = params.get("panos_host")
    api_key = params.get("panos_api_key")
    tag = params.get("panos_tag")
    if not (host and api_key and tag):
        return None
    return PanOsClient(
        host=host,
        api_key=api_key,
        vsys=params.get("panos_vsys", "vsys1"),
        verify_tls=bool(params.get("panos_verify_tls", True)),
    )


def _s1_client(params: dict) -> SentinelOneClient | None:
    """Build a SentinelOne client from ``ActionRequest.parameters``.

    Returns ``None`` when either field is missing so the executor
    can cleanly fall through to the next vendor / simulation. We
    don't pull the API token out of an env var here — the dispatcher
    intentionally treats every credential as request-scoped so that
    multi-tenant deployments can route different tenants to
    different S1 consoles in the same process.
    """
    console_url = params.get("s1_console_url")
    api_token = params.get("s1_api_token")
    if not (console_url and api_token):
        return None
    return SentinelOneClient(console_url=console_url, api_token=api_token)


__all__ = [
    "_aws_client",
    "_cloudflare_client",
    "_cortex_client",
    "_cs_client",
    "_entra_client",
    "_fortigate_client",
    "_gws_client",
    "_mde_client",
    "_okta_client",
    "_panos_client",
    "_s1_client",
]
