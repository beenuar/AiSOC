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

from app.clients.aws_cloudtrail_client import AWSCloudTrailClient
from app.clients.aws_iam_client import AWSIAMClient
from app.clients.aws_security_groups import AWSSecurityGroupsClient
from app.clients.azure_entra_client import AzureEntraClient
from app.clients.cloudflare_client import CloudflareClient
from app.clients.cortex_xdr_client import CortexXdrClient
from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.clients.defender_client import DefenderClient
from app.clients.fortigate_client import FortiGateClient
from app.clients.gcp_iam_client import GCPIAMClient
from app.clients.github_client import GitHubClient
from app.clients.gmail_client import GmailClient
from app.clients.google_workspace_client import GoogleWorkspaceClient
from app.clients.m365_mail_client import M365MailClient
from app.clients.okta_client import OktaClient
from app.clients.onepassword_client import OnePasswordClient
from app.clients.panos_client import PanOsClient
from app.clients.salesforce_client import SalesforceClient
from app.clients.sentinelone_client import SentinelOneClient
from app.clients.slack_admin_client import SlackAdminClient
from app.clients.snowflake_client import SnowflakeClient
from app.clients.swg_clients import NetskopeClient, ZscalerClient


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


def _cloudtrail_client(params: dict) -> AWSCloudTrailClient | None:
    """Build a CloudTrail read client from request-scoped credentials.

    Separate from ``_aws_client`` on purpose. That factory returns ``None``
    unless ``aws_security_group_id`` is present, which is correct for a
    firewall action and wrong for an audit read: a tenant with AWS keys and no
    security group would have had a CloudTrail verb answer "credentials not
    configured" while holding perfectly good credentials.
    """
    access_key = params.get("aws_access_key_id")
    secret_key = params.get("aws_secret_access_key")
    if not (access_key and secret_key):
        return None
    return AWSCloudTrailClient(
        access_key_id=str(access_key),
        secret_access_key=str(secret_key),
        region=str(params.get("aws_region") or "us-east-1"),
        session_token=params.get("aws_session_token"),
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


def _m365_mail_client(params: dict) -> M365MailClient | None:
    """Mailbox client from the same three fields the Entra client reads.

    Deliberately the same credential names: one Azure app registration with
    both the directory and the mail permissions covers identity response and
    mailbox remediation, and asking an operator to register a second app to
    purge a phishing message is friction with no security benefit.
    """
    tenant_id = params.get("azure_tenant_id")
    client_id = params.get("azure_client_id")
    client_secret = params.get("azure_client_secret")
    if not (tenant_id and client_id and client_secret):
        return None
    return M365MailClient(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)


def _gmail_client(params: dict) -> GmailClient | None:
    """Gmail client from the Workspace service-account key.

    ``gws_subject_email`` is optional here and required on the Workspace
    client, because Gmail impersonates the mailbox being acted on rather than
    a fixed admin — the subject is per call. It is still read so a deployment
    that configures only a report mailbox has a default.
    """
    key = params.get("gws_service_account_key")
    if not key:
        return None
    try:
        return GmailClient(service_account_key=key, subject_email=str(params.get("gws_subject_email") or ""))
    except ValueError:
        # A malformed key is a configuration error, and the caller's
        # "credentials not configured" branch is the right place for it to
        # surface: both mean "we did not reach the vendor", and raising here
        # would turn it into an executor crash instead.
        return None


# ---------------------------------------------------------------------------
# Wave-2 Phase 6.1 factories
# ---------------------------------------------------------------------------
#
# Each ships a ``*_CLIENT_PARAM_KEYS`` tuple beside it. The tuple is not
# documentation: ``tests/test_dry_run_credential_strip.py`` re-derives the
# keys a factory reads by parsing its source and asserts the two agree, and
# the per-arm dry-run test strips the tuple and requires the factory to go
# ``None``. That pairing is what stops the defect this repository has
# already shipped — a strip list naming ``splunk_host`` while the factory
# read ``splunk_url``, so a "dry run" called the customer's production
# Splunk.


AWS_IAM_CLIENT_PARAM_KEYS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "aws_region",
)


def _aws_iam_client(params: dict) -> AWSIAMClient | None:
    access_key_id = params.get("aws_access_key_id")
    secret_access_key = params.get("aws_secret_access_key")
    if not (access_key_id and secret_access_key):
        return None
    return AWSIAMClient(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=params.get("aws_session_token"),
        region=params.get("aws_region", "us-east-1"),
    )


GCP_IAM_CLIENT_PARAM_KEYS = ("gcp_service_account_key",)


def _gcp_iam_client(params: dict) -> GCPIAMClient | None:
    key = params.get("gcp_service_account_key")
    if not key:
        return None
    try:
        return GCPIAMClient(service_account_key=key)
    except ValueError:
        # A malformed key is a configuration error and the caller's
        # "credentials not configured" branch is where it belongs: both
        # mean the vendor was not reached, and raising here would turn it
        # into an executor crash. Same reasoning as _gmail_client.
        return None


GITHUB_CLIENT_PARAM_KEYS = ("github_token",)


def _github_client(params: dict) -> GitHubClient | None:
    token = params.get("github_token")
    if not token:
        return None
    return GitHubClient(token=token)


SLACK_ADMIN_CLIENT_PARAM_KEYS = ("slack_admin_token", "slack_team_id")


def _slack_admin_client(params: dict) -> SlackAdminClient | None:
    token = params.get("slack_admin_token")
    if not token:
        return None
    return SlackAdminClient(admin_token=token, team_id=params.get("slack_team_id"))


SALESFORCE_CLIENT_PARAM_KEYS = ("salesforce_instance_url", "salesforce_access_token")


def _salesforce_client(params: dict) -> SalesforceClient | None:
    instance_url = params.get("salesforce_instance_url")
    access_token = params.get("salesforce_access_token")
    if not (instance_url and access_token):
        return None
    return SalesforceClient(instance_url=instance_url, access_token=access_token)


SNOWFLAKE_CLIENT_PARAM_KEYS = (
    "snowflake_account_url",
    "snowflake_token",
    "snowflake_token_type",
    "snowflake_warehouse",
    "snowflake_role",
)


def _snowflake_client(params: dict) -> SnowflakeClient | None:
    account_url = params.get("snowflake_account_url")
    token = params.get("snowflake_token")
    if not (account_url and token):
        return None
    return SnowflakeClient(
        account_url=account_url,
        token=token,
        token_type=params.get("snowflake_token_type", "OAUTH"),
        warehouse=params.get("snowflake_warehouse"),
        role=params.get("snowflake_role"),
    )


ONEPASSWORD_CLIENT_PARAM_KEYS = ("onepassword_scim_url", "onepassword_scim_token")


def _onepassword_client(params: dict) -> OnePasswordClient | None:
    bridge_url = params.get("onepassword_scim_url")
    token = params.get("onepassword_scim_token")
    if not (bridge_url and token):
        return None
    return OnePasswordClient(bridge_url=bridge_url, bearer_token=token)


ZSCALER_CLIENT_PARAM_KEYS = ("zscaler_base_url", "zscaler_session_cookie")


def _zscaler_client(params: dict) -> ZscalerClient | None:
    base_url = params.get("zscaler_base_url")
    cookie = params.get("zscaler_session_cookie")
    if not (base_url and cookie):
        return None
    return ZscalerClient(base_url=base_url, session_cookie=cookie)


NETSKOPE_CLIENT_PARAM_KEYS = ("netskope_base_url", "netskope_api_token")


def _netskope_client(params: dict) -> NetskopeClient | None:
    base_url = params.get("netskope_base_url")
    token = params.get("netskope_api_token")
    if not (base_url and token):
        return None
    return NetskopeClient(base_url=base_url, api_token=token)


__all__ = [
    "AWS_IAM_CLIENT_PARAM_KEYS",
    "GCP_IAM_CLIENT_PARAM_KEYS",
    "GITHUB_CLIENT_PARAM_KEYS",
    "NETSKOPE_CLIENT_PARAM_KEYS",
    "ONEPASSWORD_CLIENT_PARAM_KEYS",
    "SALESFORCE_CLIENT_PARAM_KEYS",
    "SLACK_ADMIN_CLIENT_PARAM_KEYS",
    "SNOWFLAKE_CLIENT_PARAM_KEYS",
    "ZSCALER_CLIENT_PARAM_KEYS",
    "_aws_client",
    "_aws_iam_client",
    "_gcp_iam_client",
    "_github_client",
    "_netskope_client",
    "_onepassword_client",
    "_salesforce_client",
    "_slack_admin_client",
    "_snowflake_client",
    "_zscaler_client",
    "_cloudflare_client",
    "_cloudtrail_client",
    "_cortex_client",
    "_cs_client",
    "_entra_client",
    "_fortigate_client",
    "_gmail_client",
    "_gws_client",
    "_m365_mail_client",
    "_mde_client",
    "_okta_client",
    "_panos_client",
    "_s1_client",
]
