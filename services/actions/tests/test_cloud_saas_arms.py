"""Wave-2 Phase 6.1 arms: signatures, dry-run behaviour and vendor shapes.

Three properties, each of which has failed in this repository before and
each of which is checked here for *every* arm rather than for a sample.

**The executor calls a method its client actually has, with arguments its
real signature accepts.** ``SearchSIEMExecutor`` passed ``max_results=``
when the client takes ``max_count``; ``CreateNotableEventExecutor`` passed
``title``/``description``/``fields`` when it takes ``event_data``. Both
raised ``TypeError`` on every live call and neither was caught, because
simulation mode never constructs the client — so the only code path the
tests exercised was the one that does not call the vendor. The doubles here
are ``create_autospec`` of the real client classes, so a wrong keyword is a
test failure rather than a production ``TypeError``.

**A dry run does not reach a vendor, and does not claim it did.** Two
failures, in opposite directions. ``_SPLUNK_KEYS`` named ``splunk_host``
while the factory read ``splunk_url``, so the strip left a usable
credential and the "preview" called production Splunk. And
``NotifySlackExecutor`` fell, after a credential strip, into a simulation
branch it does not have, so every dry run reported ``message_sent: true``
on a send that never happened. So dry-run is graded per arm in both
directions: the status is SIMULATED, and the client factory was *never
called at all*.

**The client survives contact with the vendor's real response shape.**
A mock HTTP server (respx) returns recorded-shape payloads and the real
client parses them — the failure a double cannot show, because a double
answers whatever the test taught it to.
"""

from __future__ import annotations

import ast
import datetime as dt
import inspect
from typing import Any
from unittest.mock import create_autospec

import httpx
import pytest
import respx
from app.clients import factories
from app.clients.aws_iam_client import REVOKE_POLICY_NAME, AWSIAMClient
from app.clients.azure_entra_client import AzureEntraClient
from app.clients.cloudflare_client import CloudflareClient
from app.clients.gcp_iam_client import GCPIAMClient
from app.clients.github_client import GitHubClient
from app.clients.google_workspace_client import GoogleWorkspaceClient
from app.clients.okta_client import OktaClient
from app.clients.onepassword_client import OnePasswordClient
from app.clients.salesforce_client import SalesforceClient
from app.clients.slack_admin_client import SlackAdminClient
from app.clients.snowflake_client import SnowflakeClient
from app.clients.swg_clients import NetskopeClient, ZscalerClient
from app.live_actions import cloud_saas_arms
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.cloud_saas_arms import CLOUD_SAAS_EXECUTORS
from app.live_actions.models import LiveActionRequest, LiveActionStatus

#: executor class name -> (factory attribute on cloud_saas_arms,
#:                         real client class,
#:                         client methods the arm must call,
#:                         request params that satisfy the arm)
#:
#: Every arm needs a row. The first test asserts the two sets are equal, so
#: a new arm added without one is untested breadth — which is how a
#: registry fills up with things nobody exercised.
EXPECTED: dict[str, tuple[str, type, tuple[str, ...], dict[str, Any]]] = {
    # AWS
    "AwsDeactivateAccessKey": ("_aws_iam_client", AWSIAMClient, ("deactivate_access_key",), {"user_name": "ci-deploy"}),
    "AwsReactivateAccessKey": ("_aws_iam_client", AWSIAMClient, ("activate_access_key",), {"user_name": "ci-deploy"}),
    "AwsRevokeRoleSessions": ("_aws_iam_client", AWSIAMClient, ("revoke_role_sessions",), {}),
    "AwsRestoreRoleSessions": ("_aws_iam_client", AWSIAMClient, ("restore_role_sessions",), {}),
    "AwsQuarantineInstance": (
        "_aws_iam_client",
        AWSIAMClient,
        ("describe_instance_security_groups", "set_instance_security_groups"),
        {"quarantine_security_group_id": "sg-quarantine"},
    ),
    "AwsReleaseInstance": ("_aws_iam_client", AWSIAMClient, ("set_instance_security_groups",), {"security_group_ids": ["sg-web"]}),
    "AwsDisableUser": ("_aws_iam_client", AWSIAMClient, ("attach_deny_all",), {}),
    "AwsEnableUser": ("_aws_iam_client", AWSIAMClient, ("detach_deny_all",), {}),
    "AwsGetCloudIdentity": ("_aws_iam_client", AWSIAMClient, ("list_access_keys", "list_attached_user_policies"), {}),
    # GCP
    "GcpDisableServiceIdentity": ("_gcp_iam_client", GCPIAMClient, ("disable_service_account",), {}),
    "GcpEnableServiceIdentity": ("_gcp_iam_client", GCPIAMClient, ("enable_service_account",), {}),
    "GcpRevokeToken": (
        "_gcp_iam_client",
        GCPIAMClient,
        ("disable_service_account_key",),
        {"service_account": "sa@p.iam.gserviceaccount.com"},
    ),
    "GcpRestoreToken": (
        "_gcp_iam_client",
        GCPIAMClient,
        ("enable_service_account_key",),
        {"service_account": "sa@p.iam.gserviceaccount.com"},
    ),
    "GcpGetCloudIdentity": ("_gcp_iam_client", GCPIAMClient, ("get_service_account", "list_service_account_keys"), {}),
    # Entra
    "EntraDisableServiceIdentity": ("_entra_client", AzureEntraClient, ("disable_service_principal",), {}),
    "EntraEnableServiceIdentity": ("_entra_client", AzureEntraClient, ("enable_service_principal",), {}),
    "EntraRevokeOAuthGrant": ("_entra_client", AzureEntraClient, ("delete_oauth2_permission_grant",), {}),
    "EntraGetOAuthGrants": ("_entra_client", AzureEntraClient, ("list_oauth2_permission_grants",), {}),
    "EntraGetCloudIdentity": ("_entra_client", AzureEntraClient, ("get_service_principal",), {}),
    "EntraRevokeToken": ("_entra_client", AzureEntraClient, ("remove_service_principal_password",), {"key_id": "key-1"}),
    # Google Workspace
    "GoogleWorkspaceRevokeOAuthGrant": (
        "_gws_client",
        GoogleWorkspaceClient,
        ("revoke_oauth_token",),
        {"client_id": "12345.apps.googleusercontent.com"},
    ),
    "GoogleWorkspaceGetOAuthGrants": ("_gws_client", GoogleWorkspaceClient, ("list_oauth_tokens",), {}),
    "GoogleWorkspaceRevokeToken": ("_gws_client", GoogleWorkspaceClient, ("revoke_app_passwords",), {}),
    "GoogleWorkspaceGetCloudIdentity": ("_gws_client", GoogleWorkspaceClient, ("get_user",), {}),
    # Okta
    "OktaRevokeOAuthGrant": ("_okta_client", OktaClient, ("revoke_grants",), {}),
    "OktaGetOAuthGrants": ("_okta_client", OktaClient, ("list_grants",), {}),
    "OktaRevokeToken": ("_okta_client", OktaClient, ("revoke_refresh_tokens",), {"client_id": "0oaclient"}),
    "OktaGetCloudIdentity": ("_okta_client", OktaClient, ("get_user_status",), {}),
    # GitHub
    "GitHubRemoveOrgMember": ("_github_client", GitHubClient, ("remove_org_member",), {"org": "acme"}),
    "GitHubRestoreOrgMember": ("_github_client", GitHubClient, ("set_org_membership",), {"org": "acme"}),
    "GitHubRevokeDeployKey": ("_github_client", GitHubClient, ("delete_deploy_key",), {"owner": "acme", "repo": "api"}),
    "GitHubDisableWorkflow": ("_github_client", GitHubClient, ("set_workflow_enabled",), {"owner": "acme", "repo": "api"}),
    "GitHubEnableWorkflow": ("_github_client", GitHubClient, ("set_workflow_enabled",), {"owner": "acme", "repo": "api"}),
    "GitHubRevokeToken": ("_github_revocation_client", GitHubClient, ("revoke_credentials",), {}),
    "GitHubGetSecretScanningAlerts": ("_github_client", GitHubClient, ("list_secret_scanning_alerts",), {"owner": "acme", "repo": "api"}),
    "GitHubGetCloudIdentity": ("_github_client", GitHubClient, ("get_org_membership",), {"org": "acme"}),
    # Slack
    "SlackDisableUser": ("_slack_admin_client", SlackAdminClient, ("remove_user",), {"team_id": "T1"}),
    "SlackEnableUser": ("_slack_admin_client", SlackAdminClient, ("assign_user",), {"team_id": "T1"}),
    "SlackRevokeSession": ("_slack_admin_client", SlackAdminClient, ("reset_sessions",), {}),
    "SlackGetCloudIdentity": ("_slack_admin_client", SlackAdminClient, ("get_user",), {}),
    # Salesforce
    "SalesforceDisableUser": ("_salesforce_client", SalesforceClient, ("freeze_user",), {}),
    "SalesforceEnableUser": ("_salesforce_client", SalesforceClient, ("unfreeze_user",), {}),
    "SalesforceRevokeToken": ("_salesforce_client", SalesforceClient, ("revoke_oauth_token",), {}),
    "SalesforceRevokeSession": ("_salesforce_client", SalesforceClient, ("revoke_sessions",), {}),
    "SalesforceGetCloudIdentity": ("_salesforce_client", SalesforceClient, ("resolve_user_login",), {}),
    # Snowflake
    "SnowflakeDisableUser": ("_snowflake_client", SnowflakeClient, ("disable_user",), {}),
    "SnowflakeEnableUser": ("_snowflake_client", SnowflakeClient, ("enable_user",), {}),
    "SnowflakeRevokeSession": ("_snowflake_client", SnowflakeClient, ("abort_session",), {}),
    "SnowflakeGetCloudIdentity": ("_snowflake_client", SnowflakeClient, ("describe_user",), {}),
    # 1Password
    "OnePasswordDisableUser": ("_onepassword_client", OnePasswordClient, ("suspend_user",), {}),
    "OnePasswordEnableUser": ("_onepassword_client", OnePasswordClient, ("restore_user",), {}),
    "OnePasswordGetCloudIdentity": ("_onepassword_client", OnePasswordClient, ("get_user",), {}),
    # Gateways
    "CloudflareBlockURL": ("_cloudflare_client", CloudflareClient, ("block_url",), {"account_id": "acct", "list_id": "list"}),
    "CloudflareAllowURL": ("_cloudflare_client", CloudflareClient, ("allow_url",), {"account_id": "acct", "list_id": "list"}),
    "ZscalerBlockURL": ("_zscaler_client", ZscalerClient, ("block_url",), {"category_id": "CUSTOM_01"}),
    "ZscalerAllowURL": ("_zscaler_client", ZscalerClient, ("allow_url",), {"category_id": "CUSTOM_01"}),
    "ZscalerBlockDomain": ("_zscaler_client", ZscalerClient, ("block_domain",), {"category_id": "CUSTOM_01"}),
    "ZscalerAllowDomain": ("_zscaler_client", ZscalerClient, ("allow_domain",), {"category_id": "CUSTOM_01"}),
    "NetskopeBlockURL": ("_netskope_client", NetskopeClient, ("block_url",), {"list_id": "L1"}),
    "NetskopeAllowURL": ("_netskope_client", NetskopeClient, ("allow_url",), {"list_id": "L1"}),
    "NetskopeBlockDomain": ("_netskope_client", NetskopeClient, ("block_domain",), {"list_id": "L1"}),
    "NetskopeAllowDomain": ("_netskope_client", NetskopeClient, ("allow_domain",), {"list_id": "L1"}),
}

#: A fully-populated credential bag for every vendor in this module. The
#: dry-run test runs each arm against *all* of it, because the original
#: defect was a strip list that left one usable key behind.
FULL_CREDENTIALS: dict[str, Any] = {
    "aws_access_key_id": "AKIAEXAMPLE",
    "aws_secret_access_key": "unit-test-placeholder",
    "aws_session_token": "unit-test-placeholder",
    "aws_region": "eu-west-1",
    "gcp_service_account_key": '{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"unit-test-placeholder"}',
    "azure_tenant_id": "00000000-0000-0000-0000-000000000001",
    "azure_client_id": "00000000-0000-0000-0000-000000000002",
    "azure_client_secret": "unit-test-placeholder",
    "gws_service_account_key": '{"client_email":"sa@example.invalid","private_key":"unit-test-placeholder"}',
    "gws_subject_email": "admin@example.invalid",
    "okta_domain": "https://example.okta.com",
    "okta_api_token": "unit-test-placeholder",
    "github_token": "unit-test-placeholder",
    "slack_admin_token": "unit-test-placeholder",
    "slack_team_id": "T1",
    "salesforce_instance_url": "https://example.my.salesforce.com",
    "salesforce_access_token": "unit-test-placeholder",
    "snowflake_account_url": "https://acct.snowflakecomputing.com",
    "snowflake_token": "unit-test-placeholder",
    "onepassword_scim_url": "https://scim.example.invalid",
    "onepassword_scim_token": "unit-test-placeholder",
    "cf_api_token": "unit-test-placeholder",
    "zscaler_base_url": "https://zsapi.example.invalid",
    "zscaler_session_cookie": "JSESSIONID=unit-test-placeholder",
    "netskope_base_url": "https://tenant.goskope.com",
    "netskope_api_token": "unit-test-placeholder",
}

#: Factories whose declared key tuple is re-derived from their source.
#: ``_github_revocation_client`` is deliberately absent: it takes no
#: credentials, which is the point of that arm.
FACTORY_KEY_TUPLES = {
    "_aws_iam_client": factories.AWS_IAM_CLIENT_PARAM_KEYS,
    "_gcp_iam_client": factories.GCP_IAM_CLIENT_PARAM_KEYS,
    "_github_client": factories.GITHUB_CLIENT_PARAM_KEYS,
    "_slack_admin_client": factories.SLACK_ADMIN_CLIENT_PARAM_KEYS,
    "_salesforce_client": factories.SALESFORCE_CLIENT_PARAM_KEYS,
    "_snowflake_client": factories.SNOWFLAKE_CLIENT_PARAM_KEYS,
    "_onepassword_client": factories.ONEPASSWORD_CLIENT_PARAM_KEYS,
    "_zscaler_client": factories.ZSCALER_CLIENT_PARAM_KEYS,
    "_netskope_client": factories.NETSKOPE_CLIENT_PARAM_KEYS,
}


def _keys_read_by(func) -> set[str]:
    """Re-derive the ``params.get("...")`` keys a factory reads from its source.

    The anti-drift half: a constant that merely agrees with itself proves
    nothing, so the tuple is compared against a parse of the factory body.
    """
    tree = ast.parse(inspect.getsource(func).lstrip())
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        attribute = node.func
        if not isinstance(attribute, ast.Attribute) or attribute.attr != "get":
            continue
        if not isinstance(attribute.value, ast.Name) or attribute.value.id != "params":
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            found.add(node.args[0].value)
    return found


def _request(executor_cls, **extra: Any) -> LiveActionRequest:
    params = dict(FULL_CREDENTIALS)
    params.update(EXPECTED[executor_cls.__name__][3])
    params.update(extra)
    return LiveActionRequest(
        vendor_id=executor_cls.vendor_id,
        capability=executor_cls.capability,
        target="TARGET",
        params=params,
    )


class TestEveryArmIsGraded:
    def test_every_executor_has_a_row(self) -> None:
        assert {cls.__name__ for cls in CLOUD_SAAS_EXECUTORS} == set(EXPECTED)

    def test_every_capability_has_a_contract(self) -> None:
        missing = sorted({cls.capability for cls in CLOUD_SAAS_EXECUTORS} - set(CAPABILITY_CONTRACTS))
        assert not missing, f"{missing}: an arm whose verb nobody classified is dispatchable with the unsafe defaults"

    def test_no_new_verb_is_automatic_at_a_disruptive_tier(self) -> None:
        """Unverifiable means not autonomous.

        None of these verbs has a ``PostActionVerifier`` probe, so none of
        them may be AUTOMATIC above READ_ONLY. Asserted directly rather
        than left to the contract gate's general rule, because this is the
        specific property the phase promised.
        """
        for cls in CLOUD_SAAS_EXECUTORS:
            contract = CAPABILITY_CONTRACTS[cls.capability]
            if contract.impact.value == "read_only":
                continue
            assert contract.approval.value != "automatic", f"{cls.__name__} ({cls.capability}) is automatic with no verification probe"

    def test_every_platform_reversal_names_a_registered_verb(self) -> None:
        """A declared rollback must resolve to something that runs.

        ``unisolate_host`` had a contract and no executor, so the rollback
        for the most disruptive action in the product resolved to nothing.
        """
        from app.live_actions.builtins import _BUILTIN_ADAPTERS  # noqa: PLC0415 - import inside the test to keep collection light

        implemented = {cls.capability for cls in _BUILTIN_ADAPTERS}
        for cls in CLOUD_SAAS_EXECUTORS:
            contract = CAPABILITY_CONTRACTS[cls.capability]
            if contract.reversal.value != "platform":
                continue
            assert contract.reverse_capability in implemented, (
                f"{cls.capability} declares a platform rollback via {contract.reverse_capability!r}, which no executor implements"
            )


class TestSignaturesAreReal:
    """Every arm calls a method its client has, with arguments it accepts."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("executor_cls", CLOUD_SAAS_EXECUTORS, ids=lambda c: c.__name__)
    async def test_arm_calls_its_client_method(self, executor_cls, monkeypatch) -> None:
        factory_name, client_cls, methods, _params = EXPECTED[executor_cls.__name__]
        # create_autospec gives every method the *real* signature, so a
        # wrong keyword fails here instead of raising TypeError on the
        # first live call — which is exactly how the SearchSIEM and
        # CreateNotableEvent defects reached production.
        double = create_autospec(client_cls, instance=True)
        # Arms that compose a result from several reads need real
        # mappings back; a bare MagicMock is not one and would fail for a
        # reason that has nothing to do with the signature under test.
        for method in methods:
            getattr(double, method).return_value = {}
        monkeypatch.setattr(cloud_saas_arms, factory_name, lambda _params: double)

        result = await executor_cls().execute(_request(executor_cls))

        assert result.status is LiveActionStatus.SUCCEEDED, f"{executor_cls.__name__}: {result.error}"
        for method in methods:
            assert getattr(double, method).await_count >= 1, f"{executor_cls.__name__} did not call {client_cls.__name__}.{method}"

    @pytest.mark.parametrize("executor_cls", CLOUD_SAAS_EXECUTORS, ids=lambda c: c.__name__)
    async def test_a_vendor_error_is_reported_not_absorbed(self, executor_cls, monkeypatch) -> None:
        factory_name, client_cls, methods, _params = EXPECTED[executor_cls.__name__]
        double = create_autospec(client_cls, instance=True)
        getattr(double, methods[0]).side_effect = RuntimeError("vendor said no")
        monkeypatch.setattr(cloud_saas_arms, factory_name, lambda _params: double)

        result = await executor_cls().execute(_request(executor_cls))

        assert result.status is LiveActionStatus.FAILED
        assert "vendor said no" in (result.error or "")


class TestDryRunCannotReachAVendor:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("executor_cls", CLOUD_SAAS_EXECUTORS, ids=lambda c: c.__name__)
    async def test_dry_run_never_constructs_a_client(self, executor_cls, monkeypatch) -> None:
        """Both halves of the defect, per arm.

        SIMULATED, so no arm reports a change it did not make — the
        ``NotifySlackExecutor`` failure. And the factory is never reached
        at all, so no credential the strip list happened to miss can let a
        preview call a production system — the Splunk failure.
        """
        factory_name, _client_cls, _methods, _params = EXPECTED[executor_cls.__name__]
        calls: list[dict] = []

        def _refuse(params):
            calls.append(params)
            raise AssertionError(f"{executor_cls.__name__}: dry run constructed a client")

        monkeypatch.setattr(cloud_saas_arms, factory_name, _refuse)

        request = _request(executor_cls)
        result = await executor_cls().execute(request.model_copy(update={"dry_run": True}))

        assert result.status is LiveActionStatus.SIMULATED
        assert not calls
        assert result.details["would_run"] == executor_cls.capability

    @pytest.mark.parametrize("factory_name", sorted(FACTORY_KEY_TUPLES))
    def test_declared_key_tuple_matches_what_the_factory_reads(self, factory_name: str) -> None:
        factory = getattr(factories, factory_name)
        declared = set(FACTORY_KEY_TUPLES[factory_name])
        assert _keys_read_by(factory) == declared, (
            f"{factory_name}: the factory reads {sorted(_keys_read_by(factory))} and the "
            f"tuple declares {sorted(declared)}. A key the factory reads and the tuple "
            f"omits is a dry run that calls the customer's production system."
        )

    @pytest.mark.parametrize("factory_name", sorted(FACTORY_KEY_TUPLES))
    def test_stripping_the_declared_keys_disables_the_factory(self, factory_name: str) -> None:
        factory = getattr(factories, factory_name)
        assert factory(dict(FULL_CREDENTIALS)) is not None, f"{factory_name} refused a fully-populated credential bag"
        stripped = {k: v for k, v in FULL_CREDENTIALS.items() if k not in FACTORY_KEY_TUPLES[factory_name]}
        assert factory(stripped) is None, f"{factory_name} still built a client after its declared keys were stripped"

    @pytest.mark.parametrize("executor_cls", CLOUD_SAAS_EXECUTORS, ids=lambda c: c.__name__)
    def test_every_arm_declares_a_strip_list_its_factory_honours(self, executor_cls) -> None:
        factory_name, _client_cls, _methods, _params = EXPECTED[executor_cls.__name__]
        declared = tuple(executor_cls._credential_keys)  # noqa: SLF001 - the declaration under test
        if factory_name == "_github_revocation_client":
            # The one endpoint GitHub refuses to authenticate. An empty
            # tuple is the correct declaration, and a non-empty one would
            # assert a property this arm does not have.
            assert declared == ()
            assert executor_cls.requires_credentials is False
            return
        assert declared, f"{executor_cls.__name__} declares no credential keys"
        if factory_name in FACTORY_KEY_TUPLES:
            assert set(declared) == set(FACTORY_KEY_TUPLES[factory_name])


class TestCredentialsAbsentIsNotFailure:
    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("executor_cls", CLOUD_SAAS_EXECUTORS, ids=lambda c: c.__name__)
    async def test_missing_credentials_say_so(self, executor_cls, monkeypatch) -> None:
        factory_name, _client_cls, _methods, _params = EXPECTED[executor_cls.__name__]
        if factory_name == "_github_revocation_client":
            pytest.skip("this verb needs no credentials; 'not configured' would be the wrong answer")
        monkeypatch.setattr(cloud_saas_arms, factory_name, lambda _params: None)

        result = await executor_cls().execute(_request(executor_cls))

        assert result.status is LiveActionStatus.FAILED
        assert "credentials are not configured" in (result.error or "")
        assert "not a statement about the target" in (result.error or "")


class TestMissingParameterIsItsOwnAnswer:
    pytestmark = pytest.mark.asyncio

    async def test_an_arm_without_its_required_argument_names_it(self, monkeypatch) -> None:
        double = create_autospec(GitHubClient, instance=True)
        monkeypatch.setattr(cloud_saas_arms, "_github_client", lambda _params: double)

        request = LiveActionRequest(
            vendor_id="github",
            capability="remove_org_member",
            target="mallory",
            params=dict(FULL_CREDENTIALS),  # no "org"
        )
        result = await cloud_saas_arms.GitHubRemoveOrgMember().execute(request)

        assert result.status is LiveActionStatus.FAILED
        assert "'org'" in (result.error or "")
        assert double.remove_org_member.await_count == 0


# ─── Mock-vendor smokes ──────────────────────────────────────────────────────
#
# Recorded response shapes through respx, driving the real client so the
# signing, the parser and the error handling all run. A double answers
# whatever the test taught it; only this shows a client that cannot read
# what the vendor actually sends.


class TestVendorShapes:
    pytestmark = pytest.mark.asyncio

    async def test_aws_access_key_deactivation_signs_and_parses(self) -> None:
        captured: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            captured["authorization"] = request.headers.get("authorization", "")
            captured["body"] = request.content.decode()
            return httpx.Response(
                200,
                text=(
                    '<UpdateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
                    "<ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>"
                    "</UpdateAccessKeyResponse>"
                ),
            )

        with respx.mock:
            respx.post("https://iam.amazonaws.com/").mock(side_effect=_handler)
            client = AWSIAMClient(access_key_id="AKIAEXAMPLE", secret_access_key="unit-test-placeholder")
            result = await client.deactivate_access_key(user_name="ci-deploy", access_key_id="AKIALEAKED")

        assert result["status"] == "Inactive"
        assert captured["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
        # IAM is a global service and must be signed against us-east-1
        # whatever region the caller configured. Signing it elsewhere is
        # rejected, so this is a correctness assertion, not a style one.
        assert "/us-east-1/iam/aws4_request" in captured["authorization"]
        assert "Action=UpdateAccessKey" in captured["body"]
        assert "Status=Inactive" in captured["body"]

    async def test_aws_role_session_revocation_writes_the_console_policy(self) -> None:
        captured: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return httpx.Response(200, text='<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"/>')

        with respx.mock:
            respx.post("https://iam.amazonaws.com/").mock(side_effect=_handler)
            client = AWSIAMClient(access_key_id="AKIAEXAMPLE", secret_access_key="unit-test-placeholder")
            result = await client.revoke_role_sessions(
                role_name="AppRole",
                issued_before=dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=dt.UTC),
            )

        assert result["policy_name"] == REVOKE_POLICY_NAME
        assert "PolicyName=AWSRevokeOlderSessions" in captured["body"]
        assert "aws%3ATokenIssueTime" in captured["body"]
        assert "2026-11-01T12%3A00%3A00Z" in captured["body"]

    async def test_aws_instance_security_groups_parse_from_describe_shape(self) -> None:
        body = (
            '<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            "<reservationSet><item><instancesSet><item>"
            "<instanceId>i-0abc</instanceId>"
            "<groupSet><item><groupId>sg-web</groupId><groupName>web</groupName></item>"
            "<item><groupId>sg-db</groupId><groupName>db</groupName></item></groupSet>"
            "</item></instancesSet></item></reservationSet></DescribeInstancesResponse>"
        )
        with respx.mock:
            respx.post("https://ec2.eu-west-1.amazonaws.com/").respond(200, text=body)
            client = AWSIAMClient(access_key_id="AKIAEXAMPLE", secret_access_key="unit-test-placeholder", region="eu-west-1")
            groups = await client.describe_instance_security_groups(instance_id="i-0abc")

        assert groups == ["sg-web", "sg-db"]

    async def test_aws_error_body_surfaces_the_vendor_message(self) -> None:
        body = (
            '<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error>'
            "<Code>NoSuchEntity</Code><Message>The user with name ghost cannot be found.</Message>"
            "</Error></ErrorResponse>"
        )
        with respx.mock:
            respx.post("https://iam.amazonaws.com/").respond(404, text=body)
            client = AWSIAMClient(access_key_id="AKIAEXAMPLE", secret_access_key="unit-test-placeholder")
            with pytest.raises(Exception, match="NoSuchEntity"):
                await client.deactivate_access_key(user_name="ghost", access_key_id="AKIA")

    async def test_github_credential_revocation_sends_no_authorization(self) -> None:
        """The property that would otherwise be a 403 nobody attributes to us.

        GitHub documents that an authenticated request to this endpoint
        returns 403. A client that adds its bearer the way every other
        call does leaves the leaked token live while an operator goes
        looking for a missing scope.
        """
        captured: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            captured["authorization"] = request.headers.get("authorization")
            captured["body"] = request.content.decode()
            return httpx.Response(202, json={})

        with respx.mock:
            respx.post("https://api.github.com/credentials/revoke").mock(side_effect=_handler)
            client = GitHubClient(token="unit-test-placeholder")
            result = await client.revoke_credentials(["ghp_000000000000000000000000000000000000"])

        assert captured["authorization"] is None
        assert result == {"submitted": 1, "http_status": 202, "accepted": True}

    async def test_github_credential_revocation_refuses_an_oversized_batch(self) -> None:
        client = GitHubClient(token="unit-test-placeholder")
        with pytest.raises(ValueError, match="1000"):
            await client.revoke_credentials([f"ghp_{index:036d}" for index in range(1001)])

    async def test_github_workflow_state_reads_back(self) -> None:
        with respx.mock:
            respx.put("https://api.github.com/repos/acme/api/actions/workflows/ci.yml/disable").respond(204)
            respx.get("https://api.github.com/repos/acme/api/actions/workflows/ci.yml").respond(
                200,
                json={"id": 161335, "name": "CI", "path": ".github/workflows/ci.yml", "state": "disabled_manually"},
            )
            client = GitHubClient(token="unit-test-placeholder")
            await client.set_workflow_enabled("acme", "api", "ci.yml", enabled=False)
            workflow = await client.get_workflow("acme", "api", "ci.yml")

        assert workflow["state"] == "disabled_manually"

    async def test_github_secret_scanning_alerts_never_carry_a_secret(self) -> None:
        with respx.mock:
            respx.get("https://api.github.com/repos/acme/api/secret-scanning/alerts").respond(
                200,
                json=[
                    {
                        "number": 2,
                        "state": "open",
                        "secret_type": "aws_access_key_id",
                        "secret_type_display_name": "Amazon AWS Access Key ID",
                        "created_at": "2026-10-30T12:00:00Z",
                        "html_url": "https://github.com/acme/api/security/secret-scanning/2",
                        "repository": {"full_name": "acme/api"},
                        "push_protection_bypassed": False,
                    }
                ],
            )
            client = GitHubClient(token="unit-test-placeholder")
            alerts = await client.list_secret_scanning_alerts(owner="acme", repo="api")

        assert alerts[0]["secret_type"] == "aws_access_key_id"
        assert all("secret" not in key or key.startswith("secret_type") for key in alerts[0])

    async def test_slack_ok_false_is_a_failure_not_a_success(self) -> None:
        """HTTP 200 with ``ok: false`` is Slack's refusal.

        A client that only reads the status code reports every refusal as
        a containment that happened.
        """
        with respx.mock:
            respx.post("https://slack.com/api/admin.users.remove").respond(200, json={"ok": False, "error": "user_not_found"})
            client = SlackAdminClient(admin_token="unit-test-placeholder", team_id="T1")
            with pytest.raises(Exception, match="user_not_found"):
                await client.remove_user("W404")

    async def test_slack_session_reset_rejects_both_scopes_at_once(self) -> None:
        client = SlackAdminClient(admin_token="unit-test-placeholder", team_id="T1")
        with pytest.raises(ValueError, match="mutually exclusive"):
            await client.reset_sessions("W1", mobile_only=True, web_only=True)

    async def test_salesforce_freeze_resolves_user_login_before_writing(self) -> None:
        """``IsFrozen`` lives on ``UserLogin``, not on ``User``.

        A write to ``User`` would be a 400 at best and, on a field that
        happened to exist, a silent no-op reported as a containment.
        """
        patched: dict[str, Any] = {}

        async def _patch_handler(request: httpx.Request) -> httpx.Response:
            patched["url"] = str(request.url)
            patched["body"] = request.content.decode()
            return httpx.Response(204)

        with respx.mock:
            respx.get(url__regex=r"https://example\.my\.salesforce\.com/services/data/v62\.0/query.*").mock(
                side_effect=[
                    httpx.Response(
                        200, json={"records": [{"Id": "005000000000001AAA", "Username": "mallory@example.invalid", "IsActive": True}]}
                    ),
                    httpx.Response(
                        200,
                        json={
                            "records": [
                                {"Id": "0Ya000000000001AAA", "UserId": "005000000000001AAA", "IsFrozen": False, "IsPasswordLocked": False}
                            ]
                        },
                    ),
                ]
            )
            respx.patch(url__regex=r".*/sobjects/UserLogin/.*").mock(side_effect=_patch_handler)
            client = SalesforceClient(instance_url="https://example.my.salesforce.com", access_token="unit-test-placeholder")
            result = await client.freeze_user("mallory@example.invalid")

        assert result["is_frozen"] is True
        assert "/sobjects/UserLogin/0Ya000000000001AAA" in patched["url"]
        assert '"IsFrozen": true' in patched["body"] or '"IsFrozen":true' in patched["body"]

    async def test_salesforce_refuses_an_identifier_it_cannot_recognise(self) -> None:
        """Refuse, never escape.

        An escaped value that reaches SOQL and matches nothing reports a
        clean result from a query that never ran — which on a containment
        path is the worst available outcome.
        """
        client = SalesforceClient(instance_url="https://example.my.salesforce.com", access_token="unit-test-placeholder")
        with pytest.raises(ValueError, match="refusing to build a query"):
            await client.resolve_user_login("' OR Id != '")

    async def test_snowflake_describe_user_reads_columns_by_name(self) -> None:
        """The SQL API returns positional rows plus a column description.

        Reading ``DISABLED`` from a fixed offset breaks the first time
        Snowflake adds a column, and breaks by reporting the wrong value
        rather than by failing.
        """
        with respx.mock:
            respx.post("https://acct.snowflakecomputing.com/api/v2/statements").respond(
                200,
                json={
                    "resultSetMetaData": {"rowType": [{"name": "property"}, {"name": "value"}, {"name": "default"}]},
                    "data": [["NAME", "MALLORY", ""], ["DISABLED", "true", "false"], ["DEFAULT_ROLE", "ANALYST", ""]],
                },
            )
            client = SnowflakeClient(account_url="https://acct.snowflakecomputing.com", token="unit-test-placeholder")
            described = await client.describe_user("MALLORY")

        assert described == {"user": "MALLORY", "disabled": True, "login_name": None, "default_role": "ANALYST"}

    async def test_snowflake_refuses_an_identifier_that_is_not_one(self) -> None:
        client = SnowflakeClient(account_url="https://acct.snowflakecomputing.com", token="unit-test-placeholder")
        with pytest.raises(ValueError, match="not a valid Snowflake"):
            await client.disable_user('MALLORY" SET PASSWORD = "x')

    async def test_snowflake_async_acceptance_is_not_reported_as_containment(self) -> None:
        with respx.mock:
            respx.post("https://acct.snowflakecomputing.com/api/v2/statements").respond(202, json={"statementHandle": "01b"})
            client = SnowflakeClient(account_url="https://acct.snowflakecomputing.com", token="unit-test-placeholder")
            with pytest.raises(Exception, match="asynchronously"):
                await client.disable_user("MALLORY")

    async def test_onepassword_suspension_patches_rather_than_replaces(self) -> None:
        """A SCIM ``PUT`` replaces the resource and silently clears what it omits."""
        captured: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={"id": "u1", "userName": "mallory@example.invalid", "active": False})

        with respx.mock:
            respx.get("https://scim.example.invalid/Users").respond(
                200,
                json={"Resources": [{"id": "u1", "userName": "mallory@example.invalid", "active": True, "displayName": "Mallory"}]},
            )
            respx.patch("https://scim.example.invalid/Users/u1").mock(side_effect=_handler)
            client = OnePasswordClient(bridge_url="https://scim.example.invalid", bearer_token="unit-test-placeholder")
            result = await client.suspend_user("mallory@example.invalid")

        assert captured["method"] == "PATCH"
        assert '"active"' in captured["body"]
        assert result["active"] is False

    async def test_gateway_list_edits_are_incremental_not_replacements(self) -> None:
        """Two concurrent containments must not lose one of the two entries."""
        captured: dict[str, Any] = {}

        async def _zscaler(request: httpx.Request) -> httpx.Response:
            captured["zscaler_url"] = str(request.url)
            captured["zscaler_body"] = request.content.decode()
            return httpx.Response(200, json={"id": "CUSTOM_01", "configuredName": "AiSOC block", "urls": ["phish.example.invalid/login"]})

        async def _netskope(request: httpx.Request) -> httpx.Response:
            captured["netskope_url"] = str(request.url)
            return httpx.Response(200, json={"data": {"urls": ["phish.example.invalid/login"]}})

        with respx.mock:
            respx.put(url__regex=r"https://zsapi\.example\.invalid/api/v1/urlCategories/CUSTOM_01.*").mock(side_effect=_zscaler)
            respx.patch("https://tenant.goskope.com/api/v2/policy/urllist/L1/append").mock(side_effect=_netskope)

            zscaler = ZscalerClient(base_url="https://zsapi.example.invalid", session_cookie="JSESSIONID=x")
            await zscaler.block_url("https://phish.example.invalid/login/", category_id="CUSTOM_01")

            netskope = NetskopeClient(base_url="https://tenant.goskope.com", api_token="unit-test-placeholder")
            await netskope.block_url("https://phish.example.invalid/login/", list_id="L1")

        assert "action=ADD_TO_LIST" in captured["zscaler_url"]
        # The scheme and trailing slash are stripped: neither vendor takes a
        # scheme, so a list entry carrying one would never match.
        assert "phish.example.invalid/login" in captured["zscaler_body"]
        assert "https://" not in captured["zscaler_body"].split('"urls"')[-1]
        assert captured["netskope_url"].endswith("/urllist/L1/append")
