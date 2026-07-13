"""Phase B2 — credential resolver tests.

The executors read vendor-prefixed parameter keys; connectors store schema
field names. These tests pin the translation for every mapped vendor so a
drifted key (which would silently drop the platform back into simulation
mode) fails CI.
"""

from __future__ import annotations

from app.services.credential_resolver import (
    CONNECTOR_TO_VENDOR,
    VENDOR_CREDENTIAL_MAP,
    canonical_vendor,
    resolve_params,
)


def test_crowdstrike_fields_map_to_cs_prefixed_keys():
    out = resolve_params(
        "crowdstrike",
        {"client_id": "abc", "client_secret": "xyz", "base_url": "https://api.crowdstrike.com"},
    )
    assert out == {
        "cs_client_id": "abc",
        "cs_client_secret": "xyz",
        "cs_base_url": "https://api.crowdstrike.com",
    }


def test_okta_fields_map():
    out = resolve_params("okta", {"domain": "https://org.okta.com", "api_token": "tok"})
    assert out == {"okta_domain": "https://org.okta.com", "okta_api_token": "tok"}


def test_splunk_fields_map_including_url_and_ssl():
    out = resolve_params("splunk", {"base_url": "https://splunk:8089", "token": "hec", "ssl_verify": True})
    assert out == {"splunk_url": "https://splunk:8089", "splunk_token": "hec", "splunk_verify_ssl": True}


def test_aws_connector_id_aliases_to_security_groups_vendor():
    assert canonical_vendor("aws_security_hub") == "aws_security_groups"
    assert canonical_vendor("aws_guardduty") == "aws_security_groups"
    out = resolve_params(
        "aws_security_hub",
        {"access_key": "AKIA...", "secret_key": "s3cr3t", "region": "eu-west-1"},
        extra={"aws_security_group_id": "sg-123"},
    )
    assert out["aws_access_key_id"] == "AKIA..."
    assert out["aws_secret_access_key"] == "s3cr3t"
    assert out["aws_region"] == "eu-west-1"
    # Operational (non-credential) param merged from extra:
    assert out["aws_security_group_id"] == "sg-123"


def test_azure_defender_aliases_to_defender_mde_keys():
    out = resolve_params("azure_defender", {"tenant_id": "t", "client_id": "c", "client_secret": "s"})
    assert out == {"mde_tenant_id": "t", "mde_client_id": "c", "mde_client_secret": "s"}


def test_google_workspace_map():
    out = resolve_params("google_workspace", {"service_account_json": "{...}", "admin_email": "admin@corp.com"})
    assert out == {"gws_service_account_key": "{...}", "gws_subject_email": "admin@corp.com"}


def test_unknown_field_is_dropped_not_forwarded():
    out = resolve_params("okta", {"domain": "d", "api_token": "t", "mystery_field": "boom"})
    assert "mystery_field" not in out


def test_already_prefixed_keys_pass_through():
    out = resolve_params("okta", {"okta_domain": "d", "okta_api_token": "t"})
    assert out == {"okta_domain": "d", "okta_api_token": "t"}


def test_extra_overrides_translated_value():
    out = resolve_params("okta", {"domain": "old"}, extra={"okta_domain": "new"})
    assert out["okta_domain"] == "new"


def test_none_values_skipped():
    out = resolve_params("jira", {"base_url": "https://j", "email": None, "api_token": "t"})
    assert out == {"jira_base_url": "https://j", "jira_api_token": "t"}


def test_every_mapped_vendor_produces_only_executor_keys():
    # Sanity sweep: translated keys must all be prefixed/executor-vocabulary,
    # never raw connector field names (which executors ignore -> simulation).
    for vendor, mapping in VENDOR_CREDENTIAL_MAP.items():
        fake_auth = {field: "v" for field in mapping}
        out = resolve_params(vendor, fake_auth)
        assert set(out) == set(mapping.values()), vendor


def test_connector_alias_table_targets_exist():
    for alias_target in CONNECTOR_TO_VENDOR.values():
        assert alias_target in VENDOR_CREDENTIAL_MAP
