"""Unit tests for the honeytoken generator — pure, no DB."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

import pytest
from app.services.generator import TOKEN_GENERATORS, generate_token

TENANT = uuid.UUID("99999999-9999-9999-9999-999999999999")


class TestGenerateTokenValidation:
    def test_unknown_token_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown token_type"):
            generate_token(
                token_type="not-a-real-type",
                name="x",
                description=None,
                tenant_id=TENANT,
                created_by=None,
            )

    @pytest.mark.parametrize("token_type", list(TOKEN_GENERATORS.keys()))
    def test_each_known_type_returns_valid_record(self, token_type: str) -> None:
        record = generate_token(
            token_type=token_type,
            name="my token",
            description="desc",
            tenant_id=TENANT,
            created_by="alice",
        )
        # Required fields
        assert isinstance(record["id"], uuid.UUID)
        assert record["tenant_id"] == TENANT
        assert record["name"] == "my token"
        assert record["description"] == "desc"
        assert record["token_type"] == token_type
        assert record["status"] == "active"
        assert record["created_by"] == "alice"
        # Token data is embedded under metadata_.token_data
        assert "token_data" in record["metadata_"]
        assert isinstance(record["metadata_"]["token_data"], dict)


class TestGenerateTokenUniqueness:
    def test_two_tokens_have_distinct_ids(self) -> None:
        a = generate_token("custom", "a", None, TENANT, None)
        b = generate_token("custom", "a", None, TENANT, None)
        assert a["id"] != b["id"]

    def test_two_aws_keys_have_distinct_access_keys(self) -> None:
        a = generate_token("aws_key", "a", None, TENANT, None)
        b = generate_token("aws_key", "a", None, TENANT, None)
        assert a["metadata_"]["token_data"]["access_key_id"] != b["metadata_"]["token_data"]["access_key_id"]


class TestGenerateTokenShape:
    def test_aws_key_has_expected_prefix_and_length(self) -> None:
        record = generate_token("aws_key", "k", None, TENANT, None)
        td = record["metadata_"]["token_data"]
        assert td["access_key_id"].startswith("AKIA")
        assert len(td["access_key_id"]) == 20
        assert td["secret_access_key"]  # non-empty

    def test_url_token_is_https(self) -> None:
        record = generate_token("url", "u", None, TENANT, None)
        assert record["metadata_"]["token_data"]["url"].startswith("https://")

    def test_email_token_uses_canary_alias(self) -> None:
        record = generate_token("email", "e", None, TENANT, None)
        email = record["metadata_"]["token_data"]["email"]
        assert email.startswith("canary+")
        assert email.endswith("@example.com")

    def test_dns_token_is_subdomain(self) -> None:
        record = generate_token("dns", "d", None, TENANT, None)
        fqdn = record["metadata_"]["token_data"]["fqdn"]
        assert fqdn.endswith(".canary.example.com")

    def test_api_key_token_starts_with_sk(self) -> None:
        record = generate_token("api_key", "a", None, TENANT, None)
        assert record["metadata_"]["token_data"]["api_key"].startswith("sk-")

    def test_file_token_has_checksum(self) -> None:
        record = generate_token("file", "f", None, TENANT, None)
        td = record["metadata_"]["token_data"]
        assert re.fullmatch(r"[0-9a-f]{64}", td["checksum"])
        assert td["filename"].endswith(".zip")


class TestGenerateTokenTtl:
    def test_default_ttl_uses_settings(self) -> None:
        record = generate_token("custom", "c", None, TENANT, None)
        # default settings.token_ttl_days = 365
        delta = record["expires_at"] - datetime.now(UTC)
        assert delta.days >= 360
        assert delta.days <= 366

    def test_explicit_ttl_overrides_default(self) -> None:
        record = generate_token("custom", "c", None, TENANT, None, ttl_days=7)
        delta = record["expires_at"] - datetime.now(UTC)
        assert 6 <= delta.days <= 7

    def test_zero_ttl_is_respected(self) -> None:
        record = generate_token("custom", "c", None, TENANT, None, ttl_days=0)
        delta = record["expires_at"] - datetime.now(UTC)
        # Same day, slightly negative or near zero
        assert delta.total_seconds() < 60

    def test_metadata_is_merged_with_token_data(self) -> None:
        meta = {"label": "phishing-trap", "owner": "soc"}
        record = generate_token("custom", "c", None, TENANT, None, metadata=meta)
        assert record["metadata_"]["label"] == "phishing-trap"
        assert record["metadata_"]["owner"] == "soc"
        assert "token_data" in record["metadata_"]
