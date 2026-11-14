"""Tests for the audit-log ``changes`` redaction & size-cap layer.

Why these matter
----------------
``audit_log.changes`` is JSONB on an immutable, RLS-scoped table. Once a
secret lands in it, you cannot delete or rewrite it through the normal
SQL path — the same property that makes audit useful for compliance
makes it dangerous if we ever persist a raw password / token / API key.

The redactor is the choke-point that prevents that. These tests pin the
following contract:

1. Sensitive-looking keys are masked at every nesting level.
2. The pattern set is case-insensitive and matches dashed/underscored
   variants ("api_key", "api-key", "API-Key").
3. Lists of dicts (e.g. role bindings, change deltas) are redacted too.
4. Oversized payloads are reduced to a marker row rather than persisted.
5. The redactor never crashes on malformed input — audit must not
   break the originating mutation.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.services.audit_redaction import (
    REDACTED_SENTINEL,
    redact_changes,
)


def _is_redacted(value: Any) -> bool:
    return value == REDACTED_SENTINEL


class TestSensitiveKeyMatching:
    """Keys that *look* like secrets must be redacted regardless of casing."""

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "Password",
            "PASSWORD",
            "passwd",
            "secret",
            "client_secret",
            "client-secret",
            "ClientSecret",
            "token",
            "api_key",
            "api-key",
            "ApiKey",
            "private_key",
            "credential",
            "authorization",
            "auth",
            "refresh_token",
            "access_token",
            "session_id",
            "cookie",
            "otp",
            "mfa_code",
            "recovery_code",
            "webhook_secret",
            "signing_key",
        ],
    )
    def test_top_level_sensitive_key_redacted(self, key: str):
        out = redact_changes({key: "super-sensitive-value"})
        assert out is not None
        assert _is_redacted(out[key]), f"key {key!r} should have been masked but was {out[key]!r}"

    def test_non_sensitive_keys_pass_through(self):
        """Innocuous keys must NOT be touched — false positives erode trust."""
        payload = {
            "title": "Suspicious login from 1.2.3.4",
            "severity": "high",
            "count": 7,
            "tags": ["aws", "iam"],
        }
        out = redact_changes(payload)
        assert out == payload

    def test_substring_match_redacts(self):
        """A field named ``user_password_hash`` is still sensitive."""
        out = redact_changes({"user_password_hash": "$2b$..."})
        assert _is_redacted(out["user_password_hash"])


class TestNestedStructures:
    """Sensitive keys nested in dicts and lists must still be masked."""

    def test_nested_dict(self):
        payload = {
            "user": {
                "email": "a@b.com",
                "password": "p4ssw0rd",
                "profile": {"api_key": "sk-abc"},
            }
        }
        out = redact_changes(payload)
        assert out["user"]["email"] == "a@b.com"
        assert _is_redacted(out["user"]["password"])
        assert _is_redacted(out["user"]["profile"]["api_key"])

    def test_list_of_dicts(self):
        payload = {
            "bindings": [
                {"role": "admin", "token": "t1"},
                {"role": "viewer", "token": "t2"},
            ]
        }
        out = redact_changes(payload)
        assert [b["role"] for b in out["bindings"]] == ["admin", "viewer"]
        assert all(_is_redacted(b["token"]) for b in out["bindings"])

    def test_change_delta_tuple_form(self):
        """Audit emits ``{"field": [before, after]}`` deltas; lists of scalars must pass through."""
        out = redact_changes({"status": ["open", "investigating"]})
        assert out["status"] == ["open", "investigating"]


class TestPassthroughs:
    def test_none_returns_none(self):
        assert redact_changes(None) is None

    def test_empty_dict_returns_empty(self):
        assert redact_changes({}) == {}

    def test_does_not_mutate_input(self):
        original = {"password": "x", "ok": 1}
        snapshot = json.loads(json.dumps(original))
        redact_changes(original)
        assert original == snapshot, "redact_changes must not mutate caller's dict"


class TestSizeCap:
    """Oversized payloads must be capped instead of persisted as-is."""

    def test_oversized_payload_replaced_with_marker(self, monkeypatch):
        # Lower the cap to make the test fast and deterministic.
        monkeypatch.setenv("AISOC_AUDIT_MAX_CHANGES_BYTES", "256")
        # ~10KB of content — comfortably over 256 bytes when JSON-encoded.
        payload = {"data": "x" * 10_000}
        out = redact_changes(payload)
        assert out is not None
        # The marker row should be JSON-serializable and substantially
        # smaller than the original.
        encoded = json.dumps(out)
        assert len(encoded) < 1024
        # It should advertise WHY the payload was redacted.
        assert "truncated" in json.dumps(out).lower() or "size" in json.dumps(out).lower()

    def test_under_cap_passes_through(self, monkeypatch):
        monkeypatch.setenv("AISOC_AUDIT_MAX_CHANGES_BYTES", "65536")
        payload = {"title": "ok", "count": 3}
        out = redact_changes(payload)
        assert out == payload


class TestRobustness:
    """The redactor must never crash on weird input."""

    def test_exotic_value_types_do_not_raise(self):
        class Custom:
            def __repr__(self) -> str:
                return "Custom()"

        # Some endpoints accidentally pass non-JSON types. The redactor
        # should still produce SOMETHING JSON-encodable rather than
        # propagating a TypeError up into the request handler.
        out = redact_changes({"thing": Custom()})
        assert out is not None
        # The resulting payload must round-trip through JSON.
        json.dumps(out, default=str)

    def test_deeply_nested_input_does_not_blow_stack(self):
        # Construct a 50-deep nested dict. The redactor caps recursion
        # internally; we only check it doesn't recurse without bound.
        payload: dict[str, Any] = {"level": 0}
        cursor = payload
        for i in range(1, 50):
            cursor["next"] = {"level": i, "password": "p"}
            cursor = cursor["next"]
        out = redact_changes(payload)
        assert out is not None
