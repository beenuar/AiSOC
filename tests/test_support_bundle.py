"""A support bundle must be safe to email, or it will not be sent.

A bundle is by construction the most concentrated pile of configuration a
deployment produces, and its whole purpose is to leave the building. Getting
redaction wrong is worse than having no bundle at all.

These tests are almost entirely about what must *not* be in it. The
collection side is uninteresting: if it misses something, the next round of
questions catches it. If it leaks a credential, nothing catches it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "scripts" / "support_bundle.py"

spec = importlib.util.spec_from_file_location("support_bundle", MODULE_PATH)
assert spec and spec.loader
support_bundle = importlib.util.module_from_spec(spec)
sys.modules["support_bundle"] = support_bundle
spec.loader.exec_module(support_bundle)

redact = support_bundle.redact


class TestRedaction:
    @pytest.mark.parametrize(
        ("secret", "label"),
        [
            ("Bearer eyJhbGciOiJIUzI1NiJ9abcdefghij", "Bearer"),
            ("vault:v1:gAAAAABmZ2hpamtsbW5vcA", "vault"),
            ("sk-abcdefghijklmnopqrstuvwxyz", "api key"),
            ("AKIAIOSFODNN7EXAMPLE", "aws key"),
            ("ghp_abcdefghijklmnopqrstuvwxyz123456", "github token"),
            ("xoxb-1234567890-abcdefghijkl", "slack token"),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u",
                "jwt",
            ),
        ],
    )
    def test_credential_shapes_are_stripped(self, secret: str, label: str) -> None:
        out = redact(f"log line containing {secret} and more text")
        assert secret not in out, f"{label} survived redaction"
        assert "redacted" in out.lower()

    def test_credentials_in_a_connection_string_are_stripped(self) -> None:
        """How a DSN leaks: in a URL, in a log line, in a stack trace."""
        dsn = "postgresql+asyncpg://aisoc:hunter2@db.internal:5432/aisoc"
        out = redact(f"connecting to {dsn}")
        assert "hunter2" not in out
        assert "db.internal" in out, "the host is diagnostic and should survive"

    def test_a_private_key_block_is_stripped_whole(self) -> None:
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\nabcdefgh\n-----END RSA PRIVATE KEY-----"
        out = redact(f"config: {key}")
        assert "MIIEowIBAAKCAQEAxyz" not in out
        assert "redacted" in out

    def test_ordinary_text_is_untouched(self) -> None:
        """Over-redaction makes a bundle useless in a different way."""
        line = "2026-09-22 ERROR fusion: kafka consumer lag 4211 on aisoc.raw_events"
        assert redact(line) == line

    def test_redaction_is_applied_to_every_collected_string(self) -> None:
        """A redactor nothing calls is decoration."""
        source = MODULE_PATH.read_text(encoding="utf-8")
        # Every collector that returns free text must pass it through redact.
        for collector in ("collect_recent_errors", "collect_service_health"):
            start = source.index(f"def {collector}")
            body = source[start : source.index("\ndef ", start + 1)]
            assert "redact(" in body, f"{collector} does not redact its output"


class TestEnvironmentAllowList:
    def test_unknown_variables_are_not_valued(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Allow-list, not deny-list: a new setting is redacted by default.

        A deny-list means every secret-shaped variable added after today is
        exposed until someone remembers to extend it, and nobody remembers.
        """
        monkeypatch.setenv("AISOC_NEW_THING_ADDED_TOMORROW", "sensitive-value")
        collected = support_bundle.collect_environment()
        assert "sensitive-value" not in json.dumps(collected)
        assert "AISOC_NEW_THING_ADDED_TOMORROW" in collected["set_but_redacted"]

    def test_credential_named_variables_are_not_even_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The name alone can identify the customer and environment."""
        monkeypatch.setenv("AISOC_ACMEPROD_DB_PASSWORD", "x")
        collected = support_bundle.collect_environment()
        blob = json.dumps(collected)
        assert "ACMEPROD" not in blob
        assert collected["withheld_sensitive_names"] >= 1

    def test_allow_listed_flags_are_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bundle with no configuration in it answers nothing."""
        monkeypatch.setenv("AISOC_DEEP_INVESTIGATION", "false")
        monkeypatch.setenv("RETENTION_WORKER_DRY_RUN", "true")
        collected = support_bundle.collect_environment()
        assert collected["configured"]["AISOC_DEEP_INVESTIGATION"] == "false"
        assert collected["configured"]["RETENTION_WORKER_DRY_RUN"] == "true"

    def test_an_allow_listed_name_holding_a_secret_is_still_redacted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Belt and braces: allow-listing a name is not allow-listing a value."""
        monkeypatch.setenv("LOG_LEVEL", "debug token=ghp_abcdefghijklmnopqrstuvwxyz12")
        collected = support_bundle.collect_environment()
        assert "ghp_abcdefghij" not in json.dumps(collected)

    def test_an_overlap_between_the_two_lists_must_be_recorded(self) -> None:
        """A contradiction otherwise resolves silently, whichever way the code
        happens to check first."""
        for name in support_bundle.ENV_ALLOW_LIST:
            assert not support_bundle.SENSITIVE_NAME_RE.search(name), (
                f"{name} is allow-listed and matches the sensitive-name pattern. "
                f"If it is genuinely safe, move it to ALLOW_LIST_OVERRIDES with "
                f"the reason."
            )

    def test_every_override_states_why_it_is_safe(self) -> None:
        for name, reason in support_bundle.ALLOW_LIST_OVERRIDES.items():
            assert support_bundle.SENSITIVE_NAME_RE.search(name), (
                f"{name} does not match the sensitive pattern, so it needs no override — put it in ENV_ALLOW_LIST"
            )
            assert len(reason) > 20, f"{name} has no stated reason"

    def test_an_override_still_redacts_its_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Overriding the name check is not overriding value redaction."""
        monkeypatch.setenv("AISOC_CREDENTIAL_ENVELOPE", "local ghp_abcdefghijklmnopqrstuvwxyz1")
        collected = support_bundle.collect_environment()
        assert "ghp_abcdefghij" not in json.dumps(collected)


class TestBundleShape:
    def test_the_bundle_serialises(self) -> None:
        bundle = support_bundle.build_bundle(api_url="http://127.0.0.1:9", include_logs=False)
        json.dumps(bundle, default=str)
        assert bundle["schema_version"] == 1
        assert "versions" in bundle and "gates" in bundle

    def test_an_unreachable_api_is_a_finding_not_a_crash(self) -> None:
        """An unreachable API is usually the answer, not an obstacle to one."""
        health = support_bundle.collect_service_health("http://127.0.0.1:9")
        assert health["available"] is False
        assert "error" in health or "note" in health

    def test_logs_can_be_skipped_entirely(self) -> None:
        """Some deployments cannot let even redacted log text leave."""
        bundle = support_bundle.build_bundle(api_url="http://127.0.0.1:9", include_logs=False)
        assert "recent_errors" not in bundle

    def test_the_bundle_says_what_it_does_not_contain(self) -> None:
        """A recipient has to know it is safe to send without reading it all."""
        bundle = support_bundle.build_bundle(api_url="http://127.0.0.1:9", include_logs=False)
        readme = bundle["_readme"].lower()
        assert "redacted" in readme
        assert "no event data" in readme or "no event" in readme
