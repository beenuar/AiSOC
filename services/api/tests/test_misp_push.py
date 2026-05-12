"""Unit tests for MISP push (Stage 3 #20).

The MISP push surface lives at three layers and each is tested in isolation:

1. **Pure mappers** in ``app.services.misp_push`` — STIX → MISP attribute /
   event translation. No I/O, no network, deterministic given the input.
2. **``MispPushClient``** — async wrapper around the MISP REST API. We
   exercise the configured / unconfigured branches and the air-gap chokepoint
   without ever opening a real socket: ``httpx.AsyncClient`` is patched at
   the class level using ``unittest.mock.patch`` and ``MockTransport``,
   matching the convention used in ``test_connectors_endpoint.py``.
3. **``stix_taxii.py`` endpoints + helpers** — the orchestration layer that
   converts a successful push into a structured ``MispPushResult`` and the
   admin endpoints (``/misp/health`` and ``/misp/dry-run``).

The endpoint tests mount the ``stix_taxii`` router on a stub ``FastAPI``
app — exactly the pattern from ``test_demo_mode.py`` — so we don't have to
spin up the full app (auth middleware, DB, etc.) just to verify routing
and request/response shape. The real production app composition is covered
by ``test_security_defaults.py``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from app.api.v1.endpoints import stix_taxii
from app.api.v1.endpoints.stix_taxii import (
    MispPushResult,
    STIXBundle,
    STIXIndicator,
    _push_bundle_or_swallow,
    _push_indicator_or_swallow,
    _should_push,
)
from app.api.v1.endpoints.stix_taxii import (
    router as stix_router,
)
from app.core.airgap import AirgapViolation
from app.core.config import settings
from app.services.misp_push import (
    MispNotConfigured,
    MispPushClient,
    MispPushError,
    ParsedPattern,
    confidence_to_threat_level,
    parse_stix_pattern,
    stix_bundle_to_misp_event,
    stix_indicator_to_misp_attribute,
    stix_indicator_to_misp_event,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ── Pure mapper tests ───────────────────────────────────────────────────────


class TestParseStixPattern:
    """``parse_stix_pattern`` is the load-bearing translation primitive.

    A regression here silently drops indicators on the floor instead of
    pushing them, which would be invisible to the operator until they
    notice their MISP feed is empty. Cover every supported observable
    explicitly (one test per branch) so the table-of-regexes can never
    regress without somebody removing a test.
    """

    @pytest.mark.parametrize(
        ("pattern", "expected_type", "expected_category", "expected_value"),
        [
            (
                "[ipv4-addr:value = '198.51.100.47']",
                "ip-dst",
                "Network activity",
                "198.51.100.47",
            ),
            (
                "[ipv6-addr:value = '2001:db8::1']",
                "ip-dst",
                "Network activity",
                "2001:db8::1",
            ),
            (
                "[domain-name:value = 'evil.example.com']",
                "domain",
                "Network activity",
                "evil.example.com",
            ),
            (
                "[url:value = 'https://drop.evil.example/upload']",
                "url",
                "Network activity",
                "https://drop.evil.example/upload",
            ),
            (
                "[email-addr:value = 'cfo@spoof.example']",
                "email-src",
                "Payload delivery",
                "cfo@spoof.example",
            ),
            (
                "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                "md5",
                "Payload delivery",
                "d41d8cd98f00b204e9800998ecf8427e",
            ),
            (
                "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
                "sha1",
                "Payload delivery",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            (
                "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                "sha256",
                "Payload delivery",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                (
                    "[file:hashes.'SHA-512' = '"
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                    "']"
                ),
                "sha512",
                "Payload delivery",
                (
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                ),
            ),
            (
                "[file:name = 'invoice.exe']",
                "filename",
                "Payload delivery",
                "invoice.exe",
            ),
        ],
    )
    def test_supported_patterns(
        self,
        pattern: str,
        expected_type: str,
        expected_category: str,
        expected_value: str,
    ) -> None:
        result = parse_stix_pattern(pattern)
        assert isinstance(result, ParsedPattern)
        assert result.misp_type == expected_type
        assert result.misp_category == expected_category
        assert result.value == expected_value

    def test_empty_pattern_returns_none(self) -> None:
        """Empty / falsy patterns short-circuit to ``None`` without raising.

        Bundle pushes feed every object through this function; a single
        malformed indicator must not blow up the entire push.
        """
        assert parse_stix_pattern("") is None

    def test_unknown_pattern_returns_none(self) -> None:
        """STIX patterns we don't yet translate return ``None`` (skip-and-log).

        This contract is what lets us add new observable types without
        breaking existing callers.
        """
        # ``process:name`` is valid STIX but isn't in the MISP table.
        assert parse_stix_pattern("[process:name = 'svchost.exe']") is None

    def test_case_insensitive_observable_prefix(self) -> None:
        """STIX is technically case-sensitive but we match leniently.

        Some upstream tools (Microsoft Sentinel exporter, in particular)
        emit ``IPv4-Addr`` instead of ``ipv4-addr``. Matching on those is
        cheap and avoids a foot-gun.
        """
        assert parse_stix_pattern("[IPv4-Addr:value = '10.0.0.1']") == ParsedPattern(
            misp_type="ip-dst", misp_category="Network activity", value="10.0.0.1"
        )


class TestConfidenceToThreatLevel:
    """STIX confidence (0-100) → MISP threat_level_id (1-4) mapping.

    The boundary values matter for SOC tuning — operators set alert
    thresholds based on ``threat_level_id`` so a wrong cutoff means
    an indicator either spams them or hides from them.
    """

    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (100, 1),  # high
            (90, 1),
            (80, 1),  # boundary: still high
            (79, 2),  # boundary: drops to medium
            (50, 2),  # boundary: still medium
            (49, 3),  # boundary: drops to low
            (20, 3),  # boundary: still low
            (19, 4),  # boundary: undefined
            (0, 4),
        ],
    )
    def test_confidence_buckets(self, confidence: int, expected: int) -> None:
        assert confidence_to_threat_level(confidence) == expected

    def test_none_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``None`` confidence (STIX field is optional) defers to settings."""
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_THREAT_LEVEL", 3)
        assert confidence_to_threat_level(None) == 3


class TestStixIndicatorToMispAttribute:
    """Attribute-level mapping: shape, defaults, and label propagation."""

    def test_translatable_pattern_yields_attribute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_DISTRIBUTION", 1)
        ind = {
            "pattern": "[ipv4-addr:value = '198.51.100.47']",
            "name": "C2 server",
            "description": "APT-42 staging IP",
            "labels": ["apt-42", "c2"],
        }
        attr = stix_indicator_to_misp_attribute(ind)
        assert attr is not None
        assert attr["type"] == "ip-dst"
        assert attr["category"] == "Network activity"
        assert attr["value"] == "198.51.100.47"
        assert attr["to_ids"] is True
        # Distribution falls back to settings when not overridden.
        assert attr["distribution"] == 1
        # Description wins over name as the comment.
        assert attr["comment"] == "APT-42 staging IP"
        # Labels surface as MISP tags with the ``aisoc:`` prefix so an
        # operator can filter for them.
        assert {tag["name"] for tag in attr["Tag"]} == {"aisoc:apt-42", "aisoc:c2"}

    def test_unknown_pattern_returns_none(self) -> None:
        assert stix_indicator_to_misp_attribute({"pattern": "[process:name = 'x']"}) is None

    def test_explicit_distribution_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The caller can force a distribution per-attribute.

        Bundles use this to keep every attribute aligned with the event-
        level distribution, regardless of the running defaults.
        """
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_DISTRIBUTION", 0)
        attr = stix_indicator_to_misp_attribute({"pattern": "[ipv4-addr:value = '10.0.0.1']"}, distribution=3)
        assert attr is not None
        assert attr["distribution"] == 3

    def test_no_labels_emits_no_tag_field(self) -> None:
        """We must not emit an empty ``Tag: []`` — MISP rejects that.

        Verified against MISP 2.4.x; an empty array trips a JSON schema
        check on the receiving end.
        """
        attr = stix_indicator_to_misp_attribute({"pattern": "[ipv4-addr:value = '10.0.0.1']"})
        assert attr is not None
        assert "Tag" not in attr

    def test_falls_back_to_name_when_no_description(self) -> None:
        attr = stix_indicator_to_misp_attribute(
            {
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "name": "fallback name",
            }
        )
        assert attr is not None
        assert attr["comment"] == "fallback name"

    def test_no_name_or_description_yields_empty_comment(self) -> None:
        attr = stix_indicator_to_misp_attribute({"pattern": "[ipv4-addr:value = '10.0.0.1']"})
        assert attr is not None
        assert attr["comment"] == ""


class TestStixIndicatorToMispEvent:
    def test_indicator_event_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A single STIX indicator becomes a single-attribute MISP event."""
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_DISTRIBUTION", 0)
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_THREAT_LEVEL", 4)
        monkeypatch.setattr(settings, "MISP_PUSH_DEFAULT_ANALYSIS", 0)
        indicator = {
            "id": "indicator--abc",
            "name": "C2 IP",
            "pattern": "[ipv4-addr:value = '198.51.100.47']",
            "confidence": 95,
        }
        event = stix_indicator_to_misp_event(indicator)
        assert event is not None
        body = event["Event"]
        assert body["info"] == "C2 IP"
        assert body["distribution"] == 0
        # Confidence 95 → threat level 1 (high), overriding default 4.
        assert body["threat_level_id"] == 1
        assert body["analysis"] == 0
        assert len(body["Attribute"]) == 1
        # Tags include source provenance + the indicator ID.
        tag_names = {t["name"] for t in body["Tag"]}
        assert "aisoc:source=stix" in tag_names
        assert "aisoc:indicator=indicator--abc" in tag_names

    def test_indicator_event_returns_none_on_unknown_pattern(self) -> None:
        assert stix_indicator_to_misp_event({"id": "indicator--x", "pattern": "[process:name = 'svchost.exe']"}) is None

    def test_indicator_event_falls_back_to_id_when_no_name(self) -> None:
        event = stix_indicator_to_misp_event({"id": "indicator--zzz", "pattern": "[ipv4-addr:value = '10.0.0.1']"})
        assert event is not None
        assert event["Event"]["info"] == "AiSOC indicator indicator--zzz"


class TestStixBundleToMispEvent:
    def test_bundle_aggregates_translatable_indicators(self) -> None:
        bundle = {
            "id": "bundle--xyz",
            "objects": [
                {"type": "indicator", "name": "ip", "pattern": "[ipv4-addr:value = '10.0.0.1']"},
                {"type": "indicator", "name": "dom", "pattern": "[domain-name:value = 'evil.example']"},
                # Non-indicator object — must be ignored, not skipped.
                {"type": "identity", "name": "AiSOC"},
                # Translatable miss — counts toward _skipped.
                {"type": "indicator", "pattern": "[process:name = 'x']"},
            ],
        }
        event = stix_bundle_to_misp_event(bundle)
        assert event["_skipped"] == 1
        assert event["_attribute_count"] == 2
        assert len(event["Event"]["Attribute"]) == 2
        # Bundle ID propagates as a tag for downstream filtering.
        tag_names = {t["name"] for t in event["Event"]["Tag"]}
        assert "aisoc:bundle=bundle--xyz" in tag_names

    def test_bundle_event_info_uses_indicator_names(self) -> None:
        """When ``info`` is omitted, the event title surfaces the first 3 names.

        Operators eyeballing a list of MISP events benefit from a real
        title rather than a UUID. We cap at three so a 100-indicator
        bundle doesn't generate a 1 KB ``info`` string.
        """
        bundle = {
            "id": "bundle--xyz",
            "objects": [{"type": "indicator", "name": f"name{i}", "pattern": f"[ipv4-addr:value = '10.0.0.{i}']"} for i in range(5)],
        }
        event = stix_bundle_to_misp_event(bundle)
        info = event["Event"]["info"]
        assert "name0; name1; name2" in info
        assert "name3" not in info

    def test_bundle_explicit_info_wins(self) -> None:
        event = stix_bundle_to_misp_event({"id": "bundle--xyz", "objects": []}, info="Operator-supplied label")
        assert event["Event"]["info"] == "Operator-supplied label"

    def test_empty_bundle_yields_zero_attributes(self) -> None:
        """A bundle with no objects must not crash — it returns an empty event.

        The ``MispPushClient`` is responsible for refusing to push these
        (so we don't spam MISP with empty events), but the mapper itself
        is permissive.
        """
        event = stix_bundle_to_misp_event({"id": "bundle--xyz", "objects": []})
        assert event["_attribute_count"] == 0
        assert event["_skipped"] == 0
        assert event["Event"]["Attribute"] == []


# ── MispPushClient tests ────────────────────────────────────────────────────


class TestMispPushClientConfig:
    """Configuration / constructor behaviour — no network."""

    def test_unconfigured_when_url_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "")
        monkeypatch.setattr(settings, "MISP_API_KEY", "secret")
        client = MispPushClient()
        assert client.configured is False

    def test_unconfigured_when_api_key_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal")
        monkeypatch.setattr(settings, "MISP_API_KEY", "")
        client = MispPushClient()
        assert client.configured is False

    def test_configured_when_both_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal/")
        monkeypatch.setattr(settings, "MISP_API_KEY", "secret")
        client = MispPushClient()
        assert client.configured is True
        # Trailing slash is stripped so URL composition is predictable.
        assert client._url == "https://misp.internal"

    def test_explicit_args_override_settings(self) -> None:
        client = MispPushClient(
            url="https://override.example/",
            api_key="explicit-key",
            verify_ssl=False,
            timeout=5.0,
        )
        assert client._url == "https://override.example"
        assert client._api_key == "explicit-key"
        assert client._verify_ssl is False
        assert client._timeout == 5.0


def _patch_async_client(monkeypatch: pytest.MonkeyPatch, handler):
    """Replace ``app.services.misp_push.httpx.AsyncClient`` with a mock-transport one.

    Mirrors the convention from ``test_connectors_endpoint.py``: we
    swap the symbol used by the production code so it gets a real
    ``AsyncClient`` (which knows how to ``async with`` itself) backed
    by a synthetic transport. Patching with ``unittest.mock.patch`` and
    setting ``return_value`` doesn't work here because ``MagicMock``
    intercepts ``__aenter__`` and returns another mock instead of the
    underlying client.

    We capture ``httpx.AsyncClient`` *before* the patch so the factory
    doesn't recurse into itself once the symbol on the production
    module is rebound.
    """

    real_async_client = httpx.AsyncClient

    def _factory(**kwargs: Any) -> httpx.AsyncClient:
        # Strip ``transport`` if production code ever passes one — we
        # always want our handler to win.
        kwargs.pop("transport", None)
        return real_async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("app.services.misp_push.httpx.AsyncClient", _factory)


class TestMispPushClientHealthCheck:
    """``health_check`` — auth header, air-gap, error mapping.

    We swap ``httpx.AsyncClient`` for a factory that builds a real
    ``AsyncClient`` backed by a ``MockTransport``. This is the same
    pattern ``test_connectors_endpoint.py`` uses, and it sidesteps the
    foot-gun where ``MagicMock`` proxies the async context manager
    instead of returning the real client.
    """

    @pytest.mark.asyncio
    async def test_raises_when_unconfigured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "")
        monkeypatch.setattr(settings, "MISP_API_KEY", "")
        client = MispPushClient()
        with pytest.raises(MispNotConfigured):
            await client.health_check()

    @pytest.mark.asyncio
    async def test_blocked_by_airgap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Air-gap policy must short-circuit before any HTTP call."""
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(settings, "AISOC_AIRGAP_ALLOWLIST", [])
        client = MispPushClient(url="https://misp.public.example", api_key="k")
        with pytest.raises(AirgapViolation):
            await client.health_check()

    @pytest.mark.asyncio
    async def test_success_returns_user_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")

        async def _handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "k"
            assert request.url.path == "/users/view/me"
            return httpx.Response(
                200,
                json={
                    "User": {"email": "ops@example.com"},
                    "Role": {"name": "publisher"},
                },
            )

        _patch_async_client(monkeypatch, _handler)
        result = await client.health_check()
        assert result == {
            "ok": True,
            "url": "https://misp.internal",
            "user": "ops@example.com",
            "role": "publisher",
        }

    @pytest.mark.asyncio
    async def test_401_surfaces_as_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="bad")

        async def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"errors": "invalid key"})

        _patch_async_client(monkeypatch, _handler)
        with pytest.raises(MispPushError, match="auth failed"):
            await client.health_check()

    @pytest.mark.asyncio
    async def test_5xx_surfaces_as_push_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")

        async def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="upstream down")

        _patch_async_client(monkeypatch, _handler)
        with pytest.raises(MispPushError, match="503"):
            await client.health_check()

    @pytest.mark.asyncio
    async def test_connection_error_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A network-level ``RequestError`` is wrapped, not propagated raw.

        Endpoints catch ``MispPushError`` to render structured 5xx
        responses; leaking the raw ``httpx`` exception type would mean
        every caller has to know about the transport library.
        """
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")

        async def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns fail")

        _patch_async_client(monkeypatch, _handler)
        with pytest.raises(MispPushError, match="unreachable"):
            await client.health_check()


class TestMispPushClientPushEvent:
    @pytest.mark.asyncio
    async def test_strips_internal_fields_before_post(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``_skipped`` / ``_attribute_count`` are bookkeeping, not MISP fields.

        Posting them to MISP would either be silently ignored or trip
        a strict-mode JSON validator depending on MISP version. Either
        way they have no business being on the wire.
        """
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")
        captured: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(
                200,
                json={"Event": {"id": "42", "uuid": "uuid-42"}},
            )

        event = {
            "Event": {"info": "test", "Attribute": []},
            "_skipped": 5,
            "_attribute_count": 2,
        }
        _patch_async_client(monkeypatch, _handler)
        result = await client.push_event(event)

        body = captured["body"].decode()
        assert "_skipped" not in body
        assert "_attribute_count" not in body
        assert result["misp_event_id"] == "42"
        assert result["misp_event_uuid"] == "uuid-42"
        assert result["url"] == "https://misp.internal/events/view/42"

    @pytest.mark.asyncio
    async def test_push_indicator_unknown_pattern_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If we can't translate the pattern we never open a socket.

        MISP would just reject the empty event anyway; failing fast
        keeps the air-gap audit log clean.
        """
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")
        with pytest.raises(MispPushError, match="cannot be mapped"):
            await client.push_indicator({"pattern": "[process:name = 'x']"})

    @pytest.mark.asyncio
    async def test_push_bundle_with_no_translatable_indicators_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")
        with pytest.raises(MispPushError, match="no MISP-translatable indicators"):
            await client.push_bundle(
                {
                    "id": "bundle--empty",
                    "objects": [{"type": "indicator", "pattern": "[process:name = 'x']"}],
                }
            )

    @pytest.mark.asyncio
    async def test_push_bundle_returns_attribute_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bundle pushes surface ``pushed_attributes`` / ``skipped_attributes``.

        These flow through to the API response so an operator can see
        "we mirrored 4/5 indicators; one was a process name we don't
        know how to express in MISP".
        """
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        client = MispPushClient(url="https://misp.internal", api_key="k")

        async def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"Event": {"id": "9", "uuid": "u-9"}})

        bundle = {
            "id": "bundle--mixed",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.1']"},
                {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.2']"},
                {"type": "indicator", "pattern": "[process:name = 'x']"},  # skipped
            ],
        }
        _patch_async_client(monkeypatch, _handler)
        result = await client.push_bundle(bundle)
        assert result["pushed_attributes"] == 2
        assert result["skipped_attributes"] == 1


# ── stix_taxii.py helper tests ──────────────────────────────────────────────


class TestShouldPush:
    """``_should_push`` is a one-liner but its precedence is load-bearing.

    Per-request override beats env default; env default beats hard-off.
    Get this wrong and operators either spam MISP or never push at all.
    """

    def test_explicit_true_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", False)
        assert _should_push(True) is True

    def test_explicit_false_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", True)
        assert _should_push(False) is False

    def test_none_falls_back_to_auto_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", True)
        assert _should_push(None) is True

    def test_none_falls_back_to_auto_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", False)
        assert _should_push(None) is False


def _stub_indicator() -> STIXIndicator:
    return STIXIndicator(
        id="indicator--test",
        created="2026-01-01T00:00:00+00:00",
        modified="2026-01-01T00:00:00+00:00",
        name="C2 server",
        pattern="[ipv4-addr:value = '198.51.100.47']",
        valid_from="2026-01-01T00:00:00+00:00",
        confidence=92,
        labels=["c2"],
    )


def _stub_bundle() -> STIXBundle:
    return STIXBundle(
        id="bundle--test",
        created="2026-01-01T00:00:00+00:00",
        objects=[
            {
                "type": "indicator",
                "name": "C2 server",
                "pattern": "[ipv4-addr:value = '198.51.100.47']",
            }
        ],
    )


class TestPushIndicatorOrSwallow:
    """End-to-end of the orchestration helper.

    The endpoint must return a 201 even when the MISP push fails — the
    publish is durable, the mirror is best-effort. These tests pin the
    structured ``MispPushResult`` we return for each failure mode.
    """

    @pytest.mark.asyncio
    async def test_unconfigured_returns_structured_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "")
        monkeypatch.setattr(settings, "MISP_API_KEY", "")
        result = await _push_indicator_or_swallow(_stub_indicator())
        assert result is not None
        assert result.pushed is False
        assert result.error is not None
        assert "not configured" in result.error.lower()

    @pytest.mark.asyncio
    async def test_airgap_violation_caught(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A real ``AirgapViolation`` from the client must NOT 500 the request."""
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.push_indicator = AsyncMock(side_effect=AirgapViolation("blocked"))
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        result = await _push_indicator_or_swallow(_stub_indicator())
        assert result is not None
        assert result.pushed is False
        assert result.error is not None and "Air-gap" in result.error

    @pytest.mark.asyncio
    async def test_push_error_caught(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.push_indicator = AsyncMock(side_effect=MispPushError("boom"))
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        result = await _push_indicator_or_swallow(_stub_indicator())
        assert result is not None
        assert result.pushed is False
        assert result.error == "boom"

    @pytest.mark.asyncio
    async def test_success_populates_event_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.push_indicator = AsyncMock(
            return_value={
                "ok": True,
                "misp_event_id": "42",
                "misp_event_uuid": "uuid-42",
                "url": "https://misp.example/events/view/42",
                "raw": {},
            }
        )
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        result = await _push_indicator_or_swallow(_stub_indicator())
        assert result == MispPushResult(
            pushed=True,
            misp_event_id="42",
            misp_event_uuid="uuid-42",
            url="https://misp.example/events/view/42",
        )


class TestPushBundleOrSwallow:
    @pytest.mark.asyncio
    async def test_success_includes_attribute_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bundle results must surface translation counts to the caller.

        This is the only way a downstream operator finds out their
        bundle was partially mirrored — the publish endpoint is 201
        regardless.
        """
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.push_bundle = AsyncMock(
            return_value={
                "ok": True,
                "misp_event_id": "9",
                "misp_event_uuid": "u9",
                "url": "https://misp.example/events/view/9",
                "pushed_attributes": 4,
                "skipped_attributes": 1,
            }
        )
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        result = await _push_bundle_or_swallow(_stub_bundle())
        assert result is not None
        assert result.pushed is True
        assert result.pushed_attributes == 4
        assert result.skipped_attributes == 1


# ── Endpoint tests (TestClient on a stub app) ───────────────────────────────


@pytest.fixture
def stub_app() -> FastAPI:
    """Mount only the stix_taxii router — keeps tests independent of auth/middleware.

    Same pattern as ``test_demo_mode.py``: the production composition
    is covered elsewhere; here we test routing + serialization only.
    """
    app = FastAPI()
    app.include_router(stix_router, prefix="/api/v1")
    return app


@pytest.fixture
def client(stub_app: FastAPI) -> TestClient:
    return TestClient(stub_app)


class TestCreateIndicatorEndpoint:
    def test_default_no_push(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without ``push_to_misp`` and with auto-push off, ``misp`` is null."""
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", False)
        resp = client.post(
            "/api/v1/threatintel/stix/indicators",
            json={
                "name": "demo",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "labels": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["misp"] is None

    def test_explicit_push_unconfigured_returns_error_payload(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """``?push_to_misp=true`` with no MISP creds returns a 201 + error.

        We deliberately do NOT 4xx — the publish itself succeeded, only
        the mirror failed. The operator finds out via the embedded
        ``misp.error`` field.
        """
        monkeypatch.setattr(settings, "MISP_URL", "")
        monkeypatch.setattr(settings, "MISP_API_KEY", "")
        resp = client.post(
            "/api/v1/threatintel/stix/indicators?push_to_misp=true",
            json={
                "name": "demo",
                "pattern": "[ipv4-addr:value = '10.0.0.2']",
                "labels": [],
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["misp"]["pushed"] is False
        assert "not configured" in body["misp"]["error"].lower()

    def test_auto_push_triggers_when_env_enabled(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """``MISP_PUSH_AUTO=true`` makes every publish attempt a push.

        We mock the push helper itself so this test stays pure — the
        helper logic is covered by ``TestPushIndicatorOrSwallow``.
        """
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", True)

        async def _ok_push(_indicator: STIXIndicator) -> MispPushResult:
            return MispPushResult(pushed=True, misp_event_id="7", url="x")

        monkeypatch.setattr(stix_taxii, "_push_indicator_or_swallow", _ok_push)
        resp = client.post(
            "/api/v1/threatintel/stix/indicators",
            json={
                "name": "demo",
                "pattern": "[ipv4-addr:value = '10.0.0.3']",
                "labels": [],
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["misp"]["pushed"] is True
        assert body["misp"]["misp_event_id"] == "7"

    def test_explicit_push_false_overrides_auto(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """``?push_to_misp=false`` must short-circuit even with auto on.

        Operators use this for reflective bulk replays where they don't
        want to spam MISP with the same indicator twice.
        """
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", True)

        called = False

        async def _track(_: STIXIndicator) -> MispPushResult:
            nonlocal called
            called = True
            return MispPushResult(pushed=True)

        monkeypatch.setattr(stix_taxii, "_push_indicator_or_swallow", _track)
        resp = client.post(
            "/api/v1/threatintel/stix/indicators?push_to_misp=false",
            json={
                "name": "demo",
                "pattern": "[ipv4-addr:value = '10.0.0.4']",
                "labels": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["misp"] is None
        assert called is False


class TestCreateBundleEndpoint:
    def test_empty_bundle_rejected(self, client: TestClient) -> None:
        """An empty ``objects`` list 400s — there's nothing to publish."""
        resp = client.post(
            "/api/v1/threatintel/stix/bundles",
            json={"objects": []},
        )
        assert resp.status_code == 400

    def test_push_to_misp_query_flag_works(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _ok_push(_b: STIXBundle) -> MispPushResult:
            return MispPushResult(
                pushed=True,
                misp_event_id="11",
                pushed_attributes=2,
                skipped_attributes=0,
            )

        monkeypatch.setattr(stix_taxii, "_push_bundle_or_swallow", _ok_push)
        resp = client.post(
            "/api/v1/threatintel/stix/bundles?push_to_misp=true",
            json={"objects": [{"type": "indicator", "name": "x", "pattern": "[ipv4-addr:value = '10.0.0.5']"}]},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["misp"]["pushed"] is True
        assert body["misp"]["pushed_attributes"] == 2


class TestMispHealthEndpoint:
    def test_unconfigured(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "")
        monkeypatch.setattr(settings, "MISP_API_KEY", "")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        monkeypatch.setattr(settings, "MISP_PUSH_AUTO", False)
        resp = client.get("/api/v1/threatintel/stix/misp/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is False
        assert body["ok"] is False
        assert body["airgapped"] is False
        assert body["auto_push"] is False
        assert body["error"] is not None

    def test_airgap_blocks_health_check(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Air-gap violations surface as ``ok=False`` + ``error`` not 5xx.

        Operators need to see "the policy blocked you" without being
        forced to read a stack trace.
        """
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(settings, "AISOC_AIRGAP_ALLOWLIST", [])

        resp = client.get("/api/v1/threatintel/stix/misp/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is True
        assert body["airgapped"] is True
        assert body["ok"] is False
        assert "Air-gap" in body["error"]

    def test_misp_push_error_surfaces_in_health(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.example")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.health_check = AsyncMock(side_effect=MispPushError("auth failed (401)"))
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        resp = client.get("/api/v1/threatintel/stix/misp/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["error"] == "auth failed (401)"

    def test_successful_health_check(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal")
        monkeypatch.setattr(settings, "MISP_API_KEY", "k")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)

        fake_client = MagicMock()
        fake_client.configured = True
        fake_client.health_check = AsyncMock(
            return_value={
                "ok": True,
                "url": "https://misp.internal",
                "user": "ops@example.com",
                "role": "publisher",
            }
        )
        monkeypatch.setattr(stix_taxii, "get_push_client", lambda: fake_client)

        resp = client.get("/api/v1/threatintel/stix/misp/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["user"] == "ops@example.com"
        assert body["role"] == "publisher"


class TestMispDryRunEndpoint:
    def test_indicator_dry_run_yields_event(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "indicator": {
                    "name": "preview",
                    "pattern": "[ipv4-addr:value = '198.51.100.99']",
                    "labels": ["test"],
                }
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["attribute_count"] == 1
        assert body["skipped_count"] == 0
        assert body["would_push_to"] == "https://misp.internal/events/add"
        assert body["airgap_blocked"] is False
        assert body["event"]["Event"]["Attribute"][0]["value"] == "198.51.100.99"

    def test_bundle_dry_run_aggregates(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.1']"},
                        {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']"},
                        {"type": "indicator", "pattern": "[process:name = 'x']"},  # skipped
                    ]
                }
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["attribute_count"] == 2
        assert body["skipped_count"] == 1

    def test_neither_indicator_nor_bundle_400s(self, client: TestClient) -> None:
        resp = client.post("/api/v1/threatintel/stix/misp/dry-run", json={})
        assert resp.status_code == 400
        assert "exactly one" in resp.json()["detail"]

    def test_both_indicator_and_bundle_400s(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "indicator": {
                    "name": "x",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "labels": [],
                },
                "bundle": {"objects": [{"type": "identity"}]},
            },
        )
        assert resp.status_code == 400

    def test_untranslatable_indicator_422s(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """The dry-run is the right place to surface an untranslatable pattern.

        The bulk publish endpoint is permissive (skips and logs) but
        ``/dry-run`` is explicitly diagnostic — operators run it to find
        out what would happen, so silence here would defeat the purpose.
        """
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.internal")
        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "indicator": {
                    "name": "broken",
                    "pattern": "[process:name = 'svchost.exe']",
                    "labels": [],
                }
            },
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert "not currently translatable" in detail

    def test_airgap_blocked_dry_run_returns_message(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """An air-gapped deployment surfaces ``airgap_blocked=true``.

        This is the single most important diagnostic for the
        air-gap-certified deployment story — operators verify with this
        endpoint that nothing will leak before they wire MISP into
        production traffic.
        """
        monkeypatch.setattr(settings, "MISP_URL", "https://misp.public.example")
        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(settings, "AISOC_AIRGAP_ALLOWLIST", [])

        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "indicator": {
                    "name": "any",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "labels": [],
                }
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["airgap_blocked"] is True
        assert body["airgap_message"] is not None
        # Even when blocked, the dry-run still returns the would-be event
        # so operators can review the payload offline.
        assert body["attribute_count"] == 1

    def test_no_misp_url_omits_would_push_to(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "MISP_URL", "")
        resp = client.post(
            "/api/v1/threatintel/stix/misp/dry-run",
            json={
                "indicator": {
                    "name": "x",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "labels": [],
                }
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["would_push_to"] is None
        assert body["airgap_blocked"] is False
