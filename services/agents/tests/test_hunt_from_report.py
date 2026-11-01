"""Hunting from a threat report, without trusting the report.

Wave 2, Phase 5.1.

The five constraints under test, each of which is a thing that goes wrong
otherwise:

1. **Off by default, per tenant.** Outbound traffic from a security platform
   must not be acquired by upgrading, and the refusal has its own class so a
   caller renders "not enabled" rather than a network error — which would
   send somebody to debug connectivity that was never attempted.
2. **The guard is a validator, not a fetcher.** `validate_outbound_url`
   resolves and refuses private addresses; it does not bound a response, so
   the size cap is this module's job, and a `Content-Length` is a claim by
   the server being fetched rather than a bound.
3. **Redirects are not followed**, because a redirect is a second URL the
   guard never saw.
4. **Extraction is deterministic and carries its location**, so the list a
   reviewer approves is not itself model output and can actually be checked
   against the source.
5. **Indicators become closed-schema clauses with values as values**, never
   query text — and an indicator kind with no field is refused rather than
   hunted on a guessed one, because a hash searched as a hostname matches
   nothing and reads as "clean".
"""

from __future__ import annotations

import pytest
from app.hunt.from_report import (
    INDICATOR_FIELDS,
    MAX_REPORT_BYTES,
    ReportDisabled,
    ReportFetchError,
    draft_clauses,
    extract_indicators,
    fetch_report,
)

REPORT = """\
# ACME Loader campaign

The loader beaconed to 203.0.113.77 and to evil-c2[.]example.net over
hxxps://evil-c2[.]example.net/gate.php, dropping a payload with SHA-256
5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90.

Exploitation used CVE-2026-12345 (see https://github.com/acme/advisory).
Mapped to T1059.001 and T1105.
Related sample: notepad.exe
"""


# ── Fetching ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetching_is_off_unless_the_tenant_enabled_it():
    with pytest.raises(ReportDisabled, match="not enabled"):
        await fetch_report("https://example.com/report", enabled=False)


def test_the_switch_cannot_be_acquired_by_forgetting_it():
    """`enabled` is a *required* keyword, with no default at all.

    Found by a negative control that did not fire: giving `enabled` a default
    of `True` left all eighteen other cases passing, because every one of
    them passes the argument explicitly. A property stated in a docstring and
    exercised only on the path that sets it is not gated — a caller added
    later simply omits it and acquires outbound fetching silently.

    Asserted on the signature rather than by calling, because calling it
    wrongly is what must be impossible.
    """
    import inspect

    parameter = inspect.signature(fetch_report).parameters["enabled"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.asyncio
async def test_a_disabled_tenant_is_refused_before_any_network_work():
    """Its own class, so the console does not render a network error."""
    with pytest.raises(ReportDisabled) as exc:
        await fetch_report("http://127.0.0.1/report", enabled=False)
    # Not an SSRF complaint: the switch is checked first, so an operator is
    # told the thing they can act on.
    assert "not enabled" in str(exc.value)
    assert isinstance(exc.value, ReportFetchError)


@pytest.mark.asyncio
async def test_a_private_address_is_refused_by_the_existing_guard():
    with pytest.raises(ReportFetchError, match="refusing to fetch"):
        await fetch_report("http://169.254.169.254/latest/meta-data/", enabled=True)


@pytest.mark.asyncio
async def test_the_body_is_bounded_even_when_the_server_keeps_sending(monkeypatch):
    """The guard does not bound a response, so this module must.

    The server here declares nothing and simply streams; a `Content-Length`
    would be a claim by the host being fetched and is not what bounds this.
    """
    import httpx

    sent = 1024 * 32

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * sent * 10)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        text, truncated = await fetch_report("https://example.com/report", enabled=True, max_bytes=sent, client=client)
    assert truncated is True
    assert len(text) == sent


@pytest.mark.asyncio
async def test_a_small_report_is_not_reported_as_truncated(monkeypatch):
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=REPORT.encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        text, truncated = await fetch_report("https://example.com/r", enabled=True, client=client)
    assert truncated is False
    assert "ACME Loader" in text


@pytest.mark.asyncio
async def test_an_error_status_is_surfaced_rather_than_parsed():
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"not found")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ReportFetchError, match="404"):
            await fetch_report("https://example.com/r", enabled=True, client=client)


def test_the_default_size_bound_is_set_and_small_enough_to_matter():
    assert 0 < MAX_REPORT_BYTES <= 8 * 1024 * 1024


# ── Extraction ──────────────────────────────────────────────────────────────


def test_defanged_indicators_are_refanged_before_matching():
    """A real write-up prints `[.]` and `hxxps`; matching the literal finds
    nothing in exactly the documents this feature exists for."""
    indicators, _, _ = extract_indicators(REPORT)
    domains = {i.value for i in indicators if i.kind == "domain"}
    assert "evil-c2.example.net" in domains


def test_every_indicator_carries_where_it_was_found():
    """A bare list of forty strings cannot be reviewed; a line can."""
    indicators, _, _ = extract_indicators(REPORT)
    ip = next(i for i in indicators if i.kind == "ipv4")
    assert ip.value == "203.0.113.77"
    assert ip.line > 0
    assert "beaconed" in ip.excerpt


def test_hashes_and_cves_are_extracted():
    indicators, _, _ = extract_indicators(REPORT)
    kinds = {i.kind for i in indicators}
    assert "sha256" in kinds
    assert "cve" in kinds
    cve = next(i for i in indicators if i.kind == "cve")
    assert cve.value == "CVE-2026-12345"


def test_attack_techniques_are_collected_separately():
    _, techniques, _ = extract_indicators(REPORT)
    assert "T1059.001" in techniques
    assert "T1105" in techniques


def test_a_filename_is_not_extracted_as_a_domain():
    """`notepad.exe` matches a domain regex and is not a domain.

    Hunting on it produces matches that look like the campaign and are not.
    """
    indicators, _, _ = extract_indicators(REPORT)
    domains = {i.value for i in indicators if i.kind == "domain"}
    assert "notepad.exe" not in domains


def test_ubiquitous_domains_are_not_offered_as_indicators():
    """`github.com` appears in every write-up.

    Hunting on it matches the whole estate, which reads as a confirmed
    compromise rather than as a bad indicator.
    """
    indicators, _, _ = extract_indicators(REPORT)
    domains = {i.value for i in indicators if i.kind == "domain"}
    assert "github.com" not in domains


def test_indicators_are_deduplicated():
    text = "1.2.3.4 and 1.2.3.4 again\nand 1.2.3.4 once more"
    indicators, _, _ = extract_indicators(text)
    assert len([i for i in indicators if i.kind == "ipv4"]) == 1


def test_indicators_over_the_bound_are_counted_rather_than_dropped():
    """A reviewer told "here are 60" would otherwise believe that was all."""
    text = "\n".join(f"10.0.{a}.{b}" for a in range(4) for b in range(10))
    indicators, _, skipped = extract_indicators(text, limit=5)
    assert len(indicators) == 5
    assert skipped == 35


# ── Drafting ────────────────────────────────────────────────────────────────

ALLOWED = frozenset({"destination_ip", "destination_domain", "file_hash"})


def test_indicators_become_closed_schema_clauses_with_values_as_values():
    indicators, _, _ = extract_indicators(REPORT)
    clauses, _ = draft_clauses(indicators, allowed_fields=ALLOWED)
    assert clauses
    for clause in clauses:
        assert set(clause) == {"field", "operator", "value"}
        assert clause["field"] in ALLOWED
        assert clause["operator"] == "equals"
        # The value is a value. Nothing here is query text.
        assert not any(token in clause["value"].lower() for token in ("select ", " or ", "--", ";"))


def test_an_indicator_kind_with_no_field_is_refused_not_guessed():
    """A hash searched as a hostname matches nothing and reads as clean."""
    assert "cve" not in INDICATOR_FIELDS
    indicators, _, _ = extract_indicators(REPORT)
    clauses, refusals = draft_clauses(indicators, allowed_fields=ALLOWED)
    assert any("CVE-2026-12345" in r for r in refusals)
    assert all(c["field"] != "cve" for c in clauses)


def test_a_field_the_deployment_lacks_is_refused_rather_than_emitted():
    """Otherwise a human approves a plan that fails validation afterwards."""
    indicators, _, _ = extract_indicators(REPORT)
    clauses, refusals = draft_clauses(indicators, allowed_fields=frozenset({"destination_ip"}))
    assert any("file_hash" in r for r in refusals)
    assert {c["field"] for c in clauses} == {"destination_ip"}
