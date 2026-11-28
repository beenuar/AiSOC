"""Tests for the NetAPI keyless public feed client.

The two things this pins that are easy to get wrong:

* **Conditional requests.** The lists are rebuilt on the publisher's own
  schedule and are large (the domain list is megabytes). A poll that
  re-downloads an unchanged list wastes the bandwidth *and* pays the
  pipeline's per-indicator dedup cost for nothing, so an unchanged list has
  to cost a 304 and yield no indicators at all.
* **Refusing a payload that is not the feed.** The lists sit behind a CDN.
  An edge challenge page or an error page answers ``200`` with HTML, and
  without a sniff check every line of it becomes an "indicator".
"""

from __future__ import annotations

import httpx
import pytest
from app.clients.netapi import NetApiClient

pytestmark = pytest.mark.asyncio


_IPS = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
_DOMAINS = "evil.example\nbad.example.org\nphish.example.net\n"


def _transport(handler):
    return httpx.MockTransport(handler)


async def _collect(client, dataset):
    return [ioc async for ioc in client.iter_iocs(dataset)]


class TestParsing:
    async def test_ip_list_becomes_ip_iocs(self):
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=_IPS)))
        iocs = await _collect(client, client.dataset("ips"))

        assert [i["value"] for i in iocs] == ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
        assert {i["type"] for i in iocs} == {"ipv4-addr"}
        # The source name is what the fusion confidence scorer keys on; if it
        # is anything else the feed ingests and never influences a verdict.
        assert {i["source"] for i in iocs} == {"netapi"}
        assert iocs[0]["source_ref"] == "netapi:compromised-ips:1.2.3.4"
        assert "netapi" in iocs[0]["tags"]

    async def test_domain_list_becomes_domain_iocs(self):
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=_DOMAINS)))
        iocs = await _collect(client, client.dataset("domains"))

        assert [i["value"] for i in iocs] == ["evil.example", "bad.example.org", "phish.example.net"]
        assert {i["type"] for i in iocs} == {"domain-name"}
        assert {i["source"] for i in iocs} == {"netapi"}

    async def test_blank_lines_and_comments_are_skipped(self):
        body = "# NetAPI compromised IPs\n\n1.2.3.4\n\n   \n5.6.7.8\n"
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=body)))
        iocs = await _collect(client, client.dataset("ips"))

        assert [i["value"] for i in iocs] == ["1.2.3.4", "5.6.7.8"]

    async def test_invalid_lines_are_dropped_not_ingested(self):
        # A handful of malformed lines must not become indicators, and must
        # also not abort a list of 285k good ones. Built at realistic length
        # so it exercises the same path a real list takes rather than the
        # short-body path.
        good = [f"10.0.{n // 256}.{n % 256}" for n in range(60)]
        body = "\n".join(good[:10] + ["not an ip"] + good[10:20] + ["999.999.999.999"] + good[20:]) + "\n"
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=body)))
        iocs = await _collect(client, client.dataset("ips"))

        assert [i["value"] for i in iocs] == good
        assert client.last_status(client.dataset("ips")) == "fetched"

    async def test_ipv6_lines_are_typed_by_address_family(self):
        body = "1.2.3.4\n2001:db8::1\n"
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=body)))
        iocs = await _collect(client, client.dataset("ips"))

        assert [(i["value"], i["type"]) for i in iocs] == [
            ("1.2.3.4", "ipv4-addr"),
            ("2001:db8::1", "ipv6-addr"),
        ]


class TestConditionalRequests:
    async def test_first_poll_sends_no_validators(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text=_IPS, headers={"ETag": '"abc"', "Last-Modified": "Mon, 01 Jan 2029 00:00:00 GMT"})

        client = NetApiClient(transport=_transport(handler))
        await _collect(client, client.dataset("ips"))

        assert "If-None-Match" not in seen[0].headers
        assert "If-Modified-Since" not in seen[0].headers

    async def test_second_poll_sends_etag_and_last_modified(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text=_IPS, headers={"ETag": '"abc"', "Last-Modified": "Mon, 01 Jan 2029 00:00:00 GMT"})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("ips")
        await _collect(client, ds)
        await _collect(client, ds)

        assert seen[1].headers["If-None-Match"] == '"abc"'
        assert seen[1].headers["If-Modified-Since"] == "Mon, 01 Jan 2029 00:00:00 GMT"

    async def test_list_without_etag_still_sends_if_modified_since(self):
        # Measured against the live endpoints: the short domain list serves
        # Last-Modified but no ETag, so a client that only knows about ETags
        # would re-download it on every single poll.
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text=_DOMAINS, headers={"Last-Modified": "Mon, 01 Jan 2029 00:00:00 GMT"})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("domains")
        await _collect(client, ds)
        await _collect(client, ds)

        assert "If-None-Match" not in seen[1].headers
        assert seen[1].headers["If-Modified-Since"] == "Mon, 01 Jan 2029 00:00:00 GMT"

    async def test_304_yields_nothing_and_reports_not_modified(self):
        def handler(request):
            if "If-None-Match" in request.headers:
                return httpx.Response(304)
            return httpx.Response(200, text=_IPS, headers={"ETag": '"abc"'})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("ips")
        assert len(await _collect(client, ds)) == 3
        assert client.last_status(ds) == "fetched"

        # The whole point of the conditional request: an unchanged list costs
        # a 304 and produces no indicators, so the pipeline is never entered.
        assert await _collect(client, ds) == []
        assert client.last_status(ds) == "not_modified"

    async def test_304_keeps_validators_for_the_next_poll(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            if "If-None-Match" in request.headers:
                return httpx.Response(304)
            return httpx.Response(200, text=_IPS, headers={"ETag": '"abc"'})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("ips")
        await _collect(client, ds)
        await _collect(client, ds)
        await _collect(client, ds)

        # A 304 carries no ETag of its own. Dropping the stored one would make
        # the *next* poll unconditional, so every other poll would re-download.
        assert seen[2].headers["If-None-Match"] == '"abc"'

    async def test_changed_list_replaces_the_validator(self):
        seen: list[httpx.Request] = []
        etags = iter(['"v1"', '"v2"'])

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text=_IPS, headers={"ETag": next(etags)})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("ips")
        await _collect(client, ds)
        await _collect(client, ds)
        assert seen[1].headers["If-None-Match"] == '"v1"'

        await _collect(client, ds)
        assert seen[2].headers["If-None-Match"] == '"v2"'


class TestRefusesNonFeedPayloads:
    async def test_html_challenge_page_is_refused_wholesale(self):
        # A CDN challenge/error page answers 200 with HTML. Without a sniff
        # check every line of it becomes an "indicator".
        html = (
            "<!DOCTYPE html>\n<html>\n<head><title>Attention Required</title></head>\n"
            "<body>\n<p>Checking your browser</p>\n</body>\n</html>\n"
        )
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(200, text=html)))
        ds = client.dataset("domains")

        assert await _collect(client, ds) == []
        assert client.last_status(ds) == "rejected"

    async def test_rejected_payload_does_not_become_the_new_validator(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text="<html><body>nope</body></html>", headers={"ETag": '"junk"'})

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("domains")
        await _collect(client, ds)
        await _collect(client, ds)

        # Storing the junk page's ETag would make the next poll 304 against it
        # and the feed would never recover without a restart.
        assert "If-None-Match" not in seen[1].headers


class TestFailureIsNotSilence:
    async def test_http_error_yields_nothing_and_reports_failed(self):
        client = NetApiClient(transport=_transport(lambda r: httpx.Response(503)))
        ds = client.dataset("ips")

        assert await _collect(client, ds) == []
        # "unreachable" and "unchanged" are different facts and the caller
        # cannot tell them apart from an empty iterator alone.
        assert client.last_status(ds) == "failed"

    async def test_transport_error_yields_nothing_and_reports_failed(self):
        def handler(request):
            raise httpx.ConnectError("no route to host")

        client = NetApiClient(transport=_transport(handler))
        ds = client.dataset("ips")

        assert await _collect(client, ds) == []
        assert client.last_status(ds) == "failed"


class TestDatasetSelection:
    async def test_domains_default_to_the_short_list(self):
        # The default is the short list; see the measured justification in
        # docs/threat-intel/netapi.md. The full list stays available by URL.
        client = NetApiClient()
        assert client.dataset("domains").url.endswith("netapi-compromised-domains-short.txt")

    async def test_full_domain_list_is_selectable(self):
        client = NetApiClient(domains_url="https://netapi.com/api2/netapi-compromised-domains.txt")
        assert client.dataset("domains").url.endswith("netapi-compromised-domains.txt")

    async def test_unknown_dataset_is_an_error(self):
        client = NetApiClient()
        with pytest.raises(KeyError):
            client.dataset("urls")
