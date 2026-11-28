"""
NetAPI compromised-indicator feed client.

NetAPI publishes two keyless plain-text lists — one of IP addresses, one of
domains — under CC BY 4.0. They are the only IP/domain source in this service
that needs no API key: OTX requires one and the CISA KEV catalog carries CVEs
only, so without these a default deployment has no keyless indicator feed for
the two IOC types alerts most often carry.

Why conditional requests are the whole design
---------------------------------------------
The lists are large (the full domain list measured 5,627,225 bytes /
285,028 lines on 2026-11-28) and are rebuilt on the publisher's schedule,
not ours. Re-reading an unchanged list is not merely wasted bandwidth: every
indicator handed to ``ThreatIntelPipeline.ingest_iocs`` costs Redis
round-trips for the per-sink dedup check whether or not it is new. So an
unchanged list has to cost a ``304`` and produce *no indicators at all*,
which keeps the pipeline out of the picture entirely.

All three published lists honour conditional requests, but not identically,
and the difference matters. Measured against the live endpoints on
2026-11-28:

===================== ====== ============= =================================
list                  ETag   Last-Modified conditional result
===================== ====== ============= =================================
compromised-ips       yes    yes           304, 0 bytes
compromised-domains   yes    yes           304, 0 bytes
compromised-domains-  **no** yes           304, 0 bytes (If-Modified-Since)
  short
===================== ====== ============= =================================

The short domain list — the one this client defaults to — publishes no ETag.
A client that only knew about ``If-None-Match`` would therefore re-download
it on every single poll, which is exactly the cost the conditional request
exists to avoid. Both validators are sent whenever both are known.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.airgap import AirgapViolation, enforce_airgap_for_url

logger = structlog.get_logger(__name__)

#: Addresses reported by the publisher's sensor network.
IPS_URL = "https://netapi.com/api2/netapi-compromised-ips.txt"

#: The full domain list, including domains held by sinkholes.
DOMAINS_FULL_URL = "https://netapi.com/api2/netapi-compromised-domains.txt"

#: The same list with the sinkholed domains removed. This is the default —
#: see ``apps/docs/docs/integrations/netapi-threat-feed.md`` for the measurements behind
#: that choice. The full list stays available by setting ``NETAPI_DOMAINS_URL``.
DOMAINS_SHORT_URL = "https://netapi.com/api2/netapi-compromised-domains-short.txt"

#: Same convention as the CISA KEV client: identify the client rather than
#: defaulting to ``python-httpx/x.y``.
_USER_AGENT = "AiSOC/1.0 (+https://github.com/beenuar/AiSOC)"

#: How many leading indicators are checked before anything is ingested.
_SNIFF_LINES = 50

#: The share of the sniffed lines that must parse as the expected indicator
#: type. These lists sit behind a CDN, and a CDN challenge or error page is
#: served as ``200`` with an HTML body — without this check every line of
#: that page becomes an "indicator" and the store fills with markup.
_SNIFF_MIN_VALID = 0.9

#: Hostname shape. Deliberately stricter than "contains a dot": it is the
#: difference between rejecting ``<p>Checking your browser</p>`` and storing it.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$")


@dataclass(frozen=True)
class NetApiDataset:
    """One published list and how its lines become indicators."""

    key: str
    url: str
    #: ``ip`` lines are typed per address family at parse time; ``domain``
    #: lines are always ``domain-name``.
    kind: str
    label: str
    description: str
    tags: tuple[str, ...]


def _ip_ioc_type(value: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return "ipv4-addr" if parsed.version == 4 else "ipv6-addr"


def _domain_ioc_type(value: str) -> str | None:
    return "domain-name" if _DOMAIN_RE.match(value) else None


class NetApiClient:
    """Fetches the NetAPI lists and normalizes each line into an IOC dict.

    One instance holds the conditional-request validators for every dataset it
    polls, so it is scheduler-lived rather than per-poll.
    """

    def __init__(
        self,
        *,
        ips_url: str = IPS_URL,
        domains_url: str = DOMAINS_SHORT_URL,
        timeout_seconds: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._transport = transport
        self._datasets: dict[str, NetApiDataset] = {
            "ips": NetApiDataset(
                key="ips",
                url=ips_url,
                kind="ip",
                label="compromised-ips",
                description="Address listed by the NetAPI compromised-IP feed",
                tags=("netapi", "compromised", "ip"),
            ),
            "domains": NetApiDataset(
                key="domains",
                url=domains_url,
                kind="domain",
                label="compromised-domains",
                description="Domain listed by the NetAPI compromised-domain feed",
                tags=("netapi", "compromised", "domain"),
            ),
        }
        #: dataset key -> (etag, last_modified). Either half may be ``None``:
        #: the short domain list publishes no ETag.
        self._validators: dict[str, tuple[str | None, str | None]] = {}
        self._status: dict[str, str] = {}

    # ─── Introspection ───────────────────────────────────────────────────────

    def dataset(self, key: str) -> NetApiDataset:
        """Return a configured dataset. Raises ``KeyError`` for an unknown key."""
        return self._datasets[key]

    @property
    def datasets(self) -> tuple[NetApiDataset, ...]:
        return tuple(self._datasets.values())

    def last_status(self, dataset: NetApiDataset) -> str:
        """Outcome of the most recent poll of ``dataset``.

        One of ``fetched`` / ``not_modified`` / ``failed`` / ``rejected`` /
        ``blocked``, or ``unknown`` before the first poll. Valid once the
        iterator returned by :meth:`iter_iocs` has been consumed.

        This exists because an empty iterator is ambiguous. "The list has not
        changed", "the host is unreachable" and "the body was not the feed"
        are three different facts and a caller cannot tell them apart from the
        absence of indicators alone.
        """
        return self._status.get(dataset.key, "unknown")

    # ─── Normalization ───────────────────────────────────────────────────────

    def to_ioc(self, dataset: NetApiDataset, value: str, ioc_type: str) -> dict[str, Any]:
        """Convert one list line into a normalized IOC dict.

        ``source`` is ``netapi`` because that string is load-bearing twice
        over: the enrichment service surfaces a feed hit under the IOC's own
        source name, and the fusion confidence scorer recognises the threat-
        intel factor by that name. A different spelling here is a feed that
        ingests and never influences a verdict.

        No ``confidence`` is emitted. The feed publishes no per-indicator
        confidence and the CISA KEV client does not invent one either; a
        number nobody measured is worse than an absent field.
        """
        return {
            "type": ioc_type,
            "value": value,
            "description": dataset.description,
            "source": "netapi",
            "source_ref": f"netapi:{dataset.label}:{value}",
            "tags": list(dataset.tags),
            "tlp": "white",
        }

    # ─── Fetch ───────────────────────────────────────────────────────────────

    async def iter_iocs(self, dataset: NetApiDataset) -> AsyncIterator[dict[str, Any]]:
        """Stream normalized IOCs for ``dataset``.

        Yields nothing when the list is unchanged (``304``), when the request
        fails, or when the body did not look like the feed. Call
        :meth:`last_status` afterwards to find out which.

        The response is streamed rather than buffered: peak memory is a
        handful of lines regardless of how large the list grows.
        """
        try:
            enforce_airgap_for_url(dataset.url)
        except AirgapViolation as exc:
            # Registration in ``app.main`` already refuses this feed under
            # air-gap policy; this is the second gate, so a future caller that
            # constructs the client directly cannot reach the network either.
            self._status[dataset.key] = "blocked"
            logger.warning("NetAPI feed blocked by air-gap policy", dataset=dataset.key, error=str(exc))
            return

        headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain"}
        etag, last_modified = self._validators.get(dataset.key, (None, None))
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=True,
            ) as client:
                async with client.stream("GET", dataset.url, headers=headers) as response:
                    if response.status_code == httpx.codes.NOT_MODIFIED:
                        self._status[dataset.key] = "not_modified"
                        logger.info("NetAPI list unchanged", dataset=dataset.key, status=304)
                        # Deliberately keep the stored validators: a 304 carries
                        # no ETag of its own, so clearing them here would make
                        # every other poll unconditional.
                        return

                    response.raise_for_status()

                    async for ioc in self._parse(dataset, response):
                        yield ioc
        except Exception as exc:
            self._status[dataset.key] = "failed"
            logger.error(
                "NetAPI feed fetch failed; this list contributed no indicators",
                dataset=dataset.key,
                url=dataset.url,
                error=str(exc),
            )
            return

    async def _parse(self, dataset: NetApiDataset, response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
        """Validate the leading lines, then stream the whole body."""
        classify = _ip_ioc_type if dataset.kind == "ip" else _domain_ioc_type

        head: list[tuple[str, str | None]] = []
        valid_head = 0
        emitted = 0
        dropped = 0

        async for raw in response.aiter_lines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            # Domains are published lower-case but a feed can drift; the store
            # is keyed on the value, so normalize before it becomes an id.
            if dataset.kind == "domain":
                line = line.lower()

            ioc_type = classify(line)

            if len(head) < _SNIFF_LINES:
                head.append((line, ioc_type))
                if ioc_type:
                    valid_head += 1
                if len(head) < _SNIFF_LINES:
                    continue
                if not self._accept_head(dataset, valid_head, len(head)):
                    return
                for value, kind in head:
                    if kind:
                        emitted += 1
                        yield self.to_ioc(dataset, value, kind)
                    else:
                        dropped += 1
                continue

            if ioc_type:
                emitted += 1
                yield self.to_ioc(dataset, line, ioc_type)
            else:
                dropped += 1

        # A list shorter than the sniff window (a test fixture, or a feed that
        # legitimately shrank) never reached the flush above.
        if len(head) < _SNIFF_LINES:
            if not self._accept_head(dataset, valid_head, len(head)):
                return
            for value, kind in head:
                if kind:
                    emitted += 1
                    yield self.to_ioc(dataset, value, kind)
                else:
                    dropped += 1

        self._validators[dataset.key] = (
            response.headers.get("ETag"),
            response.headers.get("Last-Modified"),
        )
        self._status[dataset.key] = "fetched"
        logger.info(
            "NetAPI list fetched",
            dataset=dataset.key,
            indicators=emitted,
            dropped=dropped,
            etag=bool(response.headers.get("ETag")),
            last_modified=bool(response.headers.get("Last-Modified")),
        )

    def _accept_head(self, dataset: NetApiDataset, valid: int, total: int) -> bool:
        """Refuse a body whose leading lines are not indicators.

        Returns ``False`` having recorded the refusal, in which case the
        validators are left untouched on purpose: storing the rejected
        response's ETag would make the next poll a 304 against the junk and
        the feed would never recover without a restart.
        """
        if total == 0:
            self._status[dataset.key] = "rejected"
            logger.error("NetAPI list was empty; refusing it", dataset=dataset.key)
            return False
        if valid / total >= _SNIFF_MIN_VALID:
            return True
        self._status[dataset.key] = "rejected"
        logger.error(
            "NetAPI response did not look like the feed; refusing it wholesale",
            dataset=dataset.key,
            url=dataset.url,
            sniffed=total,
            valid=valid,
        )
        return False
