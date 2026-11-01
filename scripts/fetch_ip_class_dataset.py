#!/usr/bin/env python3
"""Downloader half of the anonymizer and hosting classification dataset.

Pairs with `scripts/ip_class_dataset.py` (the loader) and
`scripts/check_ip_class_dataset.py` (the gate that compares the two).  The
pairing is the fidelity-corpus rule: two datasets in this repository once
shipped a loader for a corpus nobody could fetch, so their only numbers came
from a ten-line fixture.  A loader without a downloader cannot be refreshed
and cannot be audited.

What this fetches, and why each source is here
----------------------------------------------
Every source below is published by the party that owns the addresses, at a
documented no-authentication endpoint that exists so third parties can load
it into network tooling.  That is the whole redistribution argument, and it
is recorded per source in the manifest rather than asserted once in prose:

  tor_exit          The Tor Project's own bulk exit list.  Tor Project site
                    content is CC BY 3.0 US, so the snapshot is attributed
                    in the manifest and in the dataset header.

  hosting_provider  Each cloud's own published range endpoint.  AWS, Google
                    Cloud, Cloudflare, Fastly, DigitalOcean, Linode and
                    Oracle all document these for customer firewall and
                    allow-list configuration.

Three classes are deliberately absent, and `--check` fails if a future edit
claims otherwise: `vpn`, `public_proxy` and `residential_proxy`.  No source
for them survived the licence check.  The widely-cited community VPN and
datacentre lists carry **no licence file at all** (verified: the obvious
candidate answers 404 for `LICENSE` on its default branch), and a dataset
this repository redistributes under MIT cannot depend on one whose terms
nobody can read.  Those three classes are tenant-supplied only; the docs say
so plainly and the alert renders `unknown`, never a confident "not a VPN".

No per-event network call is made anywhere in the product.  This script is
the only thing that reaches out, it is run by a maintainer or a scheduled
refresh, and its output is committed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

USER_AGENT = "aisoc-ip-class-dataset/1 (+https://github.com/beenuar/AiSOC)"
TIMEOUT_SECONDS = 60

#: Classes the shipped snapshot covers.  `check_ip_class_dataset.py` asserts
#: this is exactly the set of classes present in the committed artefact.
COVERED_CLASSES = ("tor_exit", "hosting_provider")

#: Classes the stamper understands but no shipped source populates.  A tenant
#: may supply a list for any of them; until it does, an address carries no
#: class rather than a negative one.
TENANT_SUPPLIED_ONLY = ("vpn", "public_proxy", "residential_proxy")

#: The closed set, in the order the plan names them.  The Go stamper and the
#: Python replay path both read this through the loader.
ALL_CLASSES = ("vpn", "tor_exit", "public_proxy", "residential_proxy", "hosting_provider")


class Source:
    """One upstream publication and how to read it."""

    def __init__(
        self,
        source_id: str,
        url: str,
        cls: str,
        provider: str,
        parser: str,
        terms_url: str,
        redistribution: str,
    ) -> None:
        self.id = source_id
        self.url = url
        self.cls = cls
        self.provider = provider
        self.parser = parser
        self.terms_url = terms_url
        self.redistribution = redistribution


SOURCES: tuple[Source, ...] = (
    Source(
        "tor-project-bulk-exit-list",
        "https://check.torproject.org/torbulkexitlist",
        "tor_exit",
        "tor",
        "lines",
        "https://www.torproject.org/",
        "cc-by-3.0-us",
    ),
    Source(
        "aws-ip-ranges",
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "hosting_provider",
        "aws",
        "aws",
        "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html",
        "publisher-published-for-consumption",
    ),
    Source(
        "gcp-cloud-ip-ranges",
        "https://www.gstatic.com/ipranges/cloud.json",
        "hosting_provider",
        "gcp",
        "gcp",
        "https://cloud.google.com/vpc/docs/configure-private-google-access",
        "publisher-published-for-consumption",
    ),
    Source(
        "cloudflare-ipv4",
        "https://www.cloudflare.com/ips-v4",
        "hosting_provider",
        "cloudflare",
        "lines",
        "https://www.cloudflare.com/ips/",
        "publisher-published-for-consumption",
    ),
    Source(
        "fastly-public-ip-list",
        "https://api.fastly.com/public-ip-list",
        "hosting_provider",
        "fastly",
        "fastly",
        "https://developer.fastly.com/reference/api/utils/public-ip-list/",
        "publisher-published-for-consumption",
    ),
    Source(
        "digitalocean-geo",
        "https://www.digitalocean.com/geo/google.csv",
        "hosting_provider",
        "digitalocean",
        "csv_first_column",
        "https://docs.digitalocean.com/products/platform/",
        "publisher-published-for-consumption",
    ),
    Source(
        "linode-geo",
        "https://geoip.linode.com/",
        "hosting_provider",
        "linode",
        "csv_first_column",
        "https://www.linode.com/docs/",
        "publisher-published-for-consumption",
    ),
    Source(
        "oracle-public-ip-ranges",
        "https://docs.oracle.com/iaas/tools/public_ip_ranges.json",
        "hosting_provider",
        "oracle",
        "oracle",
        "https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm",
        "publisher-published-for-consumption",
    ),
)


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError(f"{url} answered HTTP {response.status}")
        return response.read()


def _parse_lines(body: bytes) -> Iterator[str]:
    for line in body.decode("utf-8", "replace").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            yield text


def _parse_csv_first_column(body: bytes) -> Iterator[str]:
    reader = csv.reader(io.StringIO(body.decode("utf-8", "replace")))
    for row in reader:
        if not row:
            continue
        candidate = row[0].strip()
        if candidate and not candidate.startswith("#"):
            yield candidate


def _parse_aws(body: bytes) -> Iterator[str]:
    document = json.loads(body)
    for entry in document.get("prefixes", []):
        if entry.get("ip_prefix"):
            yield entry["ip_prefix"]
    for entry in document.get("ipv6_prefixes", []):
        if entry.get("ipv6_prefix"):
            yield entry["ipv6_prefix"]


def _parse_gcp(body: bytes) -> Iterator[str]:
    document = json.loads(body)
    for entry in document.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if entry.get(key):
                yield entry[key]


def _parse_fastly(body: bytes) -> Iterator[str]:
    document = json.loads(body)
    for key in ("addresses", "ipv6_addresses"):
        for prefix in document.get(key, []):
            if prefix:
                yield prefix


def _parse_oracle(body: bytes) -> Iterator[str]:
    document = json.loads(body)
    for region in document.get("regions", []):
        for entry in region.get("cidrs", []):
            if entry.get("cidr"):
                yield entry["cidr"]


_PARSERS = {
    "lines": _parse_lines,
    "csv_first_column": _parse_csv_first_column,
    "aws": _parse_aws,
    "gcp": _parse_gcp,
    "fastly": _parse_fastly,
    "oracle": _parse_oracle,
}


def _normalise(candidate: str) -> str | None:
    """Return a canonical CIDR, or None when the token is not an address.

    A bare address becomes a host prefix so the compiled artefact has exactly
    one shape.  The Tor list is bare addresses; every cloud publishes CIDRs.
    """
    token = candidate.strip()
    if not token:
        return None
    try:
        if "/" in token:
            return str(ipaddress.ip_network(token, strict=False))
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))


def build(sources: tuple[Source, ...] = SOURCES) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
    """Fetch every source and compile the manifest plus the sorted records."""
    records: dict[str, tuple[str, str]] = {}
    manifest_sources: list[dict[str, Any]] = []

    for source in sources:
        try:
            body = _fetch(source.url)
        except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
            # Loud, never silent: a snapshot missing a source is a smaller
            # dataset that still looks complete, and the committed manifest
            # would record a record count nobody could explain.
            raise SystemExit(f"FAIL {source.id}: {source.url} could not be fetched: {exc}") from exc

        parsed = list(_PARSERS[source.parser](body))
        accepted = 0
        for candidate in parsed:
            cidr = _normalise(candidate)
            if cidr is None:
                continue
            # First source wins. Ordering in SOURCES is therefore meaningful:
            # the Tor exit list is first because an exit relay hosted at a
            # cloud provider is a Tor exit first and a rented box second.
            if cidr not in records:
                records[cidr] = (source.cls, source.provider)
                accepted += 1

        manifest_sources.append(
            {
                "id": source.id,
                "url": source.url,
                "class": source.cls,
                "provider": source.provider,
                "terms_url": source.terms_url,
                "redistribution": source.redistribution,
                "parsed": len(parsed),
                "accepted": accepted,
                "upstream_sha256": hashlib.sha256(body).hexdigest(),
            }
        )

    rows = sorted(
        ((cidr, cls, provider) for cidr, (cls, provider) in records.items()),
        key=lambda row: (ipaddress.ip_network(row[0]).version, ipaddress.ip_network(row[0])),
    )

    manifest = {
        "version": datetime.now(UTC).strftime("%Y.%m.%d"),
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "covered_classes": list(COVERED_CLASSES),
        "tenant_supplied_only": list(TENANT_SUPPLIED_ONLY),
        "all_classes": list(ALL_CLASSES),
        "record_count": len(rows),
        "sources": manifest_sources,
    }
    return manifest, rows


def render(manifest: dict[str, Any], rows: list[tuple[str, str, str]]) -> tuple[str, str]:
    """Render the two committed files. The manifest carries the body digest."""
    header = (
        "# AiSOC IP classification dataset.\n"
        "# Generated by scripts/fetch_ip_class_dataset.py; do not hand-edit.\n"
        "# Columns: cidr<TAB>class<TAB>provider\n"
        "# Tor exit relays are from the Tor Project bulk exit list, used under\n"
        "# CC BY 3.0 US. Hosting ranges are each publisher's own published list;\n"
        "# see manifest.json for the per-source provenance and terms link.\n"
    )
    body = "".join(f"{cidr}\t{cls}\t{provider}\n" for cidr, cls, provider in rows)
    manifest = dict(manifest)
    manifest["records_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return header + body, json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=repo_root() / "services" / "ingest" / "internal" / "activity" / "ipclass" / "data",
        help="directory to write ip_classes.tsv and manifest.json into",
    )
    args = parser.parse_args()

    manifest, rows = build()
    records_text, manifest_text = render(manifest, rows)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ip_classes.tsv").write_text(records_text, encoding="utf-8")
    (args.out / "manifest.json").write_text(manifest_text, encoding="utf-8")
    print(f"OK wrote {len(rows)} records to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
