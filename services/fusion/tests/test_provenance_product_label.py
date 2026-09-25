"""The vendor/product join must not say the vendor twice.

`connector_type` is what the alert queue, the Investigation Rail's connector
chip and `alert.source` all render, so a doubled label is visible on every
surface that names where an alert came from.

The interesting half of this file is `test_no_shipped_profile_doubles_its_vendor`:
it reads the vendor/product pairs out of the Go normalizer rather than
restating them here. A test that carries its own copy of the input only proves
the function is self-consistent — the previous exact-equality dedup passed
every hand-written case while four of the ten shipped profiles rendered
doubled, because no test ever asked the normalizer what it actually declares.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from app.services.provenance import product_label

NORMALIZER = Path(__file__).resolve().parents[3] / "services" / "ingest" / "internal" / "normalizer" / "normalizer.go"

#: `OcsfProduct{Name: "Okta System Log", VendorName: "Okta"}`
_PRODUCT_DECL = re.compile(r'OcsfProduct\{Name:\s*"(?P<name>[^"]+)",\s*VendorName:\s*"(?P<vendor>[^"]+)"\}')


def _label(vendor: str | None, name: str | None) -> str | None:
    product: dict[str, str] = {}
    if vendor is not None:
        product["vendor_name"] = vendor
    if name is not None:
        product["name"] = name
    return product_label({"metadata": {"product": product}})


@pytest.mark.parametrize(
    ("vendor", "name", "expected"),
    [
        # The vendor names itself inside the product. Observed doubled on a
        # live CORE stack against telemetry pushed through the ingest API.
        ("Okta", "Okta System Log", "Okta System Log"),
        ("Splunk", "Splunk Enterprise", "Splunk Enterprise"),
        ("Kubernetes", "Kubernetes Audit", "Kubernetes Audit"),
        # Containment, not prefixing: the vendor is the *last* word here.
        ("Email", "Forwarded Email", "Forwarded Email"),
        # Exact duplicates — the case the original dedup was written for.
        ("Splunk", "Splunk", "Splunk"),
        ("crowdstrike", "CrowdStrike", "crowdstrike"),
        # Neither part names the other: both survive, in vendor-first order.
        ("CrowdStrike", "Falcon", "CrowdStrike Falcon"),
        ("Microsoft", "Sentinel", "Microsoft Sentinel"),
        ("AWS", "Security Hub", "AWS Security Hub"),
        ("AiSOC", "AI Runtime", "AiSOC AI Runtime"),
        # One side missing is not a reason to drop the other.
        ("CrowdStrike", None, "CrowdStrike"),
        (None, "Falcon", "Falcon"),
        ("", "   ", None),
    ],
)
def test_product_label(vendor: str | None, name: str | None, expected: str | None) -> None:
    assert _label(vendor, name) == expected


def test_substring_match_respects_word_boundaries() -> None:
    """A vendor that merely appears inside a longer word is not swallowed."""
    assert _label("AWS", "Lawsuit Monitor") == "AWS Lawsuit Monitor"


def test_missing_or_malformed_metadata_yields_none() -> None:
    assert product_label({}) is None
    assert product_label({"metadata": {}}) is None
    assert product_label({"metadata": {"product": "Falcon"}}) is None


@pytest.mark.skipif(not NORMALIZER.is_file(), reason="ingest normalizer not present in this checkout")
def test_no_shipped_profile_doubles_its_vendor() -> None:
    """Every vendor/product pair the normalizer declares must render once.

    Runs in the direction that drifts: adding a profile whose product name
    repeats its vendor fails here rather than being discovered in a screenshot.
    """
    declarations = _PRODUCT_DECL.findall(NORMALIZER.read_text(encoding="utf-8"))
    assert declarations, f"no OcsfProduct declarations found in {NORMALIZER}"

    doubled: list[tuple[str, str, str]] = []
    for name, vendor in declarations:
        label = _label(vendor, name) or ""
        words = [word.lower() for word in label.split()]
        if len(words) != len(set(words)):
            doubled.append((vendor, name, label))

    assert not doubled, "vendor repeated in the rendered label: " + ", ".join(f"{v!r}+{n!r} -> {label!r}" for v, n, label in doubled)
