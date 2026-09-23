"""An alert's source and description are what an analyst reads first.

Both were wrong, and both were found by pushing one real event through a live
CORE stack rather than by reading code:

* `connector_type` came back as **"crowdstrike crowdstrike"**, because
  `_source()` joined `vendor_name` and `name` without noticing they were the
  same string. Most connectors set both.
* `description` came back as ``{"command_line": "powershell.exe -nop -w ...``
  — the whole event serialized with `str()` — while the vendor's own
  human-written description was discarded.
"""

from __future__ import annotations

from app.services.promoter import _description, _source


def _ocsf(vendor: str | None, product: str | None, **rest) -> dict:
    meta: dict = {"product": {}}
    if vendor is not None:
        meta["product"]["vendor_name"] = vendor
    if product is not None:
        meta["product"]["name"] = product
    return {"metadata": meta, **rest}


# ── source ────────────────────────────────────────────────────────────────


def test_a_vendor_repeated_as_the_product_is_not_doubled() -> None:
    """The live regression."""
    assert _source(_ocsf("crowdstrike", "crowdstrike")) == "crowdstrike"


def test_the_dedup_is_case_insensitive() -> None:
    """Both spellings appear across connectors, so the dedup ignores case."""
    assert _source(_ocsf("CrowdStrike", "crowdstrike")) == "CrowdStrike"


def test_a_genuine_vendor_and_product_are_both_kept() -> None:
    assert _source(_ocsf("CrowdStrike", "Falcon")) == "CrowdStrike Falcon"


def test_either_half_alone_is_enough() -> None:
    assert _source(_ocsf("Splunk", None)) == "Splunk"
    assert _source(_ocsf(None, "Sentinel")) == "Sentinel"


def test_no_product_metadata_falls_back_to_ingest() -> None:
    assert _source({"metadata": {}}) == "ingest"


def test_blank_strings_are_not_treated_as_a_name() -> None:
    assert _source(_ocsf("   ", "")) == "ingest"


# ── description ───────────────────────────────────────────────────────────


def test_the_vendors_own_description_wins() -> None:
    """The live regression: this text was thrown away."""
    ocsf = {
        "raw_data": {
            "description": "powershell.exe -enc JABzAD0A spawned by winword.exe",
            "command_line": "powershell.exe -nop -w hidden -enc JABzAD0A",
            "host": "WIN-FIN-01",
        }
    }
    assert _description(ocsf) == "powershell.exe -enc JABzAD0A spawned by winword.exe"


def test_a_description_is_never_a_serialized_payload() -> None:
    """The property that actually matters, stated directly."""
    ocsf = {"raw_data": {"command_line": "whoami", "host": "WIN-01", "pid": 4242}}
    result = _description(ocsf)
    assert not result.startswith("{"), f"description is a dict dump: {result[:60]}"
    assert "'pid'" not in result and '"pid"' not in result


def test_alternative_human_keys_are_accepted() -> None:
    for key in ("message", "summary", "detail", "reason"):
        assert _description({"raw_data": {key: f"via {key}"}}) == f"via {key}"


def test_a_security_finding_description_is_used() -> None:
    assert _description({"finding": {"desc": "Notable: brute force"}}) == "Notable: brute force"


def test_a_top_level_message_is_used_when_nothing_else_is() -> None:
    assert _description({"message": "Impossible travel detected"}) == "Impossible travel detected"


def test_nothing_human_anywhere_yields_empty_not_a_dump() -> None:
    """An empty description is more honest than a dict repr pretending to be
    prose. The console renders the raw event beneath it either way."""
    assert _description({"raw_data": {"a": 1, "b": 2}}) == ""


def test_descriptions_are_capped() -> None:
    assert len(_description({"raw_data": {"description": "x" * 5000}})) == 2000
