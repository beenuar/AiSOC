"""The rail has to read the column the pipeline actually writes.

`services/fusion/app/services/alert_sink.py` records extracted entities in
`alerts.entities` as ``[{"type": "host", "value": "…"}, …]``. Its INSERT does
not list `affected_hosts`, `affected_users`, `affected_ips` or
`affected_assets` — the only writer of those four is
`services/api/app/scripts/seed_demo.py`.

`build_related_entities` sourced its pivots exclusively from those four
columns, and `Alert` did not map `entities` at all, so the Investigation Rail
rendered entity chips for seeded demo alerts and **none** for any alert the
real ingest → fusion pipeline produced. Verified against a live core stack:
an event pushed through `/v1/ingest/batch` landed with
``entities = [{"type": "host", "value": "Finance & Legal #2"}, {"type":
"user", "value": "CORP\\svc backup"}]`` and an empty `affected_hosts`, and the
alert's rail returned zero pivotable entities.

That made the pivot-route and URL-encoding fixes unreachable in production
while their own unit tests passed — the same shape as every other defect in
this audit: the mechanism worked, nothing called it on the path that mattered.
So these tests assert on the fusion spelling specifically, and one of them
uses the ampersand-and-hash hostname that motivated the encoding fix.
"""

from __future__ import annotations

from app.models.alert import Alert
from app.services.alert_rail import build_related_entities


def _alert(**kw) -> Alert:
    """An `Alert` shaped like a row the fusion sink just wrote."""
    defaults = {
        "entities": [],
        "affected_hosts": [],
        "affected_users": [],
        "affected_ips": [],
        "affected_assets": [],
        "raw_event": {},
        "enrichment_data": {},
        "mitre_tactics": [],
        "mitre_techniques": [],
        "connector_type": "acme_waf",
    }
    defaults.update(kw)
    return Alert(**defaults)


def _by_kind(alert: Alert) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in build_related_entities(alert):
        if e.pivot:
            out.setdefault(e.kind, []).append(e.pivot)
    return out


def test_the_alert_model_maps_the_column_fusion_writes() -> None:
    """Pins the premise: unmapped, the rail cannot see pipeline entities."""
    assert hasattr(Alert, "entities")


def test_pipeline_entities_become_pivotable_chips() -> None:
    pivots = _by_kind(_alert(entities=[{"type": "host", "value": "WIN-DC01"}, {"type": "user", "value": "svc_backup"}]))
    assert pivots["host"] == ["/graph?entity=host%3AWIN-DC01"]
    assert pivots["user"] == ["/graph?entity=user%3Asvc_backup"]


def test_a_host_needing_encoding_survives_the_pivot() -> None:
    """The value observed on a live stack. Unencoded, `Finance & Legal #2`
    truncates at the ampersand and pivots to a different node while looking
    like it worked."""
    pivots = _by_kind(_alert(entities=[{"type": "host", "value": "Finance & Legal #2"}]))
    assert pivots["host"] == ["/graph?entity=host%3AFinance%20%26%20Legal%20%232"]


def test_a_backslashed_account_survives_the_pivot() -> None:
    pivots = _by_kind(_alert(entities=[{"type": "user", "value": "CORP\\svc backup"}]))
    assert pivots["user"] == ["/graph?entity=user%3ACORP%5Csvc%20backup"]


def test_network_entities_are_grouped_as_network() -> None:
    groups = {e.kind: e.group for e in build_related_entities(_alert(entities=[{"type": "ip", "value": "10.0.0.7"}]))}
    assert groups["ip"] == "network"


def test_vendor_spellings_are_normalised() -> None:
    pivots = _by_kind(
        _alert(
            entities=[
                {"type": "hostname", "value": "web-01"},
                {"type": "username", "value": "alice"},
                {"type": "ip_address", "value": "10.0.0.9"},
            ]
        )
    )
    assert pivots["host"] == ["/graph?entity=host%3Aweb-01"]
    assert pivots["user"] == ["/graph?entity=user%3Aalice"]
    assert pivots["ip"] == ["/graph?entity=ip%3A10.0.0.9"]


def test_an_unrecognised_kind_is_dropped_not_guessed() -> None:
    """A `/graph?entity=<kind>:…` link the graph cannot resolve is worse than
    no chip: it looks like a working pivot and lands nowhere."""
    assert not _by_kind(_alert(entities=[{"type": "mutex", "value": "Global\\x"}]))


def test_a_row_carrying_both_spellings_yields_one_chip() -> None:
    pivots = _by_kind(_alert(entities=[{"type": "host", "value": "WIN-DC01"}], affected_hosts=["win-dc01"]))
    assert pivots["host"] == ["/graph?entity=host%3AWIN-DC01"]


def test_malformed_entity_rows_do_not_raise() -> None:
    alert = _alert(entities=[None, "host", {"value": "no-type"}, {"type": "host"}, {"type": "host", "value": "  "}])
    assert not _by_kind(alert)


def test_demo_seeded_columns_still_work() -> None:
    """The seed writes the four columns; that path must not regress."""
    pivots = _by_kind(_alert(affected_hosts=["WIN-FIN-01"], affected_users=["bob"], affected_ips=["10.1.1.1"]))
    assert pivots["host"] == ["/graph?entity=host%3AWIN-FIN-01"]
    assert pivots["user"] == ["/graph?entity=user%3Abob"]
    assert pivots["ip"] == ["/graph?entity=ip%3A10.1.1.1"]
