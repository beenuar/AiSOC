"""Phase D2 — event-lake storage-tiering config gate.

The hot/warm/cold tiering artifacts (storage-policy.xml + 002_tiering.sql) are
opt-in and applied against a live ClickHouse, so they can't be unit-executed
here. This static gate catches the drift/typos that would silently break them:
the XML must be well-formed and declare the `tiered` policy with the `default`
(hot) + `cold` volumes, and the DDL must rebind the lake to `tiered` and set a
TTL that MOVEs to the cold volume then DELETEs. Verified end-to-end against
ClickHouse 23.8 during development (policy loads, table rebinds, TTL applied).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

_TIERING = Path(__file__).resolve().parents[1] / "clickhouse" / "tiering"
_POLICY = _TIERING / "storage-policy.xml"
_DDL = _TIERING / "002_tiering.sql"


def test_storage_policy_xml_is_well_formed_and_declares_tiered():
    root = ET.fromstring(_POLICY.read_text(encoding="utf-8"))
    sc = root.find("storage_configuration")
    assert sc is not None, "missing <storage_configuration>"
    policies = sc.find("policies")
    tiered = policies.find("tiered")
    assert tiered is not None, "missing <tiered> policy"
    volumes = tiered.find("volumes")
    vol_names = {child.tag for child in volumes}
    # The first volume must keep the name `default` so an existing table on the
    # built-in default policy can be rebound (CH requires the old volume name).
    assert "default" in vol_names, f"tiered policy must keep a `default` volume; got {vol_names}"
    assert "cold" in vol_names, f"tiered policy must define a `cold` volume; got {vol_names}"
    # Cold disk must be declared.
    disks = {child.tag for child in sc.find("disks")}
    assert "cold" in disks


def test_tiering_ddl_rebinds_and_moves_to_cold():
    sql = _DDL.read_text(encoding="utf-8")
    assert "storage_policy = 'tiered'" in sql
    assert "TO VOLUME 'cold'" in sql
    assert "DELETE" in sql
    assert "aisoc.raw_events" in sql
    # 30-day hot window, 90-day retention (matches the cost model / ADR 0005).
    assert "30 DAY" in sql
    assert "90 DAY" in sql
