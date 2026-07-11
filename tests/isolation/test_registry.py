"""The registry gate: every datastore must declare isolation coverage."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stores import STORES, VALID_STATUSES  # noqa: E402

# The six datastores AiSOC runs. A new store added to the stack must be added
# here (and get a real isolation entry) or this test fails.
EXPECTED_STORES = {"postgres", "qdrant", "neo4j", "clickhouse", "redis", "kafka"}


def test_every_store_has_a_valid_coverage_status():
    for store in STORES:
        assert store.status in VALID_STATUSES, f"{store.name} has unset/invalid isolation status: {store.status}"
        assert store.note.strip(), f"{store.name} isolation entry needs a note"


def test_all_known_stores_are_registered():
    registered = {s.name for s in STORES}
    missing = EXPECTED_STORES - registered
    assert not missing, f"datastores missing an isolation entry: {sorted(missing)}"
