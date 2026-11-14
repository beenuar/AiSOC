"""Which connector types federated search will actually fan out to.

`FEDERATED_CAPABLE_TYPES` is the API's allow-list, and it had drifted from the
translators that exist. `to_aql` has been written, exported from
`app.federated.translators`, covered by tests in
`services/connectors/tests/test_federated_aql.py`, and used by the QRadar
connector's `federated_search` since federated search shipped — but `qradar`
was never added to the allow-list.

The effect was quiet: a tenant with an enabled QRadar connector was excluded
from every federated search with no error, and naming it explicitly in
`connector_ids` returned "not found, not enabled, or not federated-capable",
which reads like a misconfigured connector rather than a missing allow-list
entry.
"""

from __future__ import annotations

import pytest

federated = pytest.importorskip(
    "app.api.v1.endpoints.federated",
    reason="API dependencies not installed",
)

#: The dialect translator each federated-capable type dispatches to. Kept here
#: rather than imported so a type added to the allow-list without a translator
#: fails in this test, not at query time against a customer's connector.
_EXPECTED_TRANSLATORS = {
    "splunk": "to_spl",
    "microsoft_sentinel": "to_kql",
    "elastic": "to_esql",
    "qradar": "to_aql",
}


def test_qradar_is_federated_capable():
    assert "qradar" in federated.FEDERATED_CAPABLE_TYPES


def test_every_federated_capable_type_has_a_declared_translator():
    """Guards the same drift in the other direction."""
    missing = sorted(set(federated.FEDERATED_CAPABLE_TYPES) - set(_EXPECTED_TRANSLATORS))
    assert not missing, f"federated-capable types with no declared translator: {missing}"


def test_every_declared_translator_is_federated_capable():
    """A written, tested translator that no tenant can reach is the bug above."""
    unreachable = sorted(set(_EXPECTED_TRANSLATORS) - set(federated.FEDERATED_CAPABLE_TYPES))
    assert not unreachable, f"translators exist but the type is not allow-listed: {unreachable}"
