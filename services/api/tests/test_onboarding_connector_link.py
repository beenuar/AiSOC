"""Keep the setup checklist's source link from navigating back to itself."""

from pathlib import Path

ENDPOINT = Path(__file__).resolve().parents[1] / "app/api/v1/endpoints/onboarding.py"


def test_connector_step_links_to_connector_inventory() -> None:
    source = ENDPOINT.read_text()
    step = source[source.index('key="connector"') : source.index('key="data"')]
    assert 'href="/connectors"' in step, "Connect a source must reach the connector inventory, not link back to /onboarding"
