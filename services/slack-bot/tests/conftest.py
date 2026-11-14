"""Suite-wide environment for the Slack bot tests.

The suite builds the Bolt app without a `SLACK_SIGNING_SECRET`, which is
correct for a test run and is refused outright anywhere else
(GHSA-vf98-8367-45mp, F02): an empty signing secret turns Bolt's request
verification off, so the service would accept an unsigned `block_actions`
approval payload.

`ENVIRONMENT=test` is the explicit opt-out that refusal is built around, and
it is declared here rather than inside each test so a new one cannot be
written that silently depends on the production default.

`"test"` and not `"development"`: `development` is in the API's
`AUTH_BYPASS_ENVIRONMENTS`, and a suite that opts into a bypass to make an
authorization control tractable is the shape this repository removed
`"test"` from that set to prevent.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _test_environment() -> None:
    os.environ.setdefault("ENVIRONMENT", "test")
