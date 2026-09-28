"""The enrich step has to reach a service that serves it.

`_handle_enrich` posted `{"ioc": …}` to `{API_URL}/api/v1/enrichment/lookup`.
Measured against a running stack:

    $ curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \\
        'http://localhost:8000/api/v1/enrichment/lookup?ioc=1.2.3.4'
    404

The API has never served that path — it is absent from the OpenAPI document —
so the step could not enrich anything. The request shape was wrong as well:
the service that does serve enrichment, `services/enrichment`, reads
`{"value": …, "ioc_type": …}` on `POST /enrich`.

Two properties are asserted, and the second is the one that matters for a
security product: an unreachable enrichment service must reach the playbook
author as a **failure**, not as an empty enrichment. "Nothing is known about
this indicator" is a claim about the indicator; "the service is not running"
is not.
"""

from __future__ import annotations

import httpx
import pytest
from app.playbook import engine
from app.playbook.errors import PermanentStepFailure
from app.playbook.models import PlaybookStep, StepType


def _step(**params) -> PlaybookStep:
    return PlaybookStep(id="s1", name="enrich", type=StepType.ENRICH, params=params)


class _Recorder:
    """Captures the one request the handler makes."""

    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.url: str | None = None
        self.json: dict | None = None

    async def post(self, url, json=None, timeout=None):  # noqa: A002, ANN001
        self.url = str(url)
        self.json = json
        self.response.request = httpx.Request("POST", url)
        if self.response.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=self.response.request, response=self.response)
        return self.response


@pytest.mark.asyncio
async def test_it_posts_to_the_enrichment_service_not_the_api() -> None:
    http = _Recorder(httpx.Response(200, json={"value": "1.2.3.4", "reputation": "malicious"}))
    result = await engine._handle_enrich(_step(ioc="1.2.3.4", ioc_type="ip"), {}, http)

    assert http.url == f"{engine._ENRICHMENT_URL}/enrich", http.url
    assert "/api/v1/enrichment/lookup" not in (http.url or ""), "the API does not serve that path"
    assert result["reputation"] == "malicious"


@pytest.mark.asyncio
async def test_it_sends_the_field_names_that_service_reads() -> None:
    """`{"ioc": …}` was the old shape. `services/enrichment` reads `value`."""
    http = _Recorder(httpx.Response(200, json={}))
    await engine._handle_enrich(_step(ioc="evil.example", ioc_type="domain"), {}, http)

    assert http.json == {"value": "evil.example", "ioc_type": "domain"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(404),
        httpx.Response(503),
        httpx.Response(500),
    ],
    ids=["404", "503", "500"],
)
async def test_an_unreachable_service_fails_the_step_rather_than_returning_nothing(failure: httpx.Response) -> None:
    """The direction that matters.

    Enrichment is a `full`-profile service, so on a CORE deployment this step
    *will* fail. Returning `{}` would reach a playbook author as "nothing is
    known about this indicator", which is a claim about the indicator that
    nobody made.
    """
    http = _Recorder(failure)
    with pytest.raises(PermanentStepFailure) as raised:
        await engine._handle_enrich(_step(ioc="1.2.3.4"), {}, http)

    message = str(raised.value)
    assert "1.2.3.4" in message, "the step must name what it did not check"
    assert "says nothing about the indicator" in message


@pytest.mark.asyncio
async def test_a_missing_indicator_is_a_skip_and_not_a_call() -> None:
    """The other direction from the failure test: a step with nothing to look
    up must not be reported as a failed enrichment, and must not call out."""
    http = _Recorder(httpx.Response(200, json={}))
    result = await engine._handle_enrich(_step(), {}, http)

    assert result["skipped"] is True
    assert http.url is None, "no indicator, no request"
