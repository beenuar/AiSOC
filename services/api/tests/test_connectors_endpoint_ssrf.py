"""Connector registration refuses destinations inside the deployment.

GHSA-cq4g-g6wp-4m2w, the API-side half. The connectors service enforces the
same rule at every construction site (test route, resource reads, scheduled
polls) and is the security boundary; this check is the early 422 in the setup
wizard, so a destination that could never be polled is refused before it is
vault-encrypted and stored as a permanently unhealthy instance.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.connectors import _refuse_internal_destinations
from fastapi import HTTPException

INTERNAL = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:8089/",
    "http://10.0.0.5/",
    "http://2130706433/",
]


@pytest.mark.parametrize("url", INTERNAL)
def test_internal_destinations_are_refused(url: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        _refuse_internal_destinations({"base_url": url})
    assert exc_info.value.status_code == 422
    assert "destination refused" in str(exc_info.value.detail)


def test_the_key_name_does_not_matter() -> None:
    """Value shape, not key list: base_url is one of a dozen spellings."""
    with pytest.raises(HTTPException):
        _refuse_internal_destinations({}, {"gitlab_url": "http://169.254.169.254/"})


def test_public_and_non_url_values_pass() -> None:
    _refuse_internal_destinations(
        {"token": "x" * 48, "page_size": 500},
        {"base_url": "https://93.184.216.34:8089", "ssl_verify": True},
    )


def test_none_configs_pass() -> None:
    _refuse_internal_destinations(None, None)


def test_an_unresolvable_hostname_is_not_a_refusal() -> None:
    """The connector's own 'DNS lookup failed' is the right wizard message,
    and a host the guard cannot resolve is one nothing can connect to."""
    _refuse_internal_destinations({"base_url": "https://no-such-host.invalid:8089"})
