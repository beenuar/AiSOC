"""A proxy that attaches a service token must not let the caller aim it.

The first version of this proxy interpolated the capability and vendor id
straight into the upstream path. CodeQL called it correctly: `py/partial-ssrf`,
critical. ``../../admin`` is a perfectly good "capability" as far as string
formatting is concerned, and the service token this proxy adds on the way out
would have gone with the redirected request.

Refused at the edge rather than percent-encoded, because encoding turns a
hostile value into a harmless upstream 404 while still forwarding it, and a
404 tells an operator nothing about what was attempted.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints import live_actions
from fastapi import HTTPException


class TestPathSegmentGuard:
    @pytest.mark.parametrize(
        "value",
        [
            "isolate_host",
            "crowdstrike",
            "aws-security-groups",
            "vendor.name",
            "a",
        ],
    )
    def test_real_identifiers_are_accepted(self, value: str):
        assert live_actions._safe_segment(value, field="capability") == value

    @pytest.mark.parametrize(
        "value",
        [
            "../../admin",
            "..%2f..%2fadmin",
            "isolate_host/../../internal",
            "http://evil.example/steal",
            "host:8085/other",
            "capability?x=1",
            "with space",
            "",
            "/leading-slash",
            "trailing/",
        ],
    )
    def test_anything_that_could_steer_the_request_is_refused(self, value: str):
        with pytest.raises(HTTPException) as caught:
            live_actions._safe_segment(value, field="capability")
        assert caught.value.status_code == 400

    def test_the_refusal_names_the_field(self):
        """So an operator reading the 400 knows which parameter was wrong."""
        with pytest.raises(HTTPException) as caught:
            live_actions._safe_segment("../x", field="vendor_id")
        assert "vendor_id" in caught.value.detail

    def test_length_is_bounded(self):
        """An unbounded segment is a way to build an enormous upstream URL."""
        with pytest.raises(HTTPException):
            live_actions._safe_segment("a" * 200, field="capability")


class TestWhatIsProxied:
    def test_live_dispatch_is_not_exposed(self):
        """A live containment must carry an approver, which this proxy cannot
        supply. Only discovery and dry-run are forwarded."""
        paths = {route.path for route in live_actions.router.routes}
        assert "/live-actions/dry-run" in paths
        assert "/live-actions/dispatch" not in paths

    def test_every_route_requires_a_permission(self):
        """Upstream these sit behind a service token; the whole point of the
        proxy is that a person, not a service, is on the other end."""
        for route in live_actions.router.routes:
            dependencies = getattr(route, "dependant", None)
            assert dependencies is not None, route.path
            # Each handler takes an AuthUser produced by require_permission.
            assert route.dependant.dependencies, f"{route.path} has no auth dependency"
