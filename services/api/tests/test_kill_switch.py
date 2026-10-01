"""The kill switch is reachable, authorized and audited.

Parity plan 2.2. The agents-side half (that an engaged switch actually stops
closure) lives in `services/agents/tests/test_closure_policy.py`, which
drives the resolver. This covers the API surface: that the routes exist,
that writing requires a permission while reading does not, and that the
reason is mandatory.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
from app.api.v1.endpoints import kill_switch
from app.main import app


def _resolve(path: str, method: str) -> str | None:
    async def go() -> str | None:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "root_path": "",
            "app": app,
        }
        for route in app.router.routes:
            match, _child = route.matches(scope)
            if match.name == "FULL":
                return getattr(route, "name", None)
        return None

    return asyncio.run(go())


class TestTheRoutesExist:
    @pytest.mark.parametrize(
        ("path", "method", "handler"),
        [
            ("/api/v1/kill-switch", "GET", "read_kill_switch"),
            ("/api/v1/kill-switch/engage", "POST", "engage"),
            ("/api/v1/kill-switch/release", "POST", "release"),
        ],
    )
    def test_each_route_reaches_its_handler(self, path: str, method: str, handler: str) -> None:
        assert _resolve(path, method) == handler


class TestAuthorization:
    def test_writing_requires_a_permission(self) -> None:
        for name in ("engage", "release"):
            source = inspect.getsource(getattr(kill_switch, name))
            assert 'require_permission("settings:write")' in source, (
                f"{name} does not require a permission, so any authenticated user could freeze or unfreeze the platform"
            )

    def test_reading_does_not(self) -> None:
        """An analyst watching the queue stop moving has to be able to find
        out why without asking an administrator."""
        source = inspect.getsource(kill_switch.read_kill_switch)
        assert "require_permission" not in source
        assert "user: AuthUser" in source, "reading must still be authenticated"


class TestTheReasonIsMandatory:
    """A switch with no reason is one nobody can safely disengage: the next
    operator cannot tell a deliberate freeze from a forgotten test."""

    def test_engaging_requires_a_reason(self) -> None:
        field = kill_switch.EngageRequest.model_fields["reason"]
        assert field.is_required()
        assert any(getattr(m, "min_length", None) for m in field.metadata), "an empty-ish reason would satisfy a bare required field"

    def test_releasing_requires_one_too(self) -> None:
        assert kill_switch.ReleaseRequest.model_fields["reason"].is_required()


class TestItIsAudited:
    def test_both_transitions_write_an_audit_row(self) -> None:
        for name, action in (("engage", "'engage'"), ("release", "'release'")):
            source = inspect.getsource(getattr(kill_switch, name))
            assert "aisoc_kill_switch_audit" in source, f"{name} writes no audit row"
            assert action in source

    def test_the_log_line_cannot_be_forged_by_the_reason(self) -> None:
        """The reason is operator-supplied text that lands in a log line."""
        assert "\n" not in kill_switch._sanitize("a\nb")
        assert "\r" not in kill_switch._sanitize("a\rb")
        assert len(kill_switch._sanitize("x" * 5000)) <= 200


class TestReleasingAGlobalSwitch:
    def test_a_tenant_cannot_release_the_platform_switch(self) -> None:
        """And is told so, rather than getting a success that changes
        nothing. Reporting success over a switch that stays engaged is how
        an operator concludes the stop button is broken."""
        source = inspect.getsource(kill_switch.release)
        assert "409" in source or "HTTP_409_CONFLICT" in source
        assert "platform operator" in source
