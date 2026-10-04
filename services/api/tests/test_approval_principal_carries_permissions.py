"""An approval dispatch carries the approver's real permissions.

The defect
----------
`_dispatch_decision` in `approvals.py` built its principal like this:

    "roles": list(getattr(user, "roles", []) or []),
    "permissions": list(getattr(user, "permissions", []) or []),

`CurrentUser` defines **neither** attribute. It has `role` (singular),
`scopes` and `resolved_permissions`. So both `getattr` defaults fired and the
principal shipped an empty permission list, silently -- no exception, no log.

Downstream, `services/actions`'s `has_action_permission` returns `False` on an
empty list unconditionally, so `authorize_approver` raised, the actions service
answered 403, and the operator saw a 502 reading *"Decision recorded, but the
action service refused it"*. The approval row recorded the decision and the
action never ran. **Every** approval, for every role, including platform admin.

Why the fix is a method on `CurrentUser` and not a local helper
---------------------------------------------------------------
Resolving permissions inside a route means a route deciding its own
authorisation, which `scripts/check_one_permission_model.py` refuses -- and it
refuses it because a published advisory came from exactly that. The order also
has to match `require_permission`'s, or a caller could be allowed to approve
something the same principal would be refused for elsewhere. One method, one
order, both callers.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
APPROVALS = REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "approvals.py"


def _principal_for(**kwargs):
    from app.api.v1.deps import CurrentUser

    base = {
        "user_id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "role": "analyst",
        "email": "a@example.test",
    }
    base.update(kwargs)
    return CurrentUser(**base)


class TestCurrentUserCanAnswerWhatItMayDo:
    def test_the_method_exists(self) -> None:
        from app.api.v1.deps import CurrentUser

        assert hasattr(CurrentUser, "effective_permissions")

    def test_an_api_key_principal_reports_its_scopes(self) -> None:
        """First in the order, matching `require_permission`: a key's scopes
        are an explicit, narrower grant than its owner's role."""
        user = _principal_for(scopes=["actions:execute:low", "alerts:read"])

        assert set(user.effective_permissions()) == {"actions:execute:low", "alerts:read"}

    def test_a_database_resolved_principal_reports_that(self) -> None:
        """Second: the database-backed set, which is the one a grant
        revocation actually changes."""
        user = _principal_for(resolved_permissions=frozenset({"cases:write", "actions:execute:high"}))

        assert set(user.effective_permissions()) == {"cases:write", "actions:execute:high"}

    def test_scopes_win_over_resolved_permissions(self) -> None:
        """The order is not arbitrary. An API key must not inherit its owner's
        full database grant set -- that is the whole point of scoping a key."""
        user = _principal_for(
            scopes=["alerts:read"],
            resolved_permissions=frozenset({"*"}),
        )

        assert set(user.effective_permissions()) == {"alerts:read"}

    def test_a_plain_session_falls_back_to_the_static_role_map(self) -> None:
        """Third. This is the behaviour that shipped for fourteen releases, so
        falling back to it is no worse than before -- and never returning an
        empty list is the whole fix."""
        user = _principal_for(role="admin")

        assert user.effective_permissions(), "an admin session resolved to no permissions at all"

    def test_an_unknown_role_is_empty_rather_than_wildcard(self) -> None:
        """The negative control. Failing *open* here would make a typo in a
        role name grant everything."""
        user = _principal_for(role="not-a-real-role")

        assert user.effective_permissions() == []


class TestTheRouteUsesIt:
    def test_the_dispatch_builds_its_principal_from_the_method(self) -> None:
        source = APPROVALS.read_text(encoding="utf-8")

        assert "effective_permissions()" in source, (
            "approvals.py does not use CurrentUser.effective_permissions(), so the principal is "
            "still assembled from attributes CurrentUser does not have"
        )

    def test_it_no_longer_reads_attributes_that_do_not_exist(self) -> None:
        """The exact shape of the bug: `getattr(user, "permissions", [])` on an
        object with no such attribute, defaulting to empty and denying
        everything downstream."""
        source = APPROVALS.read_text(encoding="utf-8")

        assert 'getattr(user, "permissions"' not in source
        assert 'getattr(user, "roles"' not in source

    def test_the_route_does_not_import_the_static_map(self) -> None:
        """`check_one_permission_model` refuses this, and it refuses it because
        a published advisory came from a route deciding permissions for
        itself."""
        tree = ast.parse(APPROVALS.read_text(encoding="utf-8"))

        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(a.name for a in node.names)

        assert "ROLE_PERMISSIONS" not in imported, "approvals.py imports the static permission map. Resolve through CurrentUser instead."

    def test_submit_also_identifies_its_caller(self) -> None:
        """`submit_action` passed no principal at all, which is harmless only
        while `AISOC_ACTIONS_REQUIRE_PRINCIPAL` defaults false. Flipping that
        flag would have broken the submit leg the same way.

        Read off the call's keyword arguments rather than a character window
        around it -- a window is sensitive to how much comment sits between
        the call and the argument, which is a property of the prose and not
        of the code.
        """
        tree = ast.parse(APPROVALS.read_text(encoding="utf-8"))

        submits = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "submit_action"
        ]

        assert submits, "submit_action is no longer called; re-point this test"
        for call in submits:
            kwargs = {kw.arg for kw in call.keywords}
            assert "principal" in kwargs, "a submit_action call still identifies no caller"


class TestTheDownstreamCheckWouldHaveDenied:
    """Pins *why* an empty list was fatal, so the fix cannot be undone by
    someone concluding the empty list was harmless.

    Runs the real function in a subprocess rather than importing it. Both
    `services/api` and `services/actions` name their top-level package `app`,
    so importing the actions one into this process shadows the API's and the
    test silently measures the wrong thing -- or, as here, fails to import at
    all. A subprocess gets its own `sys.path` and genuinely executes the
    shipped code.
    """

    @pytest.mark.parametrize("required", ["actions:execute:high", "actions:execute:low"])
    def test_an_empty_permission_list_is_an_unconditional_denial(self, required: str) -> None:
        actions_root = REPO_ROOT / "services" / "actions"
        if not (actions_root / "app" / "security" / "authz.py").is_file():
            pytest.skip("services/actions is not present in this checkout")

        done = subprocess.run(
            [
                sys.executable,
                "-c",
                f"from app.security.authz import has_action_permission as h;print(h([], {required!r}))",
            ],
            cwd=actions_root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        if done.returncode != 0:
            pytest.skip(f"actions service deps unavailable here: {done.stderr.strip()[-160:]}")
        assert done.stdout.strip() == "False", (
            "an empty permission list no longer denies. If this changed deliberately, the "
            "approval principal fix is still required -- an empty list means the approver's "
            "permissions were never resolved."
        )
