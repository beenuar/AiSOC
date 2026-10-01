"""The audit log says which credential acted, and the tenant can read it.

Two defects, both of which made the log less useful than it looked.

**Attribution.** An API key owned by a user resolves to that user's email,
so an entry read `alice@corp.com deleted the rule` whether Alice did it at
the console or a key she minted a year ago did it from a script she no
longer runs. An investigator reading that line cannot tell which, and the
two call for different responses: revoke a key, or disable a person.

**Readership.** `tenant_admin` did not hold `audit_log:read`. The only roles
that did were `platform_admin` and `admin`, both of which hold `*` across
every tenant — so on a multi-tenant deployment the only principals who could
answer "who changed this?" about a customer's data were the operator's own
staff, and the customer had to ask. SOC 2 CC7.2 and ISO 27001 A.12.4 both
require the control owner to be able to review their own trail.

Granting that read is safe because both handlers already filter on the
authenticated `tenant_id`, which is asserted below rather than assumed —
a grant without that predicate would have turned a compliance gap into a
cross-tenant read.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.core.security import ROLE_PERMISSIONS

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestTheCredentialIsRecorded:
    def test_a_session_principal_carries_no_key_prefix(self) -> None:
        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="soc_analyst", email="a@example.com")
        assert user.api_key_prefix is None

    def test_an_api_key_principal_carries_one(self) -> None:
        user = CurrentUser(
            user_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            role="soc_analyst",
            email="a@example.com",
            scopes=["alerts:read"],
            # Deliberately not key-shaped. A realistic `aisoc_live_...`
            # literal is indistinguishable from a real credential to a
            # secret scanner, and a test fixture is not worth an
            # allowlist entry that would also cover a genuine leak.
            api_key_prefix="prefix-under-test",
        )
        assert user.api_key_prefix == "prefix-under-test"

    def test_emit_audit_accepts_and_records_it(self) -> None:
        from app.services import audit

        assert "api_key_prefix" in inspect.signature(audit.emit_audit).parameters
        source = inspect.getsource(audit.emit_audit)
        assert 'meta["auth_method"] = "api_key"' in source
        assert 'meta["api_key_prefix"]' in source

    def test_the_prefix_is_recorded_not_the_key(self) -> None:
        """A prefix identifies the key without being usable as one.

        It is also what the console displays and what an operator revokes
        by, so it is the identifier an investigator can act on.
        """
        from app.api.v1 import deps

        source = inspect.getsource(deps)
        assert "api_key_prefix=api_key.key_prefix" in source
        assert "api_key_prefix=api_key.key_hash" not in source
        assert "api_key_prefix=raw" not in source


class TestTheTenantCanReadItsOwnTrail:
    @pytest.mark.parametrize("role", ["tenant_admin"])
    def test_the_role_holds_the_permission(self, role: str) -> None:
        perms = ROLE_PERMISSIONS[role]
        assert "audit_log:read" in perms or "*" in perms, (
            f"{role} cannot read their own tenant's audit log, so only roles holding '*' "
            "across every tenant can answer 'who changed this?' for a customer"
        )

    @pytest.mark.parametrize("role", ["soc_analyst", "viewer", "threat_hunter"])
    def test_lower_roles_still_cannot(self, role: str) -> None:
        """The other direction, so this cannot pass by granting everyone.

        An audit trail readable by every analyst is one an insider can use
        to check whether their own activity has been noticed.
        """
        perms = ROLE_PERMISSIONS[role]
        assert "audit_log:read" not in perms and "*" not in perms

    def test_both_read_handlers_filter_on_the_authenticated_tenant(self) -> None:
        """The predicate that makes the grant safe.

        Asserted structurally: every call building the query must pass
        `current_user.tenant_id`, not a value from the request.
        """
        source = (SERVICE_ROOT / "app" / "api" / "v1" / "endpoints" / "audit.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        scoped = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "tenant_id":
                    continue
                value = keyword.value
                if (
                    isinstance(value, ast.Attribute)
                    and value.attr == "tenant_id"
                    and isinstance(value.value, ast.Name)
                    and value.value.id == "current_user"
                ):
                    scoped += 1
        assert scoped >= 2, f"expected both read handlers to scope on the authenticated tenant, found {scoped}"


class TestReadingTheTrailIsItselfRecorded:
    def test_the_list_handler_emits_an_audit_event(self) -> None:
        """Because the set of people who can read it just grew.

        An investigator asking "who looked at this?" must get an answer
        rather than a shrug, and that question only became answerable now
        that `tenant_admin` holds the read.
        """
        from app.api.v1.endpoints.audit import list_audit_events

        source = inspect.getsource(list_audit_events)
        assert "emit_audit(" in source
        assert 'action="audit_log:read"' in source

    def test_it_records_the_filters_not_the_rows(self) -> None:
        """Copying the results would duplicate the log into itself.

        The search term is the interesting fact — it is what the reader was
        looking for — and it is one line rather than a page of rows.
        """
        from app.api.v1.endpoints.audit import list_audit_events

        source = inspect.getsource(list_audit_events)
        assert '"filters"' in source
        assert '"matched": total' in source
        assert "items" not in source.split("emit_audit(")[1].split(")")[0]
