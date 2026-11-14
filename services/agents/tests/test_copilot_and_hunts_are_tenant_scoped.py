"""Copilot conversations and saved hunt searches belong to one tenant.

Both lived in a module-level dict — `_CONVERSATIONS` and `_SAVED_SEARCHES` —
with no tenant column anywhere, and the list handlers took no principal at
all. So `GET /copilot/conversations` returned every tenant's conversations
to whoever asked, `GET /copilot/conversations/{id}` returned any
conversation to anyone holding its id, and `GET /hunt/saved` did the same
for saved searches.

This is not chat history. A copilot conversation carries the analyst's
question, which names hosts and users, and the model's answer, which quotes
the alert evidence it was grounded on. A saved hunt search is the query an
analyst wrote against their own telemetry.

The durable point is that **a module global has no tenant**, so the moment a
handler writes to one the read can no longer be scoped: the information
needed to scope it was never stored. That is why these moved to tables
rather than gaining a filter.

Checked without a database, by reading the handlers' signatures and the
store's SQL. A live two-tenant replay belongs in `tests/isolation/`, which
runs against containers; these cases must hold in the unit suite so a
regression is caught on every pull request rather than only where containers
are available.
"""

from __future__ import annotations

import ast
import inspect
import pathlib

import pytest

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Every handler that reads or writes one of the two stores.
SCOPED_HANDLERS = (
    ("copilot", "list_conversations"),
    ("copilot", "get_conversation"),
    ("copilot", "chat"),
    ("copilot", "chat_stream"),
    ("hunt_search", "list_saved_searches"),
    ("hunt_search", "save_search"),
    ("hunt_search", "delete_saved_search"),
)


def _module(name: str):
    import importlib

    return importlib.import_module(f"app.api.{name}")


class TestTheDictsAreGone:
    @pytest.mark.parametrize(
        ("module", "name"),
        [("copilot", "_CONVERSATIONS"), ("hunt_search", "_SAVED_SEARCHES")],
    )
    def test_no_module_global_holds_the_data(self, module: str, name: str) -> None:
        source = (SERVICE_ROOT / "app" / "api" / f"{module}.py").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        assert name not in code, (
            f"{name} is back in {module}.py. It is one object for the whole process with no tenant, so the read cannot be scoped"
        )


class TestEveryHandlerResolvesATenant:
    @pytest.mark.parametrize(("module", "handler"), SCOPED_HANDLERS)
    def test_the_handler_binds_a_principal(self, module: str, handler: str) -> None:
        """Binding it at router level is not enough.

        Both routers already declared `dependencies=[Depends(...)]`, so every
        request *was* authenticated — and the handlers still could not scope,
        because none of them received the principal. Authenticated and
        scoped are different properties, and the gap between them is where
        this defect lived.
        """
        fn = getattr(_module(module), handler)
        params = inspect.signature(fn).parameters
        assert "principal" in params, (
            f"{module}.{handler} takes no principal, so it cannot name a tenant even though the router authenticates the request"
        )

    @pytest.mark.parametrize(("module", "handler"), SCOPED_HANDLERS)
    def test_the_handler_resolves_the_tenant_before_touching_the_store(self, module: str, handler: str) -> None:
        source = inspect.getsource(getattr(_module(module), handler))
        assert "_tenant_of(principal)" in source, f"{module}.{handler} never resolves a tenant from its principal"


class TestEveryStatementCarriesThePredicate:
    """The store's SQL, parsed rather than eyeballed.

    `resolve_scoped_tenant` returning the right id means nothing if a
    statement then forgets to use it, and that is the half a signature check
    cannot see.
    """

    def test_every_statement_filters_on_tenant_id(self) -> None:
        source = (SERVICE_ROOT / "app" / "api" / "conversation_store.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        statements: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            text = " ".join(node.value.split())
            upper = text.upper()
            # The verb must be followed by whitespace. Matching a bare prefix
            # caught the dict keys `updatedAt` and `updated_at`, which
            # uppercase to something starting with UPDATE — four string
            # literals reported as unscoped SQL.
            if any(upper.startswith(verb + " ") for verb in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                statements.append(text)

        assert len(statements) >= 6, f"expected the store's statements, found {len(statements)}"

        offenders = [
            s
            for s in statements
            if "tenant_id" not in s
            # An INSERT names the column in its column list instead of a
            # WHERE clause, which is the same property expressed differently.
        ]
        assert not offenders, f"statements with no tenant predicate: {offenders}"

    def test_the_rls_context_variable_is_spelled_correctly(self) -> None:
        """`app.current_tenant_id`, not `app.tenant_id`.

        Two modules in this tree used the wrong name until 2026-09 and the
        scope was silently never applied — every policy reads the first
        spelling, so the second sets a variable nothing consults and the
        query runs unscoped while looking correct.
        """
        source = (SERVICE_ROOT / "app" / "api" / "conversation_store.py").read_text(encoding="utf-8")
        assert "app.current_tenant_id" in source
        assert "'app.tenant_id'" not in source

    def test_an_unavailable_store_raises_rather_than_returning_empty(self) -> None:
        """Because an empty list is a claim about the tenant's data.

        The sibling stores in this service are deliberately best-effort — a
        database outage must not take the hunt scheduler offline. These are
        not, and the difference is that a scheduler losing a write retries,
        while an analyst shown an empty conversation list concludes their
        history is gone.
        """
        from app.api.conversation_store import ConversationStoreUnavailable

        assert issubclass(ConversationStoreUnavailable, RuntimeError)
        source = (SERVICE_ROOT / "app" / "api" / "conversation_store.py").read_text(encoding="utf-8")
        assert "raise ConversationStoreUnavailable" in source


class TestTheMigrationCreatesWhatTheStoreReads:
    def test_both_tables_exist_with_a_not_null_tenant(self) -> None:
        migration = (SERVICE_ROOT.parents[0] / "api" / "migrations" / "076_copilot_and_hunt_search_tenancy.sql").read_text(encoding="utf-8")
        for table in ("aisoc_copilot_conversations", "aisoc_saved_hunt_searches"):
            assert f"CREATE TABLE IF NOT EXISTS {table}" in migration
            assert "tenant_id       UUID NOT NULL" in migration, (
                f"{table} must make a row outside a tenant impossible, which is the property the dict could not have"
            )
            assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in migration
            assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in migration

    def test_the_dml_role_is_granted(self) -> None:
        """Or every write fails as a permission error on a real deployment.

        `ALTER DEFAULT PRIVILEGES` only covers tables created by the role
        that ran it, and the services connect as the DML-only `aisoc_app`.
        """
        migration = (SERVICE_ROOT.parents[0] / "api" / "migrations" / "076_copilot_and_hunt_search_tenancy.sql").read_text(encoding="utf-8")
        assert "TO aisoc_app" in migration
