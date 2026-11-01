"""The minimisation for AI-chat compliance data is in the schema.

Depth plan wave 2, Phase 7.1.

The plan sentence is "store only classification labels and a bounded
snippet, never full conversations". A sentence is not a control: a `TEXT`
column permits a conversation no matter what the prose above it says, and
the first caller that binds a whole message body will succeed silently.

So these tests read the migration and the ORM and assert the properties a
reviewer would otherwise have to take on trust:

1. no column anywhere in these tables can hold a message;
2. the snippet is bounded by the database, not only by the collector;
3. the label vocabulary is constrained, in three places that agree;
4. every table carries `tenant_id`, which is what puts it inside the
   tenant-erasure path and under RLS;
5. every table has an RLS policy with the cross-tenant-worker arm.

Point 4 matters more than it looks. `tenant_deletion.discover_tenant_tables`
finds tables by a column literally named `tenant_id` rather than from a
declared list, precisely so a migration cannot add a tenant-scoped table
that offboarding then misses. A new table that spelled it `tenant` would be
silently outside erasure, and nothing would say so.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from app.models.ai_chat_compliance import (
    AI_CHAT_LABELS,
    SNIPPET_MAX,
    AiChatAuditEvent,
    AiChatComplianceConfig,
    AiChatContentLabel,
    AiChatProject,
    AiChatUser,
)
from app.services.ai_chat_compliance.classifier import LABELS as CLASSIFIER_LABELS

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "146_ai_chat_compliance.sql"

TABLES = (
    "aisoc_ai_chat_compliance_config",
    "aisoc_ai_chat_users",
    "aisoc_ai_chat_projects",
    "aisoc_ai_chat_audit_events",
    "aisoc_ai_chat_content_labels",
)

MODELS = (AiChatComplianceConfig, AiChatUser, AiChatProject, AiChatAuditEvent, AiChatContentLabel)

#: Column names that would mean a conversation is being stored. Checked as
#: whole names rather than substrings, so `content_labels_enabled` and
#: `messages_examined` — a switch and a count — do not trip it.
FORBIDDEN_COLUMNS = {
    "body",
    "content",
    "text",
    "message",
    "messages",
    "transcript",
    "conversation",
    "prompt",
    "completion",
    "response",
}


@pytest.fixture(scope="module")
def sql() -> str:
    return MIGRATION.read_text()


def test_no_table_has_a_column_that_could_hold_a_conversation():
    """Asserted on the ORM, which is what application code binds through."""
    offenders: list[str] = []
    for model in MODELS:
        for column in model.__table__.columns:
            if column.name in FORBIDDEN_COLUMNS:
                offenders.append(f"{model.__tablename__}.{column.name}")
    assert not offenders, (
        "a column able to hold message content was added to the AI-chat "
        f"compliance tables: {offenders}. The whole minimisation argument "
        "for this feature rests on no such column existing."
    )


def test_the_snippet_is_bounded_by_the_database_and_not_only_by_the_collector(sql: str):
    """The column is the backstop for the caller that forgets to truncate."""
    assert f"snippet          VARCHAR({SNIPPET_MAX})" in sql
    assert AiChatContentLabel.__table__.c.snippet.type.length == SNIPPET_MAX


def test_the_only_unbounded_text_columns_are_identifiers(sql: str):
    """A `TEXT` column is where a conversation ends up by accident.

    Identifiers and the vault ciphertext are genuinely unbounded — a
    provider id has no published maximum and a Fernet token grows with the
    key — but every column carrying something a human wrote is a
    `VARCHAR`, and the bound is the point.
    """
    allowed_text = {
        "provider",
        "external_id",
        "chat_external_id",
        "project_external_id",
        "actor_external_id",
        "provider_org_id",
        "access_key_vault",
        "activity_cursor",
        "last_error",
        "labels",
        "secret_kinds",
    }
    for model in MODELS:
        for column in model.__table__.columns:
            type_name = type(column.type).__name__
            if type_name in {"Text", "TEXT"}:
                assert column.name in allowed_text, (
                    f"{model.__tablename__}.{column.name} is unbounded TEXT. If it carries anything a person wrote, give it a bound."
                )


def test_the_label_vocabulary_is_constrained_in_the_database(sql: str):
    """And in exactly the same three places.

    The CHECK constraint, the ORM module's tuple and the classifier's tuple
    are three copies of one vocabulary, which is the shape that drifts. An
    unconstrained label column is also how a classifier quietly ends up
    storing the matched *value* as a label.
    """
    match = re.search(r"labels <@ ARRAY\[([^\]]+)\]", sql)
    assert match, "the labels CHECK constraint is missing from migration 146"
    in_sql = tuple(re.findall(r"'([a-z_]+)'", match.group(1)))

    assert in_sql == AI_CHAT_LABELS
    assert CLASSIFIER_LABELS == AI_CHAT_LABELS


@pytest.mark.parametrize("table", TABLES)
def test_every_table_is_tenant_scoped_so_erasure_and_rls_reach_it(sql: str, table: str):
    """`tenant_id`, spelled exactly that way.

    `tenant_deletion.discover_tenant_tables` selects tables by a column
    literally named `tenant_id`, deliberately rather than from a list, so a
    migration cannot add a tenant-scoped table that offboarding misses. A
    table that spelled it `tenant` would be outside erasure with nothing
    saying so.
    """
    body = sql.split(f"CREATE TABLE IF NOT EXISTS {table} (", 1)
    assert len(body) == 2, f"{table} is not created by migration 146"
    assert "tenant_id" in body[1].split(");", 1)[0]


@pytest.mark.parametrize("model", MODELS, ids=[m.__tablename__ for m in MODELS])
def test_every_model_declares_tenant_id(model):
    assert "tenant_id" in model.__table__.c


def test_every_table_gets_rls_with_the_cross_tenant_worker_arm(sql: str):
    """Including the `OR current_tenant_id() IS NULL` arm.

    Dropping that arm does not fail anything loudly: it makes the retention
    purge and the tenant-deletion worker see zero rows and report success,
    which for an erasure is a compliance claim rather than a log line.
    """
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "tenant_id = current_tenant_id() OR current_tenant_id() IS NULL" in sql
    # Applied over the full table list, so adding a table to the migration
    # without adding it to the loop is visible here.
    loop = sql.split("FOREACH t IN ARRAY ARRAY[", 1)[1].split("]", 1)[0]
    for table in TABLES:
        assert f"'{table}'" in loop, f"{table} is not in the RLS loop"


def test_content_labelling_is_off_by_default_in_the_schema(sql: str):
    """Two opt-ins, and the stricter one is the default.

    A tenant that wants the activity feed and explicitly does not want
    message bodies read should get that without discovering a setting.
    """
    assert "content_labels_enabled BOOLEAN NOT NULL DEFAULT FALSE" in sql
    assert "enabled            BOOLEAN     NOT NULL DEFAULT FALSE" in sql
