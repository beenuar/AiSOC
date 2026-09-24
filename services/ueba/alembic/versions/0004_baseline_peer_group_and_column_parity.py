"""Bring the UEBA tables back in line with the models that read them.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-24

``0001`` and ``app/models/ueba.py`` disagreed in three places, and every one of
them was reached on the first scoreable event rather than on some rare path:

``ueba_entity_baselines.peer_group_id``
    Declared by :class:`~app.models.ueba.EntityBaseline`, created by no
    migration. SQLAlchemy names every mapped column in its ``SELECT``, so
    ``BaselineService.get_or_create`` — the first database call
    ``score_event`` makes — raised ``UndefinedColumnError``. UEBA could
    therefore never write a baseline or an anomaly, on any deployment, and
    the container stayed healthy throughout.

``ueba_peer_groups.id``
    Created as ``UUID DEFAULT gen_random_uuid()``, declared as
    ``String(64)``, and written with values like ``dept:engineering`` — the
    ids are externally-supplied group names, not surrogate keys, which is
    why ``PeerGroupService.get_or_create`` passes one explicitly. An insert
    raised ``InvalidTextRepresentation``. The column follows the model
    because the model matches the data; a UUID here would mean the caller
    could not look a group up by the name it knows it by.

``ueba_anomalies.event_type``
    ``String(64)`` in the table against ``String(128)`` in the model, so an
    event type between the two lengths passed every test and failed at
    insert time in production. Widened to the declared length rather than
    narrowing the model, which would only move the failure.

The remaining differences are the harmless direction — ``observation_count``,
``created_at`` and ``z_scores`` exist in the tables and are not mapped — and
are recorded as such in ``scripts/check_orm_migration_parity.py`` rather than
dropped. A column the models never name costs a default and nothing else;
removing it would be an irreversible change made for tidiness.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Guarded so the revision is safe on a database whose tables were created
    # from the models instead of from this chain (``create_all`` in a test
    # fixture, and the sandbox), where the column is already present.
    op.execute("ALTER TABLE ueba_entity_baselines ADD COLUMN IF NOT EXISTS peer_group_id VARCHAR(64)")

    # ``USING id::text`` rather than a drop-and-add: an existing row holds a
    # group whose members' baselines point at it, and a generated UUID is not
    # a name anything can look up again.
    op.execute("ALTER TABLE ueba_peer_groups ALTER COLUMN id DROP DEFAULT")
    op.execute("ALTER TABLE ueba_peer_groups ALTER COLUMN id TYPE VARCHAR(64) USING id::text")

    op.alter_column(
        "ueba_anomalies",
        "event_type",
        existing_type=sa.String(64),
        type_=sa.String(128),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "ueba_anomalies",
        "event_type",
        existing_type=sa.String(128),
        type_=sa.String(64),
        existing_nullable=False,
    )

    # A group id that is not a UUID cannot be cast back to one, so the
    # downgrade discards the names rather than failing halfway: anything this
    # revision made storable is not representable in the old column. Stated
    # here because a downgrade that silently drops rows is worse than one that
    # says it will.
    op.execute("DELETE FROM ueba_peer_groups WHERE id !~* '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'")
    op.execute("ALTER TABLE ueba_peer_groups ALTER COLUMN id TYPE UUID USING id::uuid")
    op.execute("ALTER TABLE ueba_peer_groups ALTER COLUMN id SET DEFAULT gen_random_uuid()")

    op.execute("ALTER TABLE ueba_entity_baselines DROP COLUMN IF EXISTS peer_group_id")
