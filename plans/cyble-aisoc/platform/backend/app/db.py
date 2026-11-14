"""SQLite + SQLModel database engine."""
from __future__ import annotations

from contextlib import contextmanager
from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

from app.config import settings

engine = create_engine(
    f"sqlite:///{settings.db_path}",
    echo=False,
    connect_args={"check_same_thread": False},
)


# Lightweight forward-only column additions for SQLite. `create_all` only
# creates *missing tables*; it never alters an existing table to pick up new
# columns. That's a footgun every time we add a field to an existing model
# (rollback audit trail, FinOps token-cost columns, etc.) because the dev DB
# at `data/aisoc.db` survives across upgrades and would otherwise drift.
#
# We keep the migration deliberately small and additive: ADD COLUMN only,
# never DROP / RENAME / type-change. Destructive migrations belong in a real
# migration tool (Alembic) once we have a production deploy; for now this
# closes the "make dev / git pull / boom" gap without dragging in Alembic.
_ADDITIVE_COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "toolcall": [
        # t1-reverse-actions: paired rollback audit trail.
        ("rollback_of_id", "INTEGER REFERENCES toolcall(id)"),
        ("rolled_back_at", "DATETIME"),
        ("rolled_back_by", "VARCHAR"),
    ],
}


def _apply_additive_migrations() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, columns in _ADDITIVE_COLUMN_MIGRATIONS.items():
            if table not in existing_tables:
                # `create_all` will have already produced the up-to-date
                # schema, so there's nothing to back-fill.
                continue
            present = {c["name"] for c in inspector.get_columns(table)}
            for col_name, col_type in columns:
                if col_name in present:
                    continue
                conn.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN "{col_name}" {col_type}')
                )


def init_db() -> None:
    from app.models import (  # noqa: F401
        academy,
        alert,
        asset,
        benchmark,
        brand,
        case,
        detection_packs,
        detection_validation,
        federated,
        finops,
        region,
        graph,
        hitl,
        ioc,
        memory,
        mssp,
        passkey,
        supply_chain,
        tenant_connector,
        threat_actor,
        tool_call,
        tool_output_audit,
        trace,
        workspace,
    )

    SQLModel.metadata.create_all(engine)
    _apply_additive_migrations()


@contextmanager
def session_scope() -> Session:
    s = Session(engine)
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Session:
    """FastAPI dependency."""
    with Session(engine) as s:
        yield s
