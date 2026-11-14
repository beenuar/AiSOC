"""Does the database schema match the migrations this build ships?

Nothing asked. ``aisoc_schema_migrations`` was read in exactly one place —
``app/scripts/run_migrations.py``, the runner that writes it — so no readiness
probe and no startup check ever graded it. A deployment whose migration step
failed, was skipped, or was rolled back ran new code against an old schema
while ``/health`` answered 200 and ``/readyz`` answered ready, and the first
symptom was an ``UndefinedColumnError`` on whichever request happened to touch
the missing column.

Report, do not refuse
---------------------
A skewed schema is reported on ``/readyz`` and on
``GET /api/v1/system/version``, and it is registered as a **non-required**
dependency on purpose. Failing readiness would pull the console out of the
load balancer, and an operator in the middle of an incident losing their
console because a migration is behind is a worse outcome than the skew
itself. ``/readyz`` answers ``ready_degraded`` with the detail; the
orchestrator keeps routing; the operator can see exactly what is wrong.

Three states, because an unknown is not a clean bill of health
--------------------------------------------------------------
``current``   — the applied set and the tree agree exactly.
``skewed``    — they disagree. ``pending`` names migrations the tree ships
                and the database has not applied (new code, old schema — the
                dangerous direction). ``applied_not_on_disk`` names the
                reverse (a rolled-back deploy, old code on a newer schema).
                One verdict, both directions named in the payload.
``unknown``   — the comparison could not be performed: no database, no
                ``aisoc_schema_migrations`` table, or a query that raised.

The third is the one this repository keeps getting wrong. A gate whose
unknown bucket is a pass is indistinguishable from a gate that works, right
up until it matters, so ``unknown`` is never ``current`` and ``healthy`` is
true only for ``current``.

Filenames, not parsed numbers
-----------------------------
``run_migrations.py`` tracks migrations by filename and applies them in
``sorted()`` filename order. ``scripts/check_migration_numbering.py`` exists
because duplicate numeric prefixes are a real occurrence here — thirteen
pre-existing collisions are deliberately frozen — so comparing on a parsed
number would fold two distinct migrations into one and call a database that
is missing one of them current.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

#: The directory ``run_migrations.py`` reads. Kept as a module constant so a
#: test can assert the two agree rather than assuming they do.
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

#: Wall-clock budget for the database read. ``/readyz`` already bounds a
#: dependency probe at 1.5 s; this keeps the same ceiling for the callers
#: that invoke the probe directly, so neither surface can hang on a database
#: that accepts a connection and then stops answering.
_QUERY_TIMEOUT_SECONDS = 1.5

SkewState = Literal["current", "skewed", "unknown"]


@dataclass(frozen=True)
class SchemaSkew:
    """The verdict, plus everything needed to act on it."""

    state: SkewState
    detail: str
    on_disk_count: int
    applied_count: int | None
    latest_applied: str | None
    pending: list[str] = field(default_factory=list)
    applied_not_on_disk: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        """What ``/readyz`` reads. Only an established match passes."""
        return self.state == "current"

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "detail": self.detail,
            "migrations_on_disk": self.on_disk_count,
            "migrations_applied": self.applied_count,
            "latest_applied": self.latest_applied,
            "pending": self.pending,
            "applied_not_on_disk": self.applied_not_on_disk,
        }


def migrations_on_disk(directory: Path | None = None) -> list[str]:
    """Migration filenames this build ships, in the order they are applied."""
    target = MIGRATIONS_DIR if directory is None else directory
    try:
        return sorted(p.name for p in target.iterdir() if p.suffix == ".sql" and p.is_file())
    except OSError:
        # A build with no migrations directory ships no migrations. That is a
        # knowable fact, not an unanswerable question, so it is an empty list
        # rather than an error — `evaluate_skew` decides what it means.
        return []


def evaluate_skew(
    *,
    applied: set[str] | None,
    on_disk: list[str],
    reason: str | None = None,
) -> SchemaSkew:
    """Compare the two sets. Pure, so the three verdicts are testable.

    *applied* is ``None`` when the database could not be asked. That is not
    the same as an empty set — an empty set is a database that answered and
    has applied nothing, which is real, actionable skew.
    """
    ordered = sorted(on_disk)
    if applied is None:
        return SchemaSkew(
            state="unknown",
            detail=(
                "Applied migrations could not be read"
                + (f" ({reason})" if reason else "")
                + f"; {len(ordered)} migration(s) on disk were not compared."
            ),
            on_disk_count=len(ordered),
            applied_count=None,
            latest_applied=None,
        )

    pending = [name for name in ordered if name not in applied]
    extra = sorted(applied - set(ordered))
    # The high-water mark is the last applied migration in apply order, which
    # is what an operator compares against a release's migration list. Taking
    # max() of the applied set would be the same thing only while every
    # applied name is also on disk.
    applied_in_order = [name for name in ordered if name in applied]
    latest = applied_in_order[-1] if applied_in_order else (extra[-1] if extra else None)

    if not pending and not extra:
        return SchemaSkew(
            state="current",
            detail=f"All {len(ordered)} migration(s) on disk are applied.",
            on_disk_count=len(ordered),
            applied_count=len(applied),
            latest_applied=latest,
        )

    parts: list[str] = []
    if pending:
        parts.append(f"{len(pending)} migration(s) on disk are not applied: {', '.join(pending)}")
    if extra:
        parts.append(f"{len(extra)} applied migration(s) are not in this build: {', '.join(extra)}")
    return SchemaSkew(
        state="skewed",
        detail="; ".join(parts) + ".",
        on_disk_count=len(ordered),
        applied_count=len(applied),
        latest_applied=latest,
        pending=pending,
        applied_not_on_disk=extra,
    )


async def _read_applied() -> tuple[set[str] | None, str | None]:
    """``(applied, reason)``. ``(None, reason)`` when the answer is unknown."""
    # Imported here rather than at module scope: importing the engine builds a
    # connection pool, and this module is also imported by the pure-function
    # tests and by `scripts/export_openapi.py`, neither of which should pay
    # for one.
    #
    # SQLAlchemy is deferred for a second reason. Everything above this
    # function is the standard library, which is what lets
    # `scripts/pending_migrations.py` load this file by path and share the
    # comparison rather than keeping a second copy of it — see that script's
    # docstring. A module-scope third-party import would put the two
    # implementations back.
    from sqlalchemy import text

    from app.db.database import AsyncSessionLocal

    try:
        async with asyncio.timeout(_QUERY_TIMEOUT_SECONDS):
            async with AsyncSessionLocal() as session:
                result = await session.execute(text("SELECT name FROM aisoc_schema_migrations"))
                return {row[0] for row in result}, None
    except TimeoutError:
        return None, "the query did not finish within 1.5s"
    except Exception as exc:  # noqa: BLE001 — a probe must answer, not raise
        # The table being absent is the single most informative case, and it
        # arrives wrapped by SQLAlchemy, so the class name alone would read as
        # a generic ProgrammingError. Name it.
        chain = f"{type(exc).__name__}: {exc}"
        if "aisoc_schema_migrations" in chain and "does not exist" in chain:
            return None, "the aisoc_schema_migrations table does not exist — migrations have never run here"
        return None, type(exc).__name__


async def probe_schema_current() -> SchemaSkew:
    """Evaluate skew against the live database. Never raises."""
    try:
        on_disk = migrations_on_disk()
        applied, reason = await _read_applied()
        return evaluate_skew(applied=applied, on_disk=on_disk, reason=reason)
    except Exception as exc:  # noqa: BLE001 — belt and braces; see the docstring
        return evaluate_skew(applied=None, on_disk=[], reason=type(exc).__name__)


class SchemaSkewed(Exception):
    """Raised by the readiness probe when the tree and the database disagree."""


class SchemaStateUnknown(Exception):
    """Raised by the readiness probe when the comparison could not be made."""


async def readyz_probe() -> bool:
    """The ``/readyz`` adapter. Three states through a two-state channel.

    ``register_dependency`` evaluates a probe's result with ``bool(...)`` and
    reports only ``True``/``False`` plus, on failure, ``type(exc).__name__``
    under ``dependency_errors``. Returning the :class:`SchemaSkew` itself
    would be the worst available answer: a dataclass instance is always
    truthy, so every verdict — including ``unknown`` — would be published as
    healthy. That is precisely the defect this module exists to prevent,
    reintroduced one layer up.

    So ``current`` returns ``True`` and the other two raise, with distinct
    class names. The exception name is the only detail channel the shared
    ``_health.py`` exposes, and using it keeps ``unknown`` legible as
    something other than ``skewed`` on ``/readyz``:

        "dependency_errors": {"schema_migrations_current": "SchemaStateUnknown"}

    ``_health.py`` is vendored byte-identical into thirteen services and
    gated on that, so widening its contract is a thirteen-service change;
    this adapter is the right size of fix for one service's need.
    """
    skew = await probe_schema_current()
    if skew.state == "current":
        return True
    if skew.state == "unknown":
        raise SchemaStateUnknown(skew.detail)
    raise SchemaSkewed(skew.detail)
