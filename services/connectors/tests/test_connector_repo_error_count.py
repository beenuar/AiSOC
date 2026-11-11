"""``error_count`` is a consecutive-failure counter, not a lifetime total.

The fleet panel shows ``error_count`` beside ``last_sync`` as the connector's
current condition. Before #1821 the counter only ever grew:
``record_poll_failure`` incremented it and ``record_poll_success`` never
touched it, so a healthy connector with a fresh sync could show a days-old
error figure as if it were failing right now. These tests pin the semantics
at the only two writers.
"""

import uuid
from unittest.mock import AsyncMock

import pytest
from app.db.connector_repo import record_poll_failure, record_poll_success


class _CapturingConnection:
    """Stands in for an async SQLAlchemy connection; records the statement."""

    def __init__(self) -> None:
        self.execute = AsyncMock()

    @property
    def statement(self):
        assert self.execute.await_count == 1, "expected exactly one UPDATE"
        return self.execute.await_args.args[0]


def _compiled_params(statement) -> dict:
    compiled = statement.compile()
    return dict(compiled.params)


@pytest.mark.asyncio
async def test_poll_success_resets_error_count_to_zero() -> None:
    connection = _CapturingConnection()
    await record_poll_success(connection, uuid.uuid4(), events_added=3)

    params = _compiled_params(connection.statement)
    assert params["error_count"] == 0
    assert params["health_status"] == "healthy"


@pytest.mark.asyncio
async def test_poll_failure_still_increments_error_count() -> None:
    connection = _CapturingConnection()
    await record_poll_failure(connection, uuid.uuid4())

    compiled = str(connection.statement.compile())
    # The increment is a SQL expression over the current column value, so it
    # shows in the compiled text rather than in the bound parameters.
    assert "error_count + " in compiled
    params = _compiled_params(connection.statement)
    assert params["health_status"] == "unhealthy"
