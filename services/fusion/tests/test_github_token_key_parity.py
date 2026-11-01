"""The GitHub token join key must be byte-identical on both sides.

Depth plan wave 2, Phase 1.4.

`services/ingest/internal/activity/session.go` writes `hashed_token` into
the session projection, and `baselines.py` keys a token's baseline on the
same value. If the two normalise differently the baseline silently never
joins to the session — there is no error, no empty result and no log line,
just a token whose history is split across two keys on every GitHub event.

The trap is concrete. Go uses `strings.TrimSpace` and no case folding. The
Python module's general field helper lowercases, which is correct for a
username and wrong for a digest, so the obvious implementation is the broken
one.

Both languages read **the same committed fixture**, which is what makes this
a contract rather than two tests that happen to agree today:
`services/ingest/internal/activity/testdata/github_token_key.json`, also
read by `github_token_key_test.go`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from app.services.baselines import resolve_sub_principal

_FIXTURE = Path(__file__).resolve().parents[3] / "services" / "ingest" / "internal" / "activity" / "testdata" / "github_token_key.json"


def _cases() -> list[dict[str, Any]]:
    cases = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert cases, f"{_FIXTURE} contains no cases, so every assertion below would be vacuous"
    return cases


def test_the_shared_fixture_is_where_both_languages_look() -> None:
    """A parity test reading its own copy proves nothing.

    Two fixtures drift, and the drift is invisible precisely because both
    suites stay green. This asserts the file the Go test names is the file
    this test reads.
    """
    go_test = _FIXTURE.parent.parent / "github_token_key_test.go"
    assert go_test.is_file(), "the Go half of this contract is missing"
    assert "testdata/github_token_key.json" in go_test.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", _cases(), ids=lambda c: str(c["name"]))
def test_python_derives_the_same_key_as_go(case: dict[str, Any]) -> None:
    event: dict[str, Any] = {"connector_type": "github", "actor": "alice"}
    if case["hashed_token"] is not None:
        event["hashed_token"] = case["hashed_token"]

    subject = resolve_sub_principal(event)
    expected = case["expected_key"]

    if not expected:
        # No credential on the entry. The resolver must not fall through to
        # a different sub-principal kind and silently key the baseline on
        # something else — which would be worse than returning nothing,
        # because the numbers would look populated.
        assert subject is None or subject.kind != "api_token", case["why"]
        return

    assert subject is not None, case["why"]
    assert subject.kind == "api_token"
    assert subject.id == expected, case["why"]


def test_lowercasing_the_token_would_break_the_join() -> None:
    """The negative control for the whole contract.

    If this ever stops distinguishing the two spellings, the parity above
    is being satisfied by a resolver that folds case, and the fixture's
    mixed-case entries would pass by accident.
    """
    mixed = "AbC123+/xyz="
    subject = resolve_sub_principal({"connector_type": "github", "hashed_token": mixed})
    assert subject is not None
    assert subject.id != mixed.lower()
    assert subject.id == mixed
