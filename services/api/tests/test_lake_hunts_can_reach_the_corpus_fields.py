"""The shipped hunt corpus can actually be compiled against the lake.

Fix pass item 5.3. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
The README publishes "68-hunt YAML library, replayed against tenant events" as
**Stable**. Measured against `lake_hunt.py`'s field map, the corpus used 114
distinct field names and **zero** of them resolved to a lake column. All 243
field uses were reported unsupported, so every hunt either returned an
unfiltered table or nothing -- the library was not replayable against tenant
events at all.

Two causes. Every one of the 68 hunts filters on a bare `source`, which the
lake stores as `connector_type` and the map did not mention. And the remaining
113 are vendor names -- `EventID`, `CommandLine`, `eventName` -- that have no
dedicated column but which the stored payload carries: the lake keeps the whole
original event in `raw_payload`, and nothing reached into it.

What "resolvable" means here, precisely
---------------------------------------
That the compiler can build a predicate for the field, not that the predicate
will match. A payload extraction finds the field if the event carries it, and
that is a property of the connector's output, not of this compiler. The honest
claim is therefore "compiles against the lake", and the README says that rather
than implying every hunt returns results.
"""

from __future__ import annotations

import collections
import glob
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def _corpus_fields() -> collections.Counter:
    counts: collections.Counter = collections.Counter()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            field = node.get("field")
            if isinstance(field, str):
                counts[field] += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for path in glob.glob(str(REPO_ROOT / "hunts" / "*.yaml")):
        walk(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    return counts


def _resolvable(field: str) -> bool:
    from app.services.lake_hunt import _column_for, _payload_expression

    return _column_for(field) is not None or _payload_expression(field, "k") is not None


class TestTheCorpusResolves:
    def test_every_field_the_corpus_filters_on_can_be_compiled(self) -> None:
        fields = _corpus_fields()
        assert fields, "no fields found in hunts/*.yaml; the corpus moved"

        unresolved = sorted(f for f in fields if not _resolvable(f))

        assert not unresolved, f"{len(unresolved)} of {len(fields)} field names cannot be compiled against the lake: {unresolved[:10]}"

    def test_source_maps_to_the_column_the_lake_actually_has(self) -> None:
        """All 68 hunts filter on it, and the lake calls it `connector_type`."""
        from app.services.lake_hunt import _column_for

        assert _column_for("source") == "connector_type"


class TestTheFallbackCannotBeUsedToInject:
    @pytest.mark.parametrize(
        "field",
        [
            "evil') OR 1=1 --",
            "a';DROP TABLE aisoc.raw_events;--",
            "raw_payload, 'x') = '' OR (JSONExtractString(raw_payload",
            "",
            "   ",
            "1startswithadigit",
            "has-a-hyphen",
            "a" * 200,
        ],
    )
    def test_a_field_name_that_is_not_an_identifier_is_refused(self, field: str) -> None:
        """Refused, not escaped.

        The name is bound as a query parameter and never interpolated, so this
        is belt and braces -- but a field name that cannot be a field name has
        no business reaching the query builder, and refusing is cheaper than
        reasoning about every downstream use of the string.
        """
        from app.services.lake_hunt import _payload_expression

        assert _payload_expression(field, "k") is None, f"{field!r} was accepted as a payload field"

    def test_an_accepted_field_name_is_bound_not_interpolated(self) -> None:
        """The negative control on the mechanism: the expression must contain a
        placeholder, and must not contain the field name itself."""
        from app.services.lake_hunt import _payload_expression

        expression = _payload_expression("EventID", "f0")

        assert expression is not None
        assert "%(f0_field)s" in expression
        assert "EventID" not in expression, "the field name was interpolated into the SQL"

    def test_the_windows_nestings_are_reached(self) -> None:
        """`EventData` and `System` are where Windows puts its payload, one
        level below anything flat -- the same nesting that once made 2,173
        Sigma rules unable to fire."""
        from app.services.lake_hunt import _payload_expression

        expression = _payload_expression("CommandLine", "f0")

        assert expression is not None
        assert "'EventData'" in expression
        assert "'System'" in expression


class TestTheCompilerStillRefusesWhatItShould:
    def test_a_compiled_hunt_binds_the_payload_field_name(self) -> None:
        from app.services.lake_hunt import compile_hunt

        class _Intents:
            filters = [("EventID", "==", "4625")]
            group_by: list[str] = []
            limit = 10

        compiled = compile_hunt(_Intents(), tenant_id="11111111-1111-1111-1111-111111111111", hours=24)

        assert compiled.params.get("f0_field") == "EventID"
        assert "EventID" not in compiled.sql
        assert not compiled.unsupported_fields
