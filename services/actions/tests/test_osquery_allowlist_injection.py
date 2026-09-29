"""GHSA-p37g-cjqx-56hq: parameter values must not be able to alter the SQL.

`render_query()` interpolated caller-supplied parameters into osquery SQL with
`str.format_map()` and then scanned the *result* for `--`, `/*` and `;`. A
denylist enumerates what is forbidden, so what it did not enumerate was
allowed: `'` was not on the list, and `recent_files` wraps `directory` in
single quotes, so `' OR 1=1 OR directory='` closed the literal and replaced
the WHERE clause. The numeric parameters were never coerced, so `LIMIT
{limit}` took `1 UNION SELECT ...` verbatim — a hole the advisory did not
name and which the `recent_files` fix alone would not have closed.

Every assertion here is written against symbols that exist on both sides of
the fix — `render_query`, `AllowlistError`, `TEMPLATES`, `PARAM_SPECS` — so
that on the vulnerable tree these tests fail because the injection succeeds,
not because an import is missing. A test that fails with `ImportError` has
proved a symbol absent, which is not the same as proving a vulnerability
caught.

The load-bearing test is `TestStatementStructure`, which is a property over
every template and every parameter rather than a list of payloads. The
payload list is what the denylist got wrong; enumerating a longer one would
repeat the mistake at a larger size.
"""

from __future__ import annotations

import pytest
from app.clients.osquery_allowlist import (
    PARAM_SPECS,
    TEMPLATES,
    AllowlistError,
    render_query,
)

#: Values that carry SQL structure. Each is hostile in *some* parameter
#: position; the tests below assert the outcome is the same in every position,
#: which is the property that was missing.
HOSTILE_VALUES: list[str] = [
    # The advisory's proof of concept: neither contains --, /* or ;.
    "' OR 1=1 OR directory='",
    "' UNION SELECT key,value,'','','','','','','','' FROM process_envs WHERE key LIKE '%SECRET%' AND ''='",
    # A bare quote is the whole vulnerability reduced to one character.
    "'",
    # Numeric positions are unquoted, so they need no quote to be injectable.
    "1 UNION SELECT 1,2,3,4,5,6,7,8,9 FROM users",
    "1 OR 1=1",
    # These three the old denylist did catch; they must keep failing.
    "/tmp'; DROP TABLE processes; --",
    "/tmp -- comment",
    "/tmp/*x*/",
]


def _structural_counts(sql: str) -> tuple[int, int]:
    """Single quotes and semicolons — the two characters that carry structure.

    A value that adds a quote has left the string literal it was placed in; a
    value that adds a semicolon has appended a second statement. Counting them
    on the rendered SQL and comparing against the template detects both without
    needing to know which payload was used.
    """
    return sql.count("'"), sql.count(";")


class TestAdvisoryProofOfConcept:
    """The two payloads in the report, asserted directly."""

    def test_quote_cannot_break_out_of_the_directory_literal(self) -> None:
        # Pre-fix this returns:
        #   ... WHERE directory = '' OR 1=1 OR directory='' LIMIT 100;
        # and the WHERE clause is gone.
        with pytest.raises(AllowlistError):
            render_query("recent_files", directory="' OR 1=1 OR directory='")

    def test_union_select_cannot_exfiltrate_the_process_environment(self) -> None:
        payload = "' UNION SELECT key,value,'','','','','','','','' FROM process_envs WHERE key LIKE '%SECRET%' AND ''='"
        with pytest.raises(AllowlistError):
            render_query("recent_files", directory=payload)

    def test_a_single_quote_is_refused(self) -> None:
        """The vulnerability at its smallest: one character the denylist lacked."""
        with pytest.raises(AllowlistError):
            render_query("recent_files", directory="/tmp'")


class TestNumericParameters:
    """Unquoted positions need no quote to be injectable.

    The advisory names `directory`; these were injectable too, and a fix scoped
    to `recent_files` would have left them open.
    """

    def test_limit_is_not_interpolated_verbatim(self) -> None:
        with pytest.raises(AllowlistError):
            render_query("running_processes", limit="1 UNION SELECT 1,2,3,4,5,6,7,8,9 FROM users")

    def test_pid_is_not_interpolated_verbatim(self) -> None:
        with pytest.raises(AllowlistError):
            render_query("process_tree", pid="1 OR 1=1")

    def test_max_depth_is_not_interpolated_verbatim(self) -> None:
        with pytest.raises(AllowlistError):
            render_query("process_tree", max_depth="5 UNION SELECT 1")

    def test_a_boolean_is_not_a_row_count(self) -> None:
        # bool subclasses int, so an unguarded int() check accepts it.
        with pytest.raises(AllowlistError):
            render_query("running_processes", limit=True)


class TestStatementStructure:
    """The property, over every template and every parameter.

    This is the test that would have caught the original defect without anyone
    having guessed the payload: for any value, in any parameter of any
    template, `render_query` either refuses it or emits SQL whose structure is
    identical to the template's.
    """

    @pytest.mark.parametrize("template_id", sorted(TEMPLATES))
    @pytest.mark.parametrize("hostile", HOSTILE_VALUES)
    def test_no_parameter_can_alter_the_statement(self, template_id: str, hostile: str) -> None:
        expected = _structural_counts(TEMPLATES[template_id])

        # ``PARAM_SPECS[template_id]`` yields parameter names whether it maps
        # each template to a set of names or to a dict keyed by them, so this
        # loop runs unchanged on both the vulnerable and the fixed module.
        for param_name in PARAM_SPECS[template_id]:
            try:
                rendered = render_query(template_id, **{param_name: hostile})
            except AllowlistError:
                continue  # refused, which is the intended outcome
            assert _structural_counts(rendered) == expected, (
                f"{template_id}.{param_name} accepted {hostile!r} and the rendered SQL no longer has the template's structure: {rendered}"
            )

    @pytest.mark.parametrize("template_id", sorted(TEMPLATES))
    def test_every_placeholder_has_a_declared_type(self, template_id: str) -> None:
        """No parameter reaches interpolation without a spec describing it."""
        import re  # noqa: PLC0415

        placeholders = {m.group(1) for m in re.finditer(r"\{(\w+)\}", TEMPLATES[template_id])}
        declared = set(PARAM_SPECS[template_id])
        assert placeholders <= declared, f"{template_id} interpolates {placeholders - declared} with no PARAM_SPECS entry"


class TestLegitimateValuesStillWork:
    """Refusing everything would also pass the tests above.

    A forensic query that cannot name the directory it is asked about is not a
    fix, so these pin the values an operator actually uses. `C:\\Program Files
    (x86)` is the one that matters: it is on every Windows host, and the
    parentheses are inert inside a string literal.
    """

    @pytest.mark.parametrize(
        "directory",
        [
            "/tmp",
            "/var/log",
            "/opt/my-app_v2.1 (beta)",
            "C:\\Windows\\System32",
            "C:\\Program Files (x86)",
            "\\\\fileserver\\share",
            "/home/josé/docs",
        ],
    )
    def test_real_directories_render(self, directory: str) -> None:
        sql = render_query("recent_files", directory=directory)
        assert directory in sql
        assert _structural_counts(sql) == _structural_counts(TEMPLATES["recent_files"])

    def test_numeric_parameters_accept_numbers(self) -> None:
        assert "50" in render_query("running_processes", limit=50)
        assert "1234" in render_query("process_tree", pid=1234)

    def test_every_template_renders_with_its_defaults(self) -> None:
        for template_id in TEMPLATES:
            assert render_query(template_id).endswith(";")
