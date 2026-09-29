"""Read-only parameterised osquery SQL templates.

Playbook steps reference templates by ID rather than passing raw SQL directly to
osctrl / FleetDM / aisoc-direct.  This ensures that the only queries that can be
executed on remote hosts via a playbook are those that have been reviewed and
approved here.

Usage
-----

    from app.clients.osquery_allowlist import render_query, TEMPLATES

    sql = render_query("running_processes", pid=1234)  # KeyError if unknown template
    sql = render_query("active_connections")            # no params needed

Every parameter declares a type in :data:`PARAM_SPECS`, and a value that is
not that type is refused.  See the parameter-contract section below for why
that is the control rather than a scan for dangerous substrings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class AllowlistError(ValueError):
    """Raised when a query or parameter fails allowlist validation."""


# ---------------------------------------------------------------------------
# Parameter contract
# ---------------------------------------------------------------------------
#
# This module used to interpolate whatever the caller passed and then scan the
# result for `--`, `/*` and `;`.  A denylist enumerates what is forbidden, so
# everything it failed to think of was permitted: `'` was not on the list, and
# `recent_files` wraps `directory` in single quotes, so a value of
# `' OR 1=1 OR directory='` closed the literal and replaced the WHERE clause.
# The numeric parameters were never coerced either, so `LIMIT {limit}` accepted
# `1 UNION SELECT ...` verbatim.  (GHSA-p37g-cjqx-56hq.)
#
# Each parameter now declares what it *is* — a bounded whole number, or an
# absolute filesystem path — and a value that is not that is refused.  osquery
# is reached through FleetDM's and osctrl's REST APIs, both of which take a
# finished SQL string and expose no bind-parameter channel, so binding is not
# available at this boundary; making the dangerous value unrepresentable is.
#
# Refusing rather than escaping is deliberate.  An escaped path is still a
# path: it reaches the endpoint, matches nothing, and returns zero rows.  On a
# forensic query that is indistinguishable from a clean host, so an operator
# reads a successful answer to a question that was never asked.  A refusal is
# loud and cannot be mistaken for a result.


#: What makes a path absolute, per platform: POSIX (`/var/log`), Windows
#: (`C:\\Windows`) or UNC (`\\\\host\\share`).  A relative path is refused
#: because the `file` table resolves against the agent's working directory,
#: which is not a property the caller gets to depend on.
_ABSOLUTE_PREFIX_RE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)")

#: Characters a path value may not contain.
#:
#: `'` and `;` are the two that carry structure in the rendered statement: a
#: quote ends the literal the value sits in, and a semicolon starts a second
#: statement.  Excluding them is what makes the injection unrepresentable
#: rather than filtered.  `"` and backtick are SQLite's identifier quotes —
#: inert inside a single-quoted literal, but illegal in Windows paths and
#: vanishingly rare elsewhere, so refusing them costs nothing and removes a
#: whole class of argument about dialects.  The C0 range and DEL are refused
#: because a newline in a path is a log-forging primitive, not a path.
#:
#: Everything else printable is allowed, including parentheses, spaces and
#: non-ASCII: `C:\\Program Files (x86)` is on every Windows host, and a path
#: refused here is a forensic question that cannot be asked at all.  Backslash
#: is permitted because osquery uses SQLite syntax, where backslash is not an
#: escape character inside a string literal.
_FORBIDDEN_IN_PATH_RE = re.compile("[\x00-\x1f\x7f'\"`;]")


@dataclass(frozen=True)
class _Integer:
    """A whole number within an inclusive range, and nothing else."""

    minimum: int
    maximum: int

    def describe(self) -> str:
        return f"a whole number between {self.minimum} and {self.maximum}"

    def coerce(self, name: str, value: Any) -> int:
        # `bool` is a subclass of `int`; `LIMIT True` is not a limit.
        if isinstance(value, bool) or not isinstance(value, int | str):
            raise AllowlistError(f"Parameter '{name}' must be {self.describe()}, not {type(value).__name__}.")
        try:
            number = int(str(value).strip())
        except ValueError:
            raise AllowlistError(f"Parameter '{name}' must be {self.describe()}; got {value!r}.") from None
        if not self.minimum <= number <= self.maximum:
            raise AllowlistError(f"Parameter '{name}' must be {self.describe()}; got {number}.")
        return number


@dataclass(frozen=True)
class _AbsolutePath:
    """An absolute filesystem path, and nothing else."""

    max_length: int = 4096

    def describe(self) -> str:
        return "an absolute filesystem path"

    def coerce(self, name: str, value: Any) -> str:
        if not isinstance(value, str):
            raise AllowlistError(f"Parameter '{name}' must be {self.describe()}, not {type(value).__name__}.")
        if not value or len(value) > self.max_length:
            raise AllowlistError(f"Parameter '{name}' must be {self.describe()} of 1 to {self.max_length} characters; got {len(value)}.")
        if not _ABSOLUTE_PREFIX_RE.match(value):
            raise AllowlistError(
                f"Parameter '{name}' must be {self.describe()} starting with '/', a drive letter such as 'C:\\', or a UNC '\\\\' prefix."
            )
        if _FORBIDDEN_IN_PATH_RE.search(value):
            # A path that legitimately contains one of these is refused rather
            # than escaped — see the parameter-contract note above.
            raise AllowlistError(
                f"Parameter '{name}' must be {self.describe()} and may not contain quotes, backticks, semicolons or control characters."
            )
        return value


#: The declared type of every parameter, by template.
_ParamType = _Integer | _AbsolutePath


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

# Each value is a SQL template string.  Python's str.format_map() is used for
# parameter substitution; callers supply keyword arguments which are validated
# against the parameter spec before interpolation.
#
# Rules for adding templates:
#   1. SQL must use parameterised placeholders in the form {param_name}.
#   2. The companion PARAM_SPECS entry must declare a type for every
#      placeholder name. There is no untyped parameter: a placeholder with no
#      spec raises rather than falling through to raw interpolation.
#   3. No DML (INSERT/UPDATE/DELETE) or DDL (CREATE/DROP/ALTER) is allowed.
#   4. Subqueries must not invoke osquery attach or join against .autoload tables
#      that modify host state.

TEMPLATES: dict[str, str] = {
    "running_processes": (
        "SELECT pid, name, path, cmdline, uid, gid, start_time, "
        "parent AS ppid, on_disk "
        "FROM processes "
        "ORDER BY start_time DESC "
        "LIMIT {limit};"
    ),
    "active_connections": (
        "SELECT pid, fd, socket, remote_address, remote_port, "
        "local_address, local_port, protocol, state "
        "FROM process_open_sockets "
        "WHERE remote_address != '' "
        "AND remote_port != 0 "
        "LIMIT {limit};"
    ),
    "logged_in_users": ("SELECT type, user, host, tty, time FROM logged_in_users ORDER BY time DESC LIMIT {limit};"),
    "recent_files": (
        "SELECT path, directory, filename, size, type, "
        "atime, mtime, ctime, uid, gid "
        "FROM file "
        "WHERE directory = '{directory}' "
        "LIMIT {limit};"
    ),
    "process_tree": (
        "WITH RECURSIVE proctree(pid, ppid, name, path, cmdline, depth) AS ( "
        "  SELECT pid, parent AS ppid, name, path, cmdline, 0 AS depth "
        "  FROM processes "
        "  WHERE pid = {pid} "
        "  UNION ALL "
        "  SELECT p.pid, p.parent, p.name, p.path, p.cmdline, pt.depth + 1 "
        "  FROM processes p "
        "  JOIN proctree pt ON p.parent = pt.pid "
        "  WHERE pt.depth < {max_depth} "
        ") "
        "SELECT pid, ppid, name, path, cmdline, depth "
        "FROM proctree "
        "ORDER BY depth, pid;"
    ),
    "package_inventory": (
        "SELECT name, version, source, "
        "COALESCE(arch, '') AS arch "
        "FROM deb_packages "
        "UNION ALL "
        "SELECT name, version, source, arch "
        "FROM rpm_packages "
        "UNION ALL "
        "SELECT name, version, 'homebrew' AS source, '' AS arch "
        "FROM homebrew_packages "
        "LIMIT {limit};"
    ),
}

# Default values for optional parameters.
_DEFAULTS: dict[str, dict[str, Any]] = {
    "running_processes": {"limit": 200},
    "active_connections": {"limit": 200},
    "logged_in_users": {"limit": 100},
    "recent_files": {"directory": "/tmp", "limit": 100},
    "process_tree": {"pid": 1, "max_depth": 5},
    "package_inventory": {"limit": 500},
}

#: A row cap, not a free integer: osquery returns these rows over the wire to
#: every targeted host's result set.
_LIMIT = _Integer(minimum=1, maximum=10_000)

# Explicit spec of which parameters each template accepts, and what each one is.
PARAM_SPECS: dict[str, dict[str, _ParamType]] = {
    "running_processes": {"limit": _LIMIT},
    "active_connections": {"limit": _LIMIT},
    "logged_in_users": {"limit": _LIMIT},
    "recent_files": {"directory": _AbsolutePath(), "limit": _LIMIT},
    "process_tree": {
        # PID 0 is the kernel scheduler on Linux and a valid row; the ceiling
        # is the widest value a pid_t can hold.
        "pid": _Integer(minimum=0, maximum=2**31 - 1),
        "max_depth": _Integer(minimum=1, maximum=64),
    },
    "package_inventory": {"limit": _LIMIT},
}

# Compile a regex that matches parameterised placeholders in the templates.
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")

#: Tokens whose count must survive interpolation unchanged.  A value that adds
#: a quote has escaped its string literal; a value that adds a semicolon has
#: appended a statement.  Comment introducers are deliberately absent: inside a
#: literal they are inert, and `/opt/my--tool` is a legitimate path.
_STRUCTURAL_TOKENS: tuple[tuple[str, str], ...] = (
    ("'", "string delimiter"),
    (";", "statement terminator"),
)


def _assert_string_params_are_quoted() -> None:
    """Every string parameter must sit inside a SQL string literal.

    :class:`_AbsolutePath` permits characters that are inert inside a quoted
    literal and would not be outside one — `--` and `/*` among them, because
    `/opt/my--tool` is a real path and refusing it would cost a forensic
    answer for a token that cannot do anything from where it sits. That
    reasoning only holds while the template actually quotes the placeholder,
    so the shape is asserted here at import rather than left as a property
    the next person to add a template has to remember.
    """
    for template_id, specs in PARAM_SPECS.items():
        template = TEMPLATES[template_id]
        for name, spec in specs.items():
            if isinstance(spec, _AbsolutePath) and f"'{{{name}}}'" not in template:
                raise AllowlistError(
                    f"Template '{template_id}' interpolates string parameter "
                    f"'{name}' outside a quoted literal. Either quote it as "
                    f"'{{{name}}}' or give it a parameter type that is safe unquoted."
                )


_assert_string_params_are_quoted()


def list_templates() -> list[str]:
    """Return the sorted list of available template IDs."""
    return sorted(TEMPLATES)


def _assert_structure_intact(template_id: str, template: str, rendered: str) -> None:
    """Fail closed if interpolation changed the statement's structure.

    The parameter types are the control; this is the assertion that they held.
    It compares the rendered SQL against the template it came from — the
    direction that drifts — so it stays true for a parameter type added later
    that forgets what its predecessors had to exclude.
    """
    for token, label in _STRUCTURAL_TOKENS:
        if rendered.count(token) != template.count(token):
            raise AllowlistError(
                f"Rendering template '{template_id}' changed the number of "
                f"{label} characters, so a parameter value escaped its "
                f"position. Refusing to emit the query."
            )


def render_query(template_id: str, **params: Any) -> str:
    """Render *template_id* with the supplied keyword parameters.

    Parameters
    ----------
    template_id:
        Must be one of the keys in :data:`TEMPLATES`.
    **params:
        Parameter values to substitute.  Unknown keys raise
        :class:`AllowlistError`; missing keys are filled from
        :data:`_DEFAULTS`.  Every supplied value must match the type its
        parameter declares in :data:`PARAM_SPECS`.

    Returns
    -------
    str
        The fully-rendered, ready-to-execute SQL string.

    Raises
    ------
    AllowlistError
        If *template_id* is not in the allowlist, if an unknown parameter
        is supplied, if a required parameter has no default, or if a value
        is not what its parameter is declared to be.
    """
    if template_id not in TEMPLATES:
        raise AllowlistError(f"Unknown template '{template_id}'. Available: {', '.join(list_templates())}")

    specs = PARAM_SPECS[template_id]
    allowed_keys = set(specs)
    unknown = set(params) - allowed_keys
    if unknown:
        raise AllowlistError(
            f"Template '{template_id}' does not accept "
            f"parameter(s): {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(allowed_keys))}"
        )

    # Merge caller-supplied params over defaults.
    merged: dict[str, Any] = {**_DEFAULTS.get(template_id, {}), **params}

    # Verify that all placeholders have values after merging.
    template = TEMPLATES[template_id]
    required = {m.group(1) for m in _PLACEHOLDER_RE.finditer(template)}
    missing = required - set(merged)
    if missing:
        raise AllowlistError(f"Template '{template_id}' requires parameter(s) with no default: {', '.join(sorted(missing))}")

    # A placeholder the spec does not describe would otherwise reach
    # format_map() unvalidated, which is the original defect in miniature.
    undeclared = required - allowed_keys
    if undeclared:
        raise AllowlistError(f"Template '{template_id}' has placeholder(s) with no PARAM_SPECS entry: {', '.join(sorted(undeclared))}.")

    # Coerce each value to the type its parameter declares. A value that is
    # not that type is refused, never repaired.
    typed = {key: specs[key].coerce(key, value) for key, value in merged.items()}

    rendered = template.format_map(typed)
    _assert_structure_intact(template_id, template, rendered)
    return rendered


def validate_raw_sql(sql: str) -> None:
    """Raise :class:`AllowlistError` if *sql* is not a known rendered template.

    This is intentionally strict: only SQL that was produced by
    :func:`render_query` (and therefore matches one of the templates exactly)
    is accepted.  Any other SQL — including manually constructed queries —
    is rejected.

    Callers that need to verify whether a given SQL string came from the
    allowlist can use this to gate execution.
    """
    normalised = " ".join(sql.split())
    for tmpl_id in TEMPLATES:
        try:
            rendered = render_query(tmpl_id, **_DEFAULTS.get(tmpl_id, {}))
        except AllowlistError:
            continue
        if normalised == " ".join(rendered.split()):
            return
    raise AllowlistError("SQL does not match any approved template. Use render_query() with an approved template ID.")
