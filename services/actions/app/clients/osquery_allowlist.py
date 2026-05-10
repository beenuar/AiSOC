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
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

# Each value is a SQL template string.  Python's str.format_map() is used for
# parameter substitution; callers supply keyword arguments which are validated
# against the parameter spec before interpolation.
#
# Rules for adding templates:
#   1. SQL must use parameterised placeholders in the form {param_name}.
#   2. The companion PARAM_SPECS entry must list every placeholder name.
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

# Explicit spec of which parameters each template accepts.
PARAM_SPECS: dict[str, set[str]] = {
    "running_processes": {"limit"},
    "active_connections": {"limit"},
    "logged_in_users": {"limit"},
    "recent_files": {"directory", "limit"},
    "process_tree": {"pid", "max_depth"},
    "package_inventory": {"limit"},
}

# Compile a regex that matches parameterised placeholders in the templates.
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


class AllowlistError(ValueError):
    """Raised when a query or parameter fails allowlist validation."""


def list_templates() -> list[str]:
    """Return the sorted list of available template IDs."""
    return sorted(TEMPLATES)


def render_query(template_id: str, **params: Any) -> str:
    """Render *template_id* with the supplied keyword parameters.

    Parameters
    ----------
    template_id:
        Must be one of the keys in :data:`TEMPLATES`.
    **params:
        Parameter values to substitute.  Unknown keys raise
        :class:`AllowlistError`; missing keys are filled from
        :data:`_DEFAULTS`.

    Returns
    -------
    str
        The fully-rendered, ready-to-execute SQL string.

    Raises
    ------
    AllowlistError
        If *template_id* is not in the allowlist, if an unknown parameter
        is supplied, or if a required parameter has no default.
    """
    if template_id not in TEMPLATES:
        raise AllowlistError(f"Unknown template '{template_id}'. Available: {', '.join(list_templates())}")

    allowed_keys = PARAM_SPECS[template_id]
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
    required = {m.group(1) for m in _PLACEHOLDER_RE.finditer(TEMPLATES[template_id])}
    missing = required - set(merged)
    if missing:
        raise AllowlistError(f"Template '{template_id}' requires parameter(s) with no default: {', '.join(sorted(missing))}")

    # Basic sanitisation: reject values that contain SQL comment sequences or
    # statement terminators other than the trailing semicolon already in the
    # template.  This is defence-in-depth; the primary protection is the
    # allowlist itself.
    for key, value in merged.items():
        val_str = str(value)
        if "--" in val_str or "/*" in val_str or ";" in val_str:
            raise AllowlistError(f"Parameter '{key}' contains disallowed characters.")

    return TEMPLATES[template_id].format_map(merged)


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
