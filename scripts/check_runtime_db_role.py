#!/usr/bin/env python3
"""Fail if the role a service connects as can reach around row-level security.

Why this exists
---------------
``060_rls_coverage.sql`` took RLS from 31 of 95 tenant-scoped tables to 92, and
established by measurement that not one of those policies filtered anything:
every deployment surface ran the services as the role the postgres image
creates from ``POSTGRES_USER``, which is a **superuser**, and a superuser
ignores policies even under ``FORCE ROW LEVEL SECURITY``. Sixty-one new
policies bought nothing operationally.

``061_runtime_app_role.sql`` and the surfaces around it fix that. This gate is
what stops it coming back — because the way it comes back is not somebody
deleting a policy, it is somebody adding a service to ``docker-compose.yml`` by
copying the block above it.

Three ways a role gets around a policy, all checked
---------------------------------------------------
``SUPERUSER``      ignores RLS outright.
``BYPASSRLS``      ignores RLS outright.
**ownership**      ``FORCE`` binds the owner, but an owner can simply issue
                   ``ALTER TABLE … NO FORCE ROW LEVEL SECURITY``. A role that
                   can turn the control off is not subject to it.

Structural, not a list of names
-------------------------------
The gate never asks "is this role called ``aisoc``". It asks which role *this
surface provisions as the database superuser* — ``POSTGRES_USER`` for the
postgres image, ``username`` for the RDS / Cloud SQL / chart credential — and
then checks whether any runtime DSN in the same surface connects as that role.
Rename every role tomorrow and the gate still works; add a fourteenth service
with a copied DSN and it fails.

Both directions
---------------
The dominant failure shape in this repository is the one-directional gate: it
compares A against B, never B against A, and prints OK while drift accumulates
in the direction things actually change. So:

* forward — a **runtime** DSN connecting as the provisioned superuser fails.
  That is the bypass.
* reverse — a **migration** DSN connecting as anything else fails. The runtime
  role holds no DDL, so this is a deploy that will die on the first
  ``CREATE TABLE``; it is worth catching in review rather than at 2am.
* reverse — a surface that provisions a database but from which no DSN could
  be parsed fails as a **blind spot**, not as a pass. This is the check that
  would have caught this gate being wrong about its own inputs: the failure
  mode of a scanner is silence, and silence here is indistinguishable from
  compliance.

Every one of those is printed with the file, the variable and the role, so the
output says what was inspected rather than only what was wrong.

A self-test runs first, every time
-----------------------------------
:func:`self_test` pushes hand-built surfaces through the same classifier the
real scan uses — a compose file with the bypass, one with the split, one with
the roles the wrong way round, one that mentions a DSN the parser cannot read
— and asserts each verdict. It is not behind a flag, because a gate whose
parser silently stopped matching reports OK, and OK is what a broken gate and a
clean tree look like from outside.

Empty input is a failure
------------------------
A probe recently ran every wired gate against an empty repository and five
reported OK, including the validator behind a number the front page quotes. A
scan that finds no deployment surface has not verified anything, so it exits
non-zero and says so.

Live mode
---------
``--dsn`` asks the database instead of the tree: connect, read ``pg_roles`` and
``pg_class``, and report the three bypasses directly. That is the only way to
catch a role whose attributes were changed outside this repository, and it also
tries the credential ``002_rls.sql`` shipped (``changeme``) so a deployment
still on it is told. Runs in ``integration.yml`` where a database exists.

Usage
-----
    python scripts/check_runtime_db_role.py                      # static scan
    python scripts/check_runtime_db_role.py --dsn "$DATABASE_URL" \\
        --owner-dsn "$DATABASE_MIGRATION_URL"                    # + live
    python scripts/check_runtime_db_role.py --self-test-only
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

# ---------------------------------------------------------------------------
# What counts as a deployment surface
# ---------------------------------------------------------------------------

#: Globs relative to the repository root. Every surface that either provisions
#: a Postgres credential or hands one to a service. Docs are excluded on
#: purpose: prose is checked by review, and a code fence in a tutorial is not a
#: deployment.
SURFACE_GLOBS: tuple[str, ...] = (
    "docker-compose.yml",
    "docker-compose.*.yml",
    "infra/compose/*.yml",
    "infra/helm/**/values.yaml",
    "infra/helm/**/templates/*.yaml",
    "infra/terraform/**/*.tf",
    "infra/terraform/**/*.tfvars",
    "infra/fly/**/*.toml",
    ".github/workflows/*.yml",
    ".env.example",
    "render.yaml",
)

#: Environment variable names whose value is a DSN the *migration/DDL* path
#: uses. These are the ones that are *supposed* to be the owner.
MIGRATION_VARS = frozenset({"DATABASE_MIGRATION_URL", "AISOC_DATABASE_MIGRATION_URL"})

#: Some DSNs must be the owner and cannot say so in their variable name, because
#: the tool reading them chose the name: alembic and the SQL runner both read
#: ``DATABASE_URL``, and ``scripts/backup.sh`` needs a credential that can dump
#: and restore every table it does not own.
#:
#: Rather than keep a list of those in this file — which would drift the moment
#: a workflow moved — the surface declares it inline, on or immediately above
#: the line, with a reason:
#:
#:     # aisoc-db-role: owner — alembic applies DDL; the runtime role has none
#:     DATABASE_URL: postgresql+asyncpg://aisoc:...@localhost:5432/ueba_ci
#:
#: The reason is required and is printed in the scan output, so the exemption
#: is visible at the point of use rather than in a table somebody has to go
#: and find. A marker with no DSN under it fails as stale — same shrink-only
#: discipline as the predicate gate's ratchet, minus the second file.
_OWNER_MARKER_RE = re.compile(r"aisoc-db-role:\s*owner\b[ \t]*[—:-]?[ \t]*(?P<reason>.*)", re.I)

#: Variables that name a database superuser being provisioned. The postgres
#: image creates ``POSTGRES_USER`` as a superuser; the managed-database modules
#: create their master user as the owner of everything the chain builds.
SUPERUSER_DECL_KEYS = ("POSTGRES_USER", "DB_USERNAME", "DB_USER", "MASTER_USERNAME")

#: A Postgres URL in any of the spellings this tree uses. The role is group 2;
#: it is optional so a DSN with no credentials still parses (and is ignored
#: rather than silently treated as compliant).
_DSN_RE = re.compile(
    r"(?P<scheme>postgres(?:ql)?(?:\+\w+)?)://(?:(?P<role>[^:/@\s\"']+)(?::(?P<password>[^@\s\"']*))?@)?"
    r"(?P<host>[^/\s\"']+)",
)

#: `KEY: value` / `KEY=value` / `KEY = "value"`, which covers YAML, dotenv,
#: HCL and TOML closely enough for the keys above. Deliberately loose: a key
#: this misses shows up as a blind spot rather than as a pass.
_ASSIGN_RE = re.compile(r"^\s*(?:-\s*name:\s*)?[\"']?(?P<key>[A-Za-z_][\w.\-]*)[\"']?\s*[:=]\s*(?P<value>.+?)\s*$")

#: Anything that looks like a Postgres URL scheme. Used only to decide whether
#: a surface the parser found nothing in *should* have yielded something.
_SCHEME_HINT_RE = re.compile(r"postgres(?:ql)?(?:\+\w+)?://")

#: Placeholder DSNs used by unit-test jobs that never open a socket
#: (``postgresql+asyncpg://x:x@localhost/x``). Recognised by shape — a role
#: equal to its own password and a host with no real name — not by a list.
_PLACEHOLDER_HOSTS = frozenset({"localhost/x", "localhost", "127.0.0.1"})


@dataclass
class Dsn:
    var: str
    role: str
    password: str | None
    host: str
    #: Set when the surface declared this DSN as deliberately the owner's,
    #: with the stated reason. ``None`` means it is a runtime DSN.
    owner_reason: str | None = None


@dataclass
class Finding:
    surface: str
    detail: str


@dataclass
class Inspected:
    """Everything the scan looked at, so the output can name it."""

    surfaces: list[str] = field(default_factory=list)
    superusers: dict[str, set[str]] = field(default_factory=dict)
    runtime_dsns: list[tuple[str, str, str]] = field(default_factory=list)  # surface, var, role
    migration_dsns: list[tuple[str, str, str]] = field(default_factory=list)
    ignored_dsns: list[tuple[str, str, str]] = field(default_factory=list)
    #: DSNs the surface declared as the owner's on purpose, with the reason.
    exempted: list[tuple[str, str, str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _strip_quotes(value: str) -> str:
    value = value.split("#", 1)[0].strip() if not value.startswith(("'", '"')) else value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _expand_default(value: str) -> str:
    """``${VAR:-fallback}`` → ``fallback``.

    Deployment surfaces parameterise both the role and the password. The role
    is what this gate reasons about, so an unresolved ``${...}`` would make
    every DSN unclassifiable — which is the same as not checking.
    """
    return re.sub(r"\$\{[A-Za-z_][\w]*:-([^}]*)\}", r"\1", value)


def _canonical_role(role: str) -> str:
    """``${var.db_username}`` and ``var.db_username`` are the same role.

    Found by enumerating what the gate *credited* rather than what it flagged:
    ``infra/terraform/main.tf`` declares ``db_username = var.db_username`` and
    interpolates ``${var.db_username}`` into every service DSN, and the naive
    string compare read those as two different roles — so the one surface that
    hands the RDS master user to thirteen services was being recorded as
    compliant. A gate's blind spots do not announce themselves in its failures.
    """
    role = role.strip()
    if role.startswith("${") and role.endswith("}"):
        role = role[2:-1]
    return role.strip()


def _is_placeholder(role: str | None, password: str | None, host: str) -> bool:
    """A DSN that exists to satisfy a settings import, not to reach a database."""
    if role is None:
        return True
    return bool(role == password and host.rstrip("/").split("/")[0] in _PLACEHOLDER_HOSTS)


def parse_surface(text: str, name: str) -> tuple[set[str], list[Dsn], bool, list[int]]:
    """Pull the provisioned superusers and every DSN out of one file.

    Returns ``(superuser_roles, dsns, saw_scheme, unused_marker_lines)``.
    ``saw_scheme`` records whether the text contains a Postgres URL at all,
    which is how the caller tells "no database here" apart from "the parser
    could not read this one".
    """
    superusers: set[str] = set()
    dsns: list[Dsn] = []
    marker_lines: dict[int, str] = {}
    consumed_markers: set[int] = set()

    pending_name: str | None = None
    for lineno, raw in enumerate(text.splitlines()):
        line = _expand_default(raw)
        match = _ASSIGN_RE.match(line)

        marker = _OWNER_MARKER_RE.search(raw)
        if marker:
            marker_lines[lineno] = marker.group("reason").strip()

        # Kubernetes-style `- name: FOO` / `  value: bar` pairs.
        stripped = line.strip()
        if stripped.startswith("- name:"):
            pending_name = _strip_quotes(stripped.split(":", 1)[1])
        key = None
        value = ""
        if match:
            key = match.group("key")
            value = _strip_quotes(match.group("value"))
            if key == "value" and pending_name:
                key = pending_name
                pending_name = None

        if key and any(key.upper().endswith(decl) for decl in SUPERUSER_DECL_KEYS):
            role = _canonical_role(value)
            if role:
                superusers.add(role)

        for dsn in _DSN_RE.finditer(line):
            owner_reason: str | None = None
            for candidate in (lineno, lineno - 1, lineno - 2):
                if candidate in marker_lines:
                    owner_reason = marker_lines[candidate]
                    consumed_markers.add(candidate)
                    break
            dsns.append(
                Dsn(
                    var=key or "<inline>",
                    role=dsn.group("role") or "",
                    password=dsn.group("password"),
                    host=dsn.group("host"),
                    owner_reason=owner_reason,
                )
            )

    stale = sorted(set(marker_lines) - consumed_markers)
    return superusers, dsns, bool(_SCHEME_HINT_RE.search(text)), stale


def classify(surface: str, text: str, inspected: Inspected, known_superusers: set[str] | None = None) -> list[Finding]:
    """Both directions, over one surface. Records what it credited as it goes.

    ``known_superusers`` carries the roles every *other* surface provisions.
    Database roles are properties of the deployment, not of the file that
    mentions them, and scoping the comparison per-file left a hole exactly
    where it mattered: ``.env.example`` hands out a DSN and declares no
    ``POSTGRES_USER``, so it landed in "nothing to compare against" and was
    never checked. Found by reading what the gate credited, not what it
    flagged.
    """
    findings: list[Finding] = []
    declared, dsns, saw_scheme, stale_markers = parse_surface(text, surface)
    superusers = declared | (known_superusers or set())
    inspected.surfaces.append(surface)
    if declared:
        inspected.superusers[surface] = declared

    usable = [d for d in dsns if not _is_placeholder(d.role or None, d.password, d.host)]

    # Reverse direction #2: the parser's own blind spot. A surface that plainly
    # contains a Postgres URL but yielded nothing readable has not been
    # checked, and reporting OK for it is the failure this clause exists to
    # prevent.
    if saw_scheme and not dsns:
        findings.append(
            Finding(surface, "contains a Postgres URL but no DSN could be parsed out of it — the gate cannot vouch for this file")
        )
        return findings

    # Reverse direction #3: an exemption that no longer excuses anything. A
    # marker left behind after its DSN moved reads as a considered decision
    # and is not one.
    for lineno in stale_markers:
        findings.append(
            Finding(surface, f"line {lineno + 1} carries an `aisoc-db-role: owner` marker with no DSN under it — remove it")
        )

    for dsn in usable:
        var, role = dsn.var, _canonical_role(dsn.role)
        is_migration = var.upper() in MIGRATION_VARS or dsn.owner_reason is not None
        bucket = inspected.migration_dsns if is_migration else inspected.runtime_dsns
        bucket.append((surface, var, role))
        if dsn.owner_reason is not None:
            inspected.exempted.append((surface, var, role, dsn.owner_reason))
            if not dsn.owner_reason:
                findings.append(
                    Finding(surface, f"{var} is marked `aisoc-db-role: owner` with no reason given; state why it needs DDL")
                )

        if not superusers:
            # Nothing in this surface says which role is privileged, so there
            # is nothing to compare against. Recorded, not credited.
            inspected.ignored_dsns.append((surface, var, role))
            continue

        if is_migration and role not in superusers:
            findings.append(
                Finding(
                    surface,
                    f"{var} connects as {role!r}, which this surface does not provision as the "
                    f"database superuser ({', '.join(sorted(superusers))}). Migrations need DDL; "
                    "the runtime role deliberately has none, so this deploy dies on the first CREATE TABLE.",
                )
            )
        elif not is_migration and role in superusers:
            findings.append(
                Finding(
                    surface,
                    f"{var} connects as {role!r}, which this surface provisions as the database "
                    "superuser. A superuser ignores every RLS policy in the schema, even under "
                    "FORCE ROW LEVEL SECURITY. Point it at the runtime role and put the owner in "
                    "DATABASE_MIGRATION_URL.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Self-test — runs before the scan, not behind a flag
# ---------------------------------------------------------------------------

_FIXTURES: tuple[tuple[str, str, bool], ...] = (
    (
        "bypass: a service connecting as the provisioned superuser",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              DATABASE_URL: postgresql+asyncpg://owner_role:pw@postgres:5432/aisoc
        """,
        False,
    ),
    (
        "split: runtime role for the service, owner for migrations",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              DATABASE_URL: postgresql+asyncpg://runtime_role:pw@postgres:5432/aisoc
              DATABASE_MIGRATION_URL: postgresql+asyncpg://owner_role:pw@postgres:5432/aisoc
        """,
        True,
    ),
    (
        "reverse: migrations pointed at the runtime role, which holds no DDL",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              DATABASE_URL: postgresql+asyncpg://runtime_role:pw@postgres:5432/aisoc
              DATABASE_MIGRATION_URL: postgresql+asyncpg://runtime_role:pw@postgres:5432/aisoc
        """,
        False,
    ),
    (
        "blind spot: a Postgres URL the DSN pattern cannot read",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              DATABASE_URL: postgresql:// {{ tpl .Values.dsn }}
        """,
        False,
    ),
    (
        "renaming the roles changes nothing — the rule is structural",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: postgres
          api:
            environment:
              DATABASE_URL: postgresql+asyncpg://postgres:pw@postgres:5432/app
        """,
        False,
    ),
    (
        "${VAR:-default} is resolved, so a parameterised bypass is still caught",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              DATABASE_URL: postgresql+asyncpg://owner_role:${PW:-x}@postgres:5432/aisoc
        """,
        False,
    ),
    (
        "a unit-test placeholder DSN is not a deployment and must not fail",
        """
        env:
          POSTGRES_USER: owner_role
          DATABASE_URL: postgresql+asyncpg://x:x@localhost/x
        """,
        True,
    ),
    (
        "an interpolated role matches its own declaration",
        """
        db_username = var.db_username
        database_url = "postgresql+asyncpg://${var.db_username}:pw@rds/aisoc"
        """,
        False,
    ),
    (
        "an owner marker with a reason excuses the DSN under it",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
        env:
          # aisoc-db-role: owner — alembic applies DDL
          DATABASE_URL: postgresql+asyncpg://owner_role:pw@localhost:5432/ueba_ci
        """,
        True,
    ),
    (
        "an owner marker with no reason is not an exemption",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
        env:
          # aisoc-db-role: owner
          DATABASE_URL: postgresql+asyncpg://owner_role:pw@localhost:5432/ueba_ci
        """,
        False,
    ),
    (
        "an owner marker left behind after its DSN moved fails as stale",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
          api:
            environment:
              # aisoc-db-role: owner — this DSN is long gone
              SOME_OTHER_SETTING: 3
              DATABASE_URL: postgresql+asyncpg://runtime_role:pw@postgres:5432/aisoc
        """,
        False,
    ),
    (
        "an owner marker cannot excuse a DSN that is not the owner's",
        """
        services:
          postgres:
            environment:
              POSTGRES_USER: owner_role
        env:
          # aisoc-db-role: owner — claims DDL but names the wrong role
          DATABASE_URL: postgresql+asyncpg://runtime_role:pw@localhost:5432/aisoc
        """,
        False,
    ),
    (
        "a surface with no database at all is simply not a finding",
        """
        services:
          web:
            environment:
              NEXT_PUBLIC_API_URL: http://api:8000
        """,
        True,
    ),
)


def self_test() -> list[str]:
    """Push known-good and known-bad surfaces through :func:`classify`.

    Returns a list of failure descriptions; empty means the classifier still
    distinguishes the cases it is supposed to.
    """
    failures: list[str] = []
    for label, text, should_pass in _FIXTURES:
        findings = classify(f"<self-test: {label}>", text, Inspected())
        passed = not findings
        if passed is not should_pass:
            verdict = "accepted" if passed else f"rejected ({findings[0].detail})"
            expected = "accept" if should_pass else "reject"
            failures.append(f"{label}: classifier {verdict}, expected it to {expected}")

    # The empty-input rule, asserted rather than assumed: a run that inspected
    # nothing must not be able to report OK.
    if not _empty_input_findings(Inspected()):
        failures.append("an Inspected with no surfaces produced no finding — the gate would pass over an empty tree")
    populated = Inspected(surfaces=["x"], runtime_dsns=[("x", "DATABASE_URL", "r")])
    if _empty_input_findings(populated):
        failures.append("a populated scan was reported as empty — the empty-input rule is over-tight")
    return failures


def _empty_input_findings(inspected: Inspected) -> list[Finding]:
    """Nothing scanned is a failure, not a pass."""
    out: list[Finding] = []
    if not inspected.surfaces:
        out.append(
            Finding(
                "<root>",
                f"no deployment surface matched any of the {len(SURFACE_GLOBS)} configured globs — "
                "nothing was verified. An absent, empty or wrongly-rooted tree fails here rather "
                "than reporting OK.",
            )
        )
    elif not (inspected.runtime_dsns or inspected.migration_dsns):
        out.append(
            Finding(
                "<root>",
                f"{len(inspected.surfaces)} surfaces were read and not one yielded a database DSN. "
                "Either the tree stopped configuring a database or the parser stopped matching; "
                "both need a human.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------

_WELL_KNOWN_PASSWORD = "changeme"  # noqa: S105 — the literal 002_rls.sql shipped; tested against, never used


def _bare_dsn(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


def _redact(dsn: str) -> str:
    return re.sub(r"//([^:/@]*)(:[^@]*)?@", r"//\1:***@", dsn)


async def _live_findings(dsn: str, owner_dsn: str | None) -> list[Finding]:
    try:
        import asyncpg  # noqa: PLC0415 — optional; live mode only
    except ImportError:
        return [Finding("<live>", "asyncpg is not installed, so --dsn could not be checked")]

    findings: list[Finding] = []
    conn = await asyncpg.connect(_bare_dsn(dsn), timeout=15)
    try:
        row = await conn.fetchrow("SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        owned = await conn.fetch(
            """
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r','v','m','p')
               AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             ORDER BY 1 LIMIT 5
            """
        )
        # A view without security_invoker executes its reads as the view's
        # owner, so it walks past every policy underneath it regardless of who
        # is querying. Checked here because it is exactly the shape this whole
        # change is about, one level of indirection further out.
        leaky_views = await conn.fetch(
            """
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind = 'v'
               AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user)
               AND coalesce((SELECT option_value FROM pg_options_to_table(c.reloptions)
                              WHERE option_name = 'security_invoker'), 'false') <> 'true'
             ORDER BY 1
            """
        )
    finally:
        await conn.close()

    role = row["role"]
    print(f"  live: connected as {role!r} (rolsuper={row['rolsuper']}, rolbypassrls={row['rolbypassrls']})")
    if row["rolsuper"]:
        findings.append(Finding("<live>", f"{role!r} is a SUPERUSER and ignores every RLS policy in this database"))
    if row["rolbypassrls"]:
        findings.append(Finding("<live>", f"{role!r} holds BYPASSRLS and ignores every RLS policy in this database"))
    if owned:
        names = ", ".join(r["relname"] for r in owned)
        findings.append(
            Finding("<live>", f"{role!r} owns objects in public ({names}…) and can ALTER TABLE … NO FORCE ROW LEVEL SECURITY")
        )
    if leaky_views:
        names = ", ".join(r["relname"] for r in leaky_views)
        findings.append(
            Finding("<live>", f"views without security_invoker execute as their owner and read past the policies: {names}")
        )

    # The credential 002_rls.sql shipped. Not detectable from a password hash,
    # but perfectly detectable by trying it.
    if not row["rolsuper"]:
        try:
            probe = await asyncpg.connect(
                re.sub(r"//([^:/@]+)(:[^@]*)?@", rf"//\1:{_WELL_KNOWN_PASSWORD}@", _bare_dsn(dsn), count=1),
                timeout=10,
            )
        except Exception:  # noqa: BLE001 — a refused login is the good outcome
            pass
        else:
            await probe.close()
            findings.append(
                Finding("<live>", f"{role!r} still accepts the password 002_rls.sql shipped; set AISOC_APP_DB_PASSWORD")
            )

    if owner_dsn:
        owner = await asyncpg.connect(_bare_dsn(owner_dsn), timeout=15)
        try:
            orow = await owner.fetchrow("SELECT current_user AS role, rolsuper FROM pg_roles WHERE rolname = current_user")
            can_ddl = await owner.fetchval("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
        finally:
            await owner.close()
        print(f"  live: migration role {orow['role']!r} (rolsuper={orow['rolsuper']}, CREATE on public={can_ddl})")
        # Reverse direction: the owner must still be able to do what it is for.
        if not can_ddl:
            findings.append(
                Finding("<live>", f"the migration role {orow['role']!r} cannot CREATE in schema public, so the chain cannot apply")
            )
        if orow["role"] == role:
            findings.append(
                Finding("<live>", "DATABASE_URL and DATABASE_MIGRATION_URL are the same role, so the split is nominal only")
            )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def collect(root: Path) -> list[Path]:
    seen: dict[Path, None] = {}
    for pattern in SURFACE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                seen.setdefault(path, None)
    return list(seen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=None, help="tree to scan (default: git toplevel)")
    parser.add_argument("--dsn", default=None, help="also inspect a live database as the runtime role")
    parser.add_argument("--owner-dsn", default=None, help="the migration role, checked in the reverse direction")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the classifier still discriminates and that the gate refuses an empty tree, then stop",
    )
    args = parser.parse_args(argv)

    # Always first, whether or not --self-test was asked for: a classifier
    # that stopped distinguishing its cases would otherwise report a clean
    # tree, and that is indistinguishable from a working gate.
    st_failures = self_test()
    if args.self_test:
        # The shared body adds the one property this file cannot check about
        # itself — that running the gate inside a repository holding no
        # content exits non-zero rather than printing OK.
        return self_test_main(
            Path(__file__).name,
            args=[],
            extra=[(f"{len(_FIXTURES)} classifier fixtures + 2 empty-input cases", not st_failures)]
            + [(f"self-test detail: {f}", False) for f in st_failures],
        )
    if st_failures:
        print("check_runtime_db_role: SELF-TEST FAILED — the gate cannot be trusted this run")
        for failure in st_failures:
            print(f"  [FAIL] {failure}")
        return 1
    print(f"check_runtime_db_role: self-test OK ({len(_FIXTURES)} classifier fixtures + 2 empty-input cases)")

    root = (args.root or repo_root()).resolve()
    surfaces = [(str(p.relative_to(root)), p.read_text(encoding="utf-8", errors="ignore")) for p in collect(root)]

    # Pass one: which roles does this deployment provision as privileged? A
    # role is a property of the database, so a surface that hands out a DSN
    # without declaring one is still checked against what the rest declared.
    known: set[str] = set()
    for _rel, text in surfaces:
        known |= parse_surface(text, _rel)[0]

    inspected = Inspected()
    findings: list[Finding] = []
    for rel, text in surfaces:
        findings.extend(classify(rel, text, inspected, known))

    findings.extend(_empty_input_findings(inspected))

    print(f"check_runtime_db_role: scanned {len(inspected.surfaces)} deployment surfaces under {root}")
    print(f"  roles this deployment provisions as privileged: {sorted(known) or '<none found>'}")
    print(
        f"  {len(inspected.runtime_dsns)} runtime DSN(s), {len(inspected.migration_dsns)} migration DSN(s), "
        f"{len(inspected.superusers)} surface(s) declaring a provisioned superuser"
    )
    for surface, roles in sorted(inspected.superusers.items()):
        credited = [f"{var}={role}" for s, var, role in inspected.runtime_dsns if s == surface]
        print(f"    {surface}: superuser={sorted(roles)} runtime={credited or ['<none>']}")
    if inspected.exempted:
        print(f"  {len(inspected.exempted)} DSN(s) declared `aisoc-db-role: owner` on purpose:")
        for surface, var, role, reason in inspected.exempted:
            print(f"    {surface}: {var} as {role!r} — {reason}")
    if inspected.ignored_dsns:
        print(f"  {len(inspected.ignored_dsns)} DSN(s) in surfaces that declare no superuser, so nothing to compare against:")
        for surface, var, role in inspected.ignored_dsns:
            print(f"    {surface}: {var} as {role!r}")

    if args.dsn:
        findings.extend(asyncio.run(_live_findings(args.dsn, args.owner_dsn)))
        print(f"  live target: {_redact(args.dsn)}")

    if findings:
        print(f"\nFAIL: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  [FAIL] {finding.surface}: {finding.detail}")
        return 1

    print("OK: no service connects as a role that can reach around row-level security.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
