"""The seeded RBAC catalog: roles, their permissions, and the seed path.

Why a module and not just a migration
--------------------------------------
``092_rbac_catalog_seed.sql`` seeds the primary tenant. A second tenant that
adopts database-backed RBAC needs the same catalog, and it needs it with the
same guarantees: catalog rows and membership backfill in ONE transaction,
because a tenant that has roles but no memberships resolves every user to
zero permissions. Two copies of that vocabulary — one in the migration, one
in the endpoint that seeds other tenants — drift. So the vocabulary lives
here, the migration embeds the same lists, and the two are pinned equal by
``services/api/tests/test_rbac_catalog_seed.py``.

Deny-by-default lives in ``permission_cache.resolve_permissions``: once a
tenant has any role row, only ``role_permissions``/``user_roles`` answer.
This module is the *data* side of that decision; the enforcement side is
unchanged.
"""

from __future__ import annotations

import logging
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

#: The permission vocabulary (name, description, category). `*` is a real
#: row: it is what the admin role's grant literally contains, so the Roles
#: screen can show what it confers instead of a footnote.
PERMISSIONS: Final[tuple[tuple[str, str, str], ...]] = (
    ("alerts:read", "View alerts", "alerts"),
    ("alerts:write", "Acknowledge / triage / update alerts", "alerts"),
    ("alerts:delete", "Delete alerts", "alerts"),
    ("cases:read", "View cases", "cases"),
    ("cases:write", "Create and edit cases", "cases"),
    ("cases:delete", "Delete cases", "cases"),
    ("cases:assign", "Assign cases to people", "cases"),
    ("cases:note", "Add notes to cases", "cases"),
    ("detections:read", "View detections", "detections"),
    ("detections:write", "Manage detections", "detections"),
    ("detections:delete", "Delete detections", "detections"),
    ("rules:read", "View detection rules", "rules"),
    ("rules:write", "Create and edit detection rules", "rules"),
    ("dashboards:read", "View dashboards", "dashboards"),
    ("reports:read", "View reports", "reports"),
    ("reports:write", "Generate and edit reports", "reports"),
    ("reports:export", "Export reports", "reports"),
    ("compliance:read", "View compliance posture", "compliance"),
    ("playbooks:read", "View playbooks", "playbooks"),
    ("playbooks:write", "Edit playbooks", "playbooks"),
    ("playbooks:execute", "Run playbooks", "playbooks"),
    ("actions:read", "View the response-action registry", "actions"),
    ("actions:execute", "Execute response actions", "actions"),
    ("investigation:run", "Run an investigation", "investigations"),
    ("threat_intel:read", "View threat intelligence", "threat_intel"),
    ("threat_intel:write", "Manage threat intelligence", "threat_intel"),
    ("threatintel:manage", "Manage threat intelligence (alias)", "threat_intel"),
    ("connectors:read", "View connectors", "connectors"),
    ("connectors:write", "Configure connectors", "connectors"),
    ("connectors:delete", "Delete connectors", "connectors"),
    ("lake:query", "Query the data lake", "lake"),
    ("lake:read_schema", "Read the lake schema", "lake"),
    ("hunts:read", "View hunts", "hunts"),
    ("knowledge_base:read", "Search the knowledge base", "knowledge_base"),
    ("graph:read", "View the investigation graph", "graph"),
    ("users:read", "View users", "admin"),
    ("users:write", "Create, edit and role-manage users", "admin"),
    ("users:delete", "Delete users", "admin"),
    ("users:manage", "Manage users (alias)", "admin"),
    ("roles:read", "View roles and permissions", "admin"),
    ("roles:write", "Create, edit and delete roles", "admin"),
    ("roles:assign", "Assign roles to users (alias)", "admin"),
    ("tenant:read", "View tenant settings", "admin"),
    ("tenant:write", "Change tenant settings", "admin"),
    ("settings:read", "Read settings", "admin"),
    ("settings:write", "Change settings", "admin"),
    ("settings:manage", "Manage settings (alias)", "admin"),
    ("sso:configure", "Configure SSO connections", "admin"),
    ("api_keys:read", "View API keys", "api_keys"),
    ("api_keys:write", "Create and revoke API keys", "api_keys"),
    ("api_keys:delete", "Delete API keys", "api_keys"),
    ("apikeys:manage", "Manage API keys (alias)", "api_keys"),
    ("audit_log:read", "Read the audit log", "audit"),
    ("audit:read", "Read the audit log (alias)", "audit"),
    # Depth 8.2 — time-boxed elevation, attribute conditions, and the
    # per-service credentials that replace the one shared service token.
    ("elevation:read", "View the tenant's privilege elevations", "access"),
    ("elevation:request", "Request a time-boxed privilege elevation", "access"),
    ("elevation:approve", "Approve or revoke a privilege elevation", "access"),
    ("access_conditions:read", "View attribute conditions on permissions", "access"),
    ("access_conditions:write", "Add, disable or remove attribute conditions", "access"),
    ("workload_identities:read", "View per-service internal credentials", "access"),
    ("workload_identities:write", "Mint, rotate or revoke per-service credentials", "access"),
    ("sla:read", "View SLA metrics", "sla"),
    ("sla:write", "Change SLA policy", "sla"),
    ("plugins:read", "View plugins", "plugins"),
    ("plugins:admin", "Administer plugins", "plugins"),
    ("plugins:execute", "Execute plugins", "plugins"),
    ("*", "Every permission (wildcard; admin role)", "system"),
)

#: The three product roles: (name, description). `viewer` is the SSO JIT
#: default and is protected (is_system) by construction.
SYSTEM_ROLES: Final[tuple[tuple[str, str], ...]] = (
    ("viewer", "Regular User. View-only. The default role for SSO just-in-time provisioning."),
    ("infosec", "Infosec analyst / incident handler. Investigates, triages and responds; manages no users, roles, SSO or settings."),
    ("admin", "Platform administrator. Full control of this tenant, including users, roles, SSO configuration and the audit log."),
)

#: Human display names for the system roles (the `label` column; `name`
#: stays the machine slug). Custom roles set their own label at create.
SYSTEM_ROLE_LABELS: Final[dict[str, str]] = {
    "viewer": "Regular User",
    "infosec": "Infosec Analyst",
    "admin": "Platform Administrator",
}

#: The SSO just-in-time default, kept as a name here so the Roles screen can
#: badge it without querying the connection table.
SSO_DEFAULT_ROLE: Final[str] = "viewer"

_VIEWER: Final[frozenset[str]] = frozenset(
    {
        "alerts:read",
        "cases:read",
        "dashboards:read",
        "detections:read",
        "reports:read",
        "connectors:read",
        "threat_intel:read",
        "actions:read",
        "knowledge_base:read",
    }
)

_INFOSEC: Final[frozenset[str]] = _VIEWER | frozenset(
    {
        "alerts:write",
        "cases:write",
        "cases:assign",
        "cases:note",
        "playbooks:read",
        "playbooks:execute",
        "threat_intel:write",
        "threatintel:manage",
        "rules:read",
        "rules:write",
        "detections:write",
        "hunts:read",
        "lake:query",
        "lake:read_schema",
        "graph:read",
        "actions:execute",
        "investigation:run",
        "reports:write",
        "reports:export",
        # An analyst may *ask* for a permission for a while, and see their
        # own requests. Approving is deliberately absent: an approver who
        # can also request is both parties to the decision, and the whole
        # control reduces to a log line.
        "elevation:request",
    }
)

#: role name -> permission names it is granted. `admin` holds the wildcard.
ROLE_GRANTS: Final[dict[str, frozenset[str]]] = {
    "viewer": _VIEWER,
    "infosec": _INFOSEC,
    "admin": frozenset({"*"}),
}


async def seed_tenant_catalog(db: AsyncSession, tenant_id: Any) -> dict[str, int]:
    """Seed the catalog for one tenant, atomically, idempotently.

    One transaction on purpose: `resolve_permissions` switches a tenant to
    database-backed mode the moment `roles` has a row, and a user without a
    `user_roles` row in such a tenant resolves to zero permissions. So the
    roles, the grants and the membership backfill land together or not at
    all. The caller commits.

    Returns row counts for the endpoint response and the migration summary.
    """
    tid = str(tenant_id)

    await db.execute(
        text(
            """
            INSERT INTO permissions (name, description, category)
            VALUES (:name, :description, :category)
            ON CONFLICT (name) DO UPDATE
               SET description = EXCLUDED.description,
                   category    = EXCLUDED.category
            """
        ),
        [{"name": name, "description": desc, "category": cat} for name, desc, cat in PERMISSIONS],
    )

    await db.execute(
        text(
            """
            INSERT INTO roles (tenant_id, name, label, description, is_system)
            VALUES (CAST(:t AS uuid), :name, :label, :description, TRUE)
            ON CONFLICT (tenant_id, name) DO UPDATE
               SET description = EXCLUDED.description
            """
        ),
        [
            {
                "t": tid,
                "name": name,
                "label": SYSTEM_ROLE_LABELS.get(name, name),
                "description": desc,
            }
            for name, desc in SYSTEM_ROLES
        ],
    )

    grant_rows: list[dict[str, str]] = []
    for role_name, perms in ROLE_GRANTS.items():
        for perm in sorted(perms):
            grant_rows.append({"t": tid, "role": role_name, "perm": perm})
    await db.execute(
        text(
            """
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id
              FROM roles r
              JOIN permissions p ON p.name = :perm
             WHERE r.tenant_id = CAST(:t AS uuid) AND r.name = :role
            ON CONFLICT DO NOTHING
            """
        ),
        grant_rows,
    )

    # Membership backfill (header explains why it cannot be a separate
    # transaction). `assigned_by IS NULL` marks seeded rows: operator
    # assignments always carry an actor id.
    await db.execute(
        text(
            """
            INSERT INTO user_roles (user_id, role_id)
            SELECT u.id, r.id
              FROM users u
              JOIN roles r ON r.tenant_id = u.tenant_id AND r.name = u.role
             WHERE r.tenant_id = CAST(:t AS uuid) AND r.is_system = TRUE
            ON CONFLICT DO NOTHING
            """
        ),
        {"t": tid},
    )
    await db.execute(
        text(
            """
            INSERT INTO user_roles (user_id, role_id)
            SELECT u.id, vr.id
              FROM users u
              JOIN roles vr ON vr.tenant_id = u.tenant_id AND vr.name = :viewer AND vr.is_system = TRUE
             WHERE u.tenant_id = CAST(:t AS uuid)
               AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id)
            ON CONFLICT DO NOTHING
            """
        ),
        {"t": tid, "viewer": SSO_DEFAULT_ROLE},
    )

    counts: dict[str, int] = {}
    for key, stmt in {
        "permissions": "SELECT count(*) FROM permissions",
        "roles": "SELECT count(*) FROM roles WHERE tenant_id = CAST(:t AS uuid)",
        "role_permissions": (
            "SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.tenant_id = CAST(:t AS uuid)"
        ),
        "user_roles": ("SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.tenant_id = CAST(:t AS uuid)"),
    }.items():
        counts[key] = int((await db.execute(text(stmt), {"t": tid})).scalar() or 0)
    return counts


async def sync_user_catalog_role(db: AsyncSession, *, tenant_id: Any, user_id: Any, role_name: str) -> None:
    """Point a user's catalog memberships at `role_name` (replace-set).

    Called from SSO provisioning after it has decided the role. Without it a
    JIT-provisioned user has `users.role` but no `user_roles` row, which in
    a catalog tenant means zero permissions. Unknown role name is a no-op
    with a safe warning — the caller has already fallen back to `viewer` by
    the time this runs, and the string on `users.role` is re-synced on the
    next sign-in.
    """
    tid, uid = str(tenant_id), str(user_id)
    row = (
        await db.execute(
            text("SELECT id FROM roles WHERE tenant_id = CAST(:t AS uuid) AND name = :r"),
            {"t": tid, "r": role_name},
        )
    ).first()
    if row is None:
        logger.warning(
            "rbac.catalog_sync_unknown_role user=%s role=%s — no seeded role of that name; memberships left alone",
            uid[:8],
            str(role_name)[:40],
        )
        return
    await db.execute(
        text("DELETE FROM user_roles WHERE user_id = CAST(:u AS uuid) AND role_id <> CAST(:r AS uuid)"),
        {"u": uid, "r": str(row[0])},
    )
    await db.execute(
        text("INSERT INTO user_roles (user_id, role_id) VALUES (CAST(:u AS uuid), CAST(:r AS uuid)) ON CONFLICT DO NOTHING"),
        {"u": uid, "r": str(row[0])},
    )
