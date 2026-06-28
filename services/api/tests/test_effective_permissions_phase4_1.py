"""Phase 4.1 — full-coverage resolver tests for Azure / GCP / Okta / GWS.

These replace the previous ``scaffolded_providers_raise_not_implemented``
gate. Each provider has a hand-rolled snapshot exercising the
trickiest pieces of its model (scope inheritance, group-via
membership, deny overrides, OU prefix matching). The reference
expectations are encoded inline so the resolver's behaviour is
pinned independently of a second simulator implementation.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.services.effective_permissions.azure import AzureRbacResolver
from app.services.effective_permissions.base import ResolverError
from app.services.effective_permissions.gcp import GcpIamResolver
from app.services.effective_permissions.gws import GoogleWorkspaceResolver
from app.services.effective_permissions.okta import OktaResolver

# ============================== AZURE ==============================


@pytest.fixture
def azure_snapshot() -> dict[str, Any]:
    """A realistic Azure snapshot: alice is a Reader at the sub level
    and has a Storage Account Contributor at the RG level, but a deny
    assignment on the sub blocks ``Microsoft.Storage/.../delete``."""
    return {
        "principals": [
            {
                "id": "alice",
                "object_id": "11111111-1111-1111-1111-111111111111",
                "type": "user",
                "groups": ["g-storage-admins"],
            }
        ],
        "role_definitions": [
            {
                "id": "Reader",
                "name": "Reader",
                "permissions": [
                    {
                        "actions": ["Microsoft.Storage/storageAccounts/read"],
                        "notActions": [],
                        "dataActions": [],
                        "notDataActions": [],
                    }
                ],
            },
            {
                "id": "StorageContributor",
                "name": "Storage Account Contributor",
                "permissions": [
                    {
                        "actions": [
                            "Microsoft.Storage/storageAccounts/read",
                            "Microsoft.Storage/storageAccounts/write",
                            "Microsoft.Storage/storageAccounts/delete",
                        ],
                        "notActions": [],
                        "dataActions": [],
                        "notDataActions": [],
                    }
                ],
            },
        ],
        "role_assignments": [
            {
                "id": "ra-sub-reader",
                "principal_id": "alice",
                "role_definition_id": "Reader",
                "scope": "/subscriptions/sub1",
            },
            {
                "id": "ra-rg-contrib",
                "principal_id": "g-storage-admins",
                "role_definition_id": "StorageContributor",
                "scope": "/subscriptions/sub1/resourceGroups/rg1",
            },
        ],
        "deny_assignments": [
            {
                "id": "da-1",
                "principal_id": "alice",
                "name": "block-storage-delete",
                "scope": "/subscriptions/sub1",
                "permissions": [
                    {
                        "actions": ["Microsoft.Storage/storageAccounts/delete"],
                        "notActions": [],
                    }
                ],
            }
        ],
        "resources": [
            {
                "id": "acct1",
                "azure_id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1",
                "kind": "Microsoft.Storage/storageAccounts",
                "service_actions": [
                    "Microsoft.Storage/storageAccounts/read",
                    "Microsoft.Storage/storageAccounts/write",
                    "Microsoft.Storage/storageAccounts/delete",
                ],
            },
            {
                "id": "acct2",
                # Outside rg1, so the contributor assignment shouldn't apply.
                "azure_id": "/subscriptions/sub1/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/acct2",
                "kind": "Microsoft.Storage/storageAccounts",
                "service_actions": [
                    "Microsoft.Storage/storageAccounts/read",
                    "Microsoft.Storage/storageAccounts/write",
                    "Microsoft.Storage/storageAccounts/delete",
                ],
            },
        ],
    }


def test_azure_resolver_inherits_role_from_subscription_scope(azure_snapshot: dict[str, Any]) -> None:
    result = AzureRbacResolver(snapshot=azure_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}

    # acct2 sits outside rg1, so only the sub-level Reader applies,
    # and the deny on delete is irrelevant (Reader never granted it).
    assert "read" in str(by_resource["acct2"].actions)
    assert by_resource["acct2"].actions == ("Microsoft.Storage/storageAccounts/read",)


def test_azure_resolver_applies_deny_assignment_for_in_scope_resource(
    azure_snapshot: dict[str, Any],
) -> None:
    result = AzureRbacResolver(snapshot=azure_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}

    acct1 = by_resource["acct1"]
    # read, write granted; delete shadowed by deny.
    assert "Microsoft.Storage/storageAccounts/read" in acct1.actions
    assert "Microsoft.Storage/storageAccounts/write" in acct1.actions
    assert "Microsoft.Storage/storageAccounts/delete" not in acct1.actions
    assert "Microsoft.Storage/storageAccounts/delete" in acct1.deny_actions


def test_azure_resolver_resolves_group_via_assignment(azure_snapshot: dict[str, Any]) -> None:
    """The Contributor assignment targets the group ``g-storage-admins``,
    not alice directly. The resolver must walk her group membership."""
    result = AzureRbacResolver(snapshot=azure_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}
    # write only comes from the group-via-contributor path
    assert "Microsoft.Storage/storageAccounts/write" in by_resource["acct1"].actions


def test_azure_resolver_resolves_by_object_id_alias(azure_snapshot: dict[str, Any]) -> None:
    object_id = "11111111-1111-1111-1111-111111111111"
    result = AzureRbacResolver(snapshot=azure_snapshot).resolve(object_id)
    assert result.principal_id == object_id
    assert any(d.resource_id == "acct1" for d in result.decisions)


def test_azure_resolver_raises_for_unknown_principal(azure_snapshot: dict[str, Any]) -> None:
    with pytest.raises(ResolverError, match="not present in snapshot"):
        AzureRbacResolver(snapshot=azure_snapshot).resolve("ghost")


def test_azure_resolver_reports_full_coverage() -> None:
    assert AzureRbacResolver.coverage == "full"


# =============================== GCP ===============================


@pytest.fixture
def gcp_snapshot() -> dict[str, Any]:
    """alice is in group eng@corp.com which holds Storage Object
    Viewer at the project level. An org-level org-policy blocks
    ``iam.serviceAccountKeys.create``."""
    return {
        "principals": [
            {
                "id": "alice@corp.com",
                "type": "user",
                "groups": ["group:eng@corp.com"],
            }
        ],
        "roles": [
            {
                "id": "roles/storage.objectViewer",
                "name": "Storage Object Viewer",
                "permissions": ["storage.objects.get", "storage.objects.list"],
            },
            {
                "id": "roles/iam.serviceAccountKeyAdmin",
                "name": "SA Key Admin",
                "permissions": [
                    "iam.serviceAccountKeys.create",
                    "iam.serviceAccountKeys.list",
                ],
            },
        ],
        "bindings": [
            {
                "id": "b-storage",
                "resource_id": "//cloudresourcemanager.googleapis.com/projects/proj",
                "role": "roles/storage.objectViewer",
                "members": ["group:eng@corp.com"],
            },
            {
                "id": "b-sa-keys",
                "resource_id": "//cloudresourcemanager.googleapis.com/projects/proj",
                "role": "roles/iam.serviceAccountKeyAdmin",
                "members": ["user:alice@corp.com"],
            },
        ],
        "org_policies": [
            {
                "id": "op-1",
                "resource_id": "//cloudresourcemanager.googleapis.com/organizations/123",
                "constraint": "constraints/iam.disableServiceAccountKeyCreation",
                "denied_permissions": ["iam.serviceAccountKeys.create"],
            }
        ],
        "resources": [
            {
                "id": "bucket1",
                "gcp_id": "//storage.googleapis.com/buckets/bucket1",
                "kind": "storage.googleapis.com/Bucket",
                "ancestors": [
                    "//storage.googleapis.com/buckets/bucket1",
                    "//cloudresourcemanager.googleapis.com/projects/proj",
                    "//cloudresourcemanager.googleapis.com/organizations/123",
                ],
            },
            {
                "id": "sa1",
                "gcp_id": "//iam.googleapis.com/projects/proj/serviceAccounts/sa1",
                "kind": "iam.googleapis.com/ServiceAccount",
                "ancestors": [
                    "//iam.googleapis.com/projects/proj/serviceAccounts/sa1",
                    "//cloudresourcemanager.googleapis.com/projects/proj",
                    "//cloudresourcemanager.googleapis.com/organizations/123",
                ],
            },
        ],
    }


def test_gcp_resolver_grants_role_via_group_membership(gcp_snapshot: dict[str, Any]) -> None:
    result = GcpIamResolver(snapshot=gcp_snapshot).resolve("alice@corp.com")
    by_resource = {d.resource_id: d for d in result.decisions}
    assert "storage.objects.get" in by_resource["bucket1"].actions
    assert "storage.objects.list" in by_resource["bucket1"].actions


def test_gcp_resolver_subtracts_org_policy_constraint(gcp_snapshot: dict[str, Any]) -> None:
    result = GcpIamResolver(snapshot=gcp_snapshot).resolve("alice@corp.com")
    by_resource = {d.resource_id: d for d in result.decisions}
    sa1 = by_resource["sa1"]
    # Org-policy blocks create; list survives.
    assert "iam.serviceAccountKeys.list" in sa1.actions
    assert "iam.serviceAccountKeys.create" not in sa1.actions
    # And surfaces in deny_actions as shadowed.
    assert "iam.serviceAccountKeys.create" in sa1.deny_actions


def test_gcp_resolver_reports_org_policy_in_policy_chain(gcp_snapshot: dict[str, Any]) -> None:
    result = GcpIamResolver(snapshot=gcp_snapshot).resolve("alice@corp.com")
    by_resource = {d.resource_id: d for d in result.decisions}
    chain_kinds = {step.kind for step in by_resource["sa1"].policy_chain}
    assert "binding" in chain_kinds
    assert "org-policy" in chain_kinds


def test_gcp_resolver_raises_for_unknown_principal(gcp_snapshot: dict[str, Any]) -> None:
    with pytest.raises(ResolverError, match="not present in snapshot"):
        GcpIamResolver(snapshot=gcp_snapshot).resolve("ghost@corp.com")


# =============================== OKTA ==============================


@pytest.fixture
def okta_snapshot() -> dict[str, Any]:
    return {
        "principals": [
            {
                "id": "alice",
                "email": "alice@corp.com",
                "groups": ["g-admins"],
                "assigned_apps": ["app-personal"],
            }
        ],
        "groups": [
            {
                "id": "g-admins",
                "name": "Admins",
                "admin_roles": ["SUPER_ADMIN"],
                "assigned_apps": ["app-okta-admin"],
            }
        ],
        "admin_roles": [
            {
                "id": "SUPER_ADMIN",
                "name": "Super Administrator",
                "privileges": [
                    "okta.users.manage",
                    "okta.groups.manage",
                    "okta.apps.manage",
                ],
            }
        ],
        "apps": [
            {"id": "app-okta-admin", "name": "Okta Admin Console"},
            {"id": "app-personal", "name": "Personal App"},
        ],
        "resources": [
            {"id": "okta-org", "kind": "okta-org"},
            {"id": "app-okta-admin", "kind": "okta-app"},
        ],
    }


def test_okta_resolver_aggregates_admin_role_privileges(okta_snapshot: dict[str, Any]) -> None:
    result = OktaResolver(snapshot=okta_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}
    org = by_resource["okta-org"]
    assert "okta.users.manage" in org.actions
    assert "okta.groups.manage" in org.actions


def test_okta_resolver_surfaces_app_reads_on_org_resource(okta_snapshot: dict[str, Any]) -> None:
    result = OktaResolver(snapshot=okta_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}
    org_actions = by_resource["okta-org"].actions
    # Both direct (app-personal) and group-via (app-okta-admin) apps.
    assert "okta.app.app-okta-admin.read" in org_actions
    assert "okta.app.app-personal.read" in org_actions


def test_okta_resolver_per_app_resource_only_surfaces_that_app(okta_snapshot: dict[str, Any]) -> None:
    result = OktaResolver(snapshot=okta_snapshot).resolve("alice")
    by_resource = {d.resource_id: d for d in result.decisions}
    app_admin = by_resource["app-okta-admin"]
    assert app_admin.actions == ("okta.app.app-okta-admin.read",)


def test_okta_resolver_raises_for_unknown_principal(okta_snapshot: dict[str, Any]) -> None:
    with pytest.raises(ResolverError, match="not present in snapshot"):
        OktaResolver(snapshot=okta_snapshot).resolve("ghost")


# ============================== GWS ================================


@pytest.fixture
def gws_snapshot() -> dict[str, Any]:
    return {
        "principals": [
            {"id": "alice@corp.com", "ou_path": "/Eng"},
        ],
        "admin_roles": [
            {
                "id": "USER_MANAGEMENT_ADMIN",
                "name": "User Management Admin",
                "privileges": ["USERS_CREATE", "USERS_UPDATE", "USERS_RETRIEVE"],
            },
            {
                "id": "GROUPS_ADMIN",
                "name": "Groups Admin",
                "privileges": ["GROUPS_CREATE", "GROUPS_UPDATE"],
            },
        ],
        "role_assignments": [
            {
                "id": "ra-1",
                "principal_id": "alice@corp.com",
                "role_id": "USER_MANAGEMENT_ADMIN",
                "scope_type": "ORG_UNIT",
                "ou_path": "/Eng",
            },
            {
                "id": "ra-2",
                "principal_id": "alice@corp.com",
                "role_id": "GROUPS_ADMIN",
                "scope_type": "CUSTOMER",
                "ou_path": "/",
            },
        ],
        "resources": [
            {"id": "user-bob", "kind": "gws-user", "ou_path": "/Eng/Backend"},
            {"id": "user-carol", "kind": "gws-user", "ou_path": "/Sales"},
            {"id": "group-eng", "kind": "gws-group", "ou_path": "/Eng"},
        ],
    }


def test_gws_resolver_scopes_org_unit_assignment_to_subtree(gws_snapshot: dict[str, Any]) -> None:
    result = GoogleWorkspaceResolver(snapshot=gws_snapshot).resolve("alice@corp.com")
    by_resource = {d.resource_id: d for d in result.decisions}
    # /Eng covers /Eng/Backend
    bob = by_resource["user-bob"]
    assert "USERS_CREATE" in bob.actions
    # but /Eng does not cover /Sales — only the CUSTOMER-scope Groups
    # Admin survives there.
    carol = by_resource["user-carol"]
    assert "USERS_CREATE" not in carol.actions
    assert "GROUPS_CREATE" in carol.actions


def test_gws_resolver_customer_scope_covers_every_ou(gws_snapshot: dict[str, Any]) -> None:
    result = GoogleWorkspaceResolver(snapshot=gws_snapshot).resolve("alice@corp.com")
    for d in result.decisions:
        assert "GROUPS_CREATE" in d.actions


def test_gws_resolver_raises_for_unknown_principal(gws_snapshot: dict[str, Any]) -> None:
    with pytest.raises(ResolverError, match="not present in snapshot"):
        GoogleWorkspaceResolver(snapshot=gws_snapshot).resolve("ghost@corp.com")


def test_gws_resolver_reports_full_coverage() -> None:
    assert GoogleWorkspaceResolver.coverage == "full"
