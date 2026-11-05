"""Entra directory audits carry the object that changed (issue #1718).

Reported by gdncomm-dika-wibowo against ten alerts from one tenant: every
one named the Microsoft service that performed the change rather than the
user, group or device that was changed. The data was in `raw_event` the
whole time; it never reached a field anything downstream reads.

The payloads below are the anonymised shapes from that report, in Graph's
own nesting, not in the shape the assertions want:

* a group add whose `targetResources` carries the member **and** the group,
  and whose group name lives in `modifiedProperties[1]`;
* an `initiatedBy.user` whose `displayName` is a first-party client and
  whose `userPrincipalName` is the person;
* a device update whose `modifiedProperties[0]` is the empty
  `Included Updated Properties` marker;
* a self-service reset initiated by the password-reset service.

This file pins the **connector** half. The envelope it asserts is the same
one `services/ingest/internal/normalizer/issue_1718_test.go` feeds to the
real Go normalizer, and the OCSF that produces is what
`services/fusion/tests/test_entra_target_entities_issue_1718.py` feeds to
the real promoter and alert sink. The three are separate because
`services/connectors` and `services/fusion` both name their top-level
package `app` — importing one inside the other's interpreter shadows it —
and because the middle layer is Go. A connector change that drops a field
reds this test rather than silently passing the other two.

Nothing here has been exercised against a live Entra tenant; the shapes
are transcribed from the report and from Graph's published schema.
"""

from __future__ import annotations

from typing import Any

from app.connectors.azure_entra import AzureEntraConnector

GROUP_ADD: dict[str, Any] = {
    "_aisoc_event_kind": "directoryAudit",
    "id": "Directory_1a2b3c4d-0000-4000-8000-000000000001",
    "activityDateTime": "2026-11-03T09:12:44.1234567Z",
    "activityDisplayName": "Add member to group",
    "category": "GroupManagement",
    "correlationId": "00000000-0000-4000-8000-00000000000a",
    "loggedByService": "Core Directory",
    "operationType": "Assign",
    "result": "success",
    "resultReason": "",
    # Graph puts the first-party client in `displayName` and the human in
    # `userPrincipalName`. This is the shape that made the alert say Teams.
    "initiatedBy": {
        "user": {
            "id": "00000000-0000-4000-8000-00000000000b",
            "displayName": "Microsoft Teams Services",
            "userPrincipalName": "user-c@example.com",
            "ipAddress": None,
        }
    },
    "targetResources": [
        {
            "type": "User",
            "id": "00000000-0000-4000-8000-00000000000c",
            "userPrincipalName": "user-b@example.com",
            "displayName": "User B",
            "groupType": None,
            "modifiedProperties": [
                {
                    "displayName": "Group.ObjectID",
                    "oldValue": None,
                    "newValue": '"00000000-0000-4000-8000-00000000000d"',
                },
                {"displayName": "Group.DisplayName", "oldValue": None, "newValue": '"Group A"'},
                {"displayName": "Group.WellKnownObjectName", "oldValue": None, "newValue": '""'},
            ],
        },
        {
            "type": "Group",
            "id": "00000000-0000-4000-8000-00000000000d",
            "userPrincipalName": None,
            "displayName": None,
            "groupType": "unknownFutureValue",
            "modifiedProperties": [],
        },
    ],
}

#: The same add, where Graph recorded `success` beside a modified property
#: saying the member was already in the group.
GROUP_ADD_ALREADY_A_MEMBER: dict[str, Any] = {
    **GROUP_ADD,
    "id": "Directory_1a2b3c4d-0000-4000-8000-000000000002",
    "targetResources": [
        {
            **GROUP_ADD["targetResources"][0],
            "modifiedProperties": [
                *GROUP_ADD["targetResources"][0]["modifiedProperties"],
                {
                    "displayName": "MethodExecutionResult.",
                    "oldValue": None,
                    "newValue": "Microsoft.Online.DirectoryServices.DirectoryValueExistsException",
                },
            ],
        },
        GROUP_ADD["targetResources"][1],
    ],
}

DEVICE_UPDATE: dict[str, Any] = {
    "_aisoc_event_kind": "directoryAudit",
    "id": "Directory_1a2b3c4d-0000-4000-8000-000000000003",
    "activityDateTime": "2026-11-03T09:20:01.0000000Z",
    "activityDisplayName": "Update device",
    "category": "DeviceManagement",
    "loggedByService": "Device Registration Service",
    "operationType": "Update",
    "result": "success",
    "resultReason": "",
    "initiatedBy": {
        "app": {
            "appId": "00000000-0000-4000-8000-00000000000e",
            "displayName": "Intune Compliance Client Prod",
            "servicePrincipalId": "00000000-0000-4000-8000-00000000000f",
            "servicePrincipalName": None,
        }
    },
    "targetResources": [
        {
            "type": "Device",
            "id": "00000000-0000-4000-8000-000000000010",
            "userPrincipalName": None,
            "displayName": "HOST-01",
            "modifiedProperties": [
                # Entry 0 is the marker, which is why reading `modified[0]`
                # lost every real property on every device event.
                {"displayName": "Included Updated Properties", "oldValue": None, "newValue": '""'},
                {
                    "displayName": "DeviceId",
                    "oldValue": None,
                    "newValue": '"00000000-0000-4000-8000-000000000010"',
                },
                {"displayName": "DeviceOSType", "oldValue": None, "newValue": '"Windows"'},
                {"displayName": "DeviceTrustType", "oldValue": None, "newValue": '"Azure AD Joined"'},
            ],
        }
    ],
}

SELF_SERVICE_RESET: dict[str, Any] = {
    "_aisoc_event_kind": "directoryAudit",
    "id": "Directory_1a2b3c4d-0000-4000-8000-000000000004",
    "activityDateTime": "2026-11-03T09:31:17.0000000Z",
    "activityDisplayName": "Reset user password",
    "category": "UserManagement",
    "loggedByService": "Self-service Password Management",
    "operationType": "Update",
    "result": "success",
    "resultReason": "",
    "initiatedBy": {
        "app": {
            "appId": "00000000-0000-4000-8000-000000000011",
            "displayName": "Microsoft password reset service",
            "servicePrincipalId": "00000000-0000-4000-8000-000000000012",
            "servicePrincipalName": None,
        }
    },
    "targetResources": [
        {
            "type": "User",
            "id": "00000000-0000-4000-8000-000000000013",
            "userPrincipalName": "user-a@example.com",
            "displayName": "User A",
            "modifiedProperties": [{"displayName": "StrongAuthenticationMethod", "oldValue": None, "newValue": '"[]"'}],
        }
    ],
}

ADMIN_RESET: dict[str, Any] = {
    **SELF_SERVICE_RESET,
    "id": "Directory_1a2b3c4d-0000-4000-8000-000000000005",
    "loggedByService": "Core Directory",
    "initiatedBy": {
        "user": {
            "id": "00000000-0000-4000-8000-000000000014",
            "displayName": "Helpdesk Operator",
            "userPrincipalName": "helpdesk@example.com",
            "ipAddress": "203.0.113.9",
        }
    },
}


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    connector = AzureEntraConnector(tenant_id="t", client_id="c", client_secret="s")  # noqa: S106 — test
    return connector.normalize(raw)


# ─── Cause 2: a human actor masked by the client's display name ──────────


def test_actor_is_the_human_not_the_first_party_client() -> None:
    out = _normalize(GROUP_ADD)

    assert out["actor"] == "user-c@example.com"
    assert out["actor_email"] == "user-c@example.com"
    # The client is not discarded, it is named as the client. Nothing has to
    # guess whether `actor_display_name` held a person or an app.
    assert out["actor_display_name"] == "Microsoft Teams Services"
    assert out["initiator_type"] == "user"


def test_app_initiator_is_named_as_an_app() -> None:
    out = _normalize(DEVICE_UPDATE)

    assert out["actor"] == "Intune Compliance Client Prod"
    assert out["actor_app"] == "Intune Compliance Client Prod"
    assert out["actor_email"] is None
    assert out["initiator_type"] == "app"


def test_initiator_type_is_always_present() -> None:
    """A clause on it can never silently stop matching."""
    out = _normalize({**GROUP_ADD, "initiatedBy": {}})

    assert out["initiator_type"] == "unknown"


# ─── Cause 4: every target survives, keyed by what it is ────────────────


def test_every_target_resource_survives() -> None:
    out = _normalize(GROUP_ADD)

    assert out["target_count"] == 2
    assert [t["type"] for t in out["targets"]] == ["User", "Group"]
    assert out["targets"][0]["user_principal_name"] == "user-b@example.com"
    assert out["targets"][1]["id"] == "00000000-0000-4000-8000-00000000000d"


def test_flat_target_fields_are_unchanged() -> None:
    """Rule compatibility: the flat fields still describe `targetResources[0]`."""
    out = _normalize(GROUP_ADD)

    assert out["target_type"] == "User"
    assert out["target_user"] == "user-b@example.com"
    assert out["target_name"] == "User B"
    assert out["target_id"] == "00000000-0000-4000-8000-00000000000c"
    assert out["modified_property"] == "Group.ObjectID"
    assert out["new_value"] == "00000000-0000-4000-8000-00000000000d"


# ─── Cause 3: every modified property survives, keyed by name ───────────


def test_group_name_survives_from_the_second_modified_property() -> None:
    out = _normalize(GROUP_ADD)

    assert out["modified_properties"]["Group.DisplayName"] == "Group A"
    # Derived by looking for the group, never by index.
    assert out["target_group_name"] == "Group A"
    assert out["target_group_id"] == "00000000-0000-4000-8000-00000000000d"


def test_device_properties_survive_past_the_empty_marker() -> None:
    out = _normalize(DEVICE_UPDATE)

    assert out["modified_properties"]["DeviceOSType"] == "Windows"
    assert out["target_device_id"] == "00000000-0000-4000-8000-000000000010"
    assert out["target_device_os"] == "Windows"
    assert out["target_device_trust_type"] == "Azure AD Joined"


# ─── Cause 5: a device target is a host ─────────────────────────────────


def test_device_target_is_lifted_as_a_hostname() -> None:
    out = _normalize(DEVICE_UPDATE)

    assert out["target_hostname"] == "HOST-01"


def test_a_user_target_is_not_lifted_as_a_hostname() -> None:
    out = _normalize(GROUP_ADD)

    assert out.get("target_hostname") is None


# ─── The MethodExecutionResult observation ──────────────────────────────


def test_a_no_op_add_carries_the_directory_exception() -> None:
    """Graph's own `result` is reported as Graph wrote it, with the
    directory's execution result named beside it rather than folded into it."""
    out = _normalize(GROUP_ADD_ALREADY_A_MEMBER)

    assert out["audit_result"] == "success"
    assert out["method_execution_result"] == "Microsoft.Online.DirectoryServices.DirectoryValueExistsException"


def test_an_ordinary_add_has_no_execution_result() -> None:
    out = _normalize(GROUP_ADD)

    assert out.get("method_execution_result") is None


# ─── Cause 6: the initiator distinguishes an admin reset from SSPR ──────


def test_self_service_reset_is_an_app_initiator() -> None:
    out = _normalize(SELF_SERVICE_RESET)

    assert out["activity"] == "Reset user password"
    assert out["initiator_type"] == "app"
    assert out["target_user"] == "user-a@example.com"


def test_administrator_reset_is_a_user_initiator() -> None:
    out = _normalize(ADMIN_RESET)

    assert out["activity"] == "Reset user password"
    assert out["initiator_type"] == "user"
    assert out["actor"] == "helpdesk@example.com"
