"""SCIM resource representation and the discovery documents (RFC 7643).

``ServiceProviderConfig``, ``ResourceTypes`` and ``Schemas`` are not
decoration. An identity provider reads them during setup to decide which
operations to attempt, and one that advertises a capability it does not
implement gets configured to use it. Everything declared here is
cross-checked against the implemented routes by
``scripts/check_scim_contract.py``, so this file cannot claim PATCH support
the router does not offer.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Final

USER_SCHEMA: Final[str] = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA: Final[str] = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_RESPONSE_SCHEMA: Final[str] = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA: Final[str] = "urn:ietf:params:scim:api:messages:2.0:Error"
SERVICE_PROVIDER_CONFIG_SCHEMA: Final[str] = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA: Final[str] = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA: Final[str] = "urn:ietf:params:scim:schemas:core:2.0:Schema"

#: The base path the router is mounted at. Referenced by the discovery
#: documents, which must give an identity provider a location it can fetch.
SCIM_BASE: Final[str] = "/scim/v2"

#: The SCIM content type. Providers send it and expect it back; some reject a
#: response labelled ``application/json``.
SCIM_CONTENT_TYPE: Final[str] = "application/scim+json"


def _stamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def user_resource(
    *,
    user_id: uuid.UUID,
    user_name: str,
    active: bool,
    external_id: str | None,
    given_name: str | None,
    family_name: str | None,
    created_at: datetime | None,
    updated_at: datetime | None,
    groups: list[tuple[uuid.UUID, str]] | None = None,
) -> dict[str, Any]:
    """One SCIM User.

    ``id`` is this platform's user UUID, so a provider's stored link survives
    a rename of every other attribute.
    """
    name: dict[str, Any] = {}
    if given_name:
        name["givenName"] = given_name
    if family_name:
        name["familyName"] = family_name
    if name:
        formatted = " ".join(part for part in (given_name, family_name) if part)
        if formatted:
            name["formatted"] = formatted

    resource: dict[str, Any] = {
        "schemas": [USER_SCHEMA],
        "id": str(user_id),
        "userName": user_name,
        "active": active,
        "emails": [{"value": user_name, "primary": True, "type": "work"}],
        "meta": {
            "resourceType": "User",
            "created": _stamp(created_at),
            "lastModified": _stamp(updated_at or created_at),
            "location": f"{SCIM_BASE}/Users/{user_id}",
        },
    }
    if external_id:
        resource["externalId"] = external_id
    if name:
        resource["name"] = name
    if groups:
        resource["groups"] = [
            {"value": str(group_id), "display": display, "$ref": f"{SCIM_BASE}/Groups/{group_id}"} for group_id, display in groups
        ]
    return resource


def group_resource(
    *,
    group_id: uuid.UUID,
    display_name: str,
    external_id: str | None,
    mapped_role: str | None,
    created_at: datetime | None,
    updated_at: datetime | None,
    members: list[tuple[uuid.UUID, str]] | None = None,
) -> dict[str, Any]:
    """One SCIM Group.

    ``mapped_role`` is surfaced under this platform's own extension URN
    rather than smuggled into a core attribute. An administrator debugging
    "why did this group not grant anything" can read the answer out of the
    same response their identity provider sees, and a ``null`` there is the
    honest representation of a group that confers nothing.
    """
    resource: dict[str, Any] = {
        "schemas": [GROUP_SCHEMA, AISOC_GROUP_EXTENSION],
        "id": str(group_id),
        "displayName": display_name,
        "members": [
            {"value": str(member_id), "display": display, "$ref": f"{SCIM_BASE}/Users/{member_id}"}
            for member_id, display in (members or [])
        ],
        AISOC_GROUP_EXTENSION: {"mappedRole": mapped_role},
        "meta": {
            "resourceType": "Group",
            "created": _stamp(created_at),
            "lastModified": _stamp(updated_at or created_at),
            "location": f"{SCIM_BASE}/Groups/{group_id}",
        },
    }
    if external_id:
        resource["externalId"] = external_id
    return resource


#: This platform's Group extension. Namespaced under our own URN so it can
#: never collide with a core attribute a future RFC revision adds.
AISOC_GROUP_EXTENSION: Final[str] = "urn:aisoc:params:scim:schemas:extension:2.0:Group"


def list_response(resources: list[dict[str, Any]], *, total: int, start_index: int, count: int) -> dict[str, Any]:
    """A SCIM ListResponse.

    ``totalResults`` is the size of the whole match, not of this page.
    Providers page on it, and returning the page size instead makes a sync
    stop after the first page while reporting success.
    """
    return {
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "itemsPerPage": len(resources),
        "startIndex": start_index,
        "Resources": resources,
    }


def error_response(status: int, detail: str, *, scim_type: str | None = None) -> dict[str, Any]:
    """A SCIM Error. ``status`` is a string per RFC 7644 section 3.12."""
    body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return body


def service_provider_config() -> dict[str, Any]:
    """What this implementation actually supports.

    Every ``supported: false`` below is a deliberate answer rather than an
    omission. Advertising bulk or sort would have an identity provider
    configure itself to use them.
    """
    return {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://beenuar.github.io/AiSOC/docs/operations/scim",
        "patch": {"supported": True},
        # Bulk is not implemented. Neither provider requires it, and a
        # half-implemented bulk endpoint applies some operations and reports
        # on all of them.
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_PAGE_SIZE},
        "changePassword": {"supported": False},
        # Sorting is not implemented; results are ordered by creation time so
        # paging is stable, which is the property paging actually needs.
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "A per-organisation bearer token, hashed at rest and rotatable with an overlap window.",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": True,
            }
        ],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{SCIM_BASE}/ServiceProviderConfig"},
    }


#: Largest page a caller may request. A provider that asks for more gets this
#: many with an honest ``itemsPerPage``, rather than an error it would
#: surface to an administrator as a failed sync.
MAX_PAGE_SIZE: Final[int] = 200

#: Default page size when a provider does not ask for one.
DEFAULT_PAGE_SIZE: Final[int] = 100


def resource_types() -> list[dict[str, Any]]:
    return [
        {
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "A principal that can sign in to this tenant.",
            "schema": USER_SCHEMA,
            "schemaExtensions": [],
            "meta": {"resourceType": "ResourceType", "location": f"{SCIM_BASE}/ResourceTypes/User"},
        },
        {
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "A directory group. Confers the platform role it maps to, or nothing.",
            "schema": GROUP_SCHEMA,
            "schemaExtensions": [{"schema": AISOC_GROUP_EXTENSION, "required": False}],
            "meta": {"resourceType": "ResourceType", "location": f"{SCIM_BASE}/ResourceTypes/Group"},
        },
    ]


def _attribute(
    name: str,
    attr_type: str = "string",
    *,
    required: bool = False,
    multi: bool = False,
    mutability: str = "readWrite",
    case_exact: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "type": attr_type,
        "multiValued": multi,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "none",
    }


def schemas() -> list[dict[str, Any]]:
    """The attribute definitions for the two resource types served here."""
    return [
        {
            "schemas": [SCHEMA_SCHEMA],
            "id": USER_SCHEMA,
            "name": "User",
            "description": "SCIM core User, as implemented by this platform.",
            "attributes": [
                _attribute("userName", required=True),
                _attribute("externalId"),
                _attribute("active", "boolean"),
                {
                    **_attribute("name", "complex"),
                    "subAttributes": [_attribute("givenName"), _attribute("familyName"), _attribute("formatted")],
                },
                {
                    **_attribute("emails", "complex", multi=True),
                    "subAttributes": [_attribute("value"), _attribute("primary", "boolean"), _attribute("type")],
                },
                {
                    **_attribute("groups", "complex", multi=True, mutability="readOnly"),
                    "subAttributes": [_attribute("value"), _attribute("display")],
                },
            ],
            "meta": {"resourceType": "Schema", "location": f"{SCIM_BASE}/Schemas/{USER_SCHEMA}"},
        },
        {
            "schemas": [SCHEMA_SCHEMA],
            "id": GROUP_SCHEMA,
            "name": "Group",
            "description": "SCIM core Group, as implemented by this platform.",
            "attributes": [
                _attribute("displayName", required=True),
                _attribute("externalId"),
                {
                    **_attribute("members", "complex", multi=True),
                    "subAttributes": [_attribute("value"), _attribute("display")],
                },
            ],
            "meta": {"resourceType": "Schema", "location": f"{SCIM_BASE}/Schemas/{GROUP_SCHEMA}"},
        },
        {
            "schemas": [SCHEMA_SCHEMA],
            "id": AISOC_GROUP_EXTENSION,
            "name": "AiSOCGroupExtension",
            "description": "The platform role a group confers, or null when it confers nothing.",
            "attributes": [_attribute("mappedRole", mutability="readOnly")],
            "meta": {"resourceType": "Schema", "location": f"{SCIM_BASE}/Schemas/{AISOC_GROUP_EXTENSION}"},
        },
    ]
