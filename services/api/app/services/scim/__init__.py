"""SCIM 2.0 provisioning (RFC 7643, RFC 7644).

Split by concern on purpose:

``patch``
    Normalises the PATCH bodies identity providers send, which differ from
    each other in five documented ways.
``filters``
    Parses the one filter shape provisioning sends, and refuses the rest
    rather than widening a result set.
``resources``
    SCIM representation and the discovery documents.
``roles``
    Maps directory groups onto the roles this platform enforces.
``tokens``
    Mints, verifies and rotates the bearer credential.
``provisioning``
    Applies operations to ``users`` and ``api_keys``, including the
    deprovisioning path that has to actually end access.
"""

from app.services.scim.filters import EqualityFilter, ScimFilterError, parse_equality
from app.services.scim.patch import ScimPatchError, ScimPatchOp, coerce_bool, member_ids, parse_patch
from app.services.scim.provisioning import DeactivationResult, deactivate_user, reactivate_user, recompute_role
from app.services.scim.roles import DEFAULT_PROVISIONED_ROLE, effective_role, resolve_role, validate_vocabulary
from app.services.scim.tokens import ScimAuthError, ScimPrincipal, mint_token, rotate_token, verify_token

__all__ = [
    "DEFAULT_PROVISIONED_ROLE",
    "DeactivationResult",
    "EqualityFilter",
    "ScimAuthError",
    "ScimFilterError",
    "ScimPatchError",
    "ScimPatchOp",
    "ScimPrincipal",
    "coerce_bool",
    "deactivate_user",
    "effective_role",
    "member_ids",
    "mint_token",
    "parse_equality",
    "parse_patch",
    "reactivate_user",
    "recompute_role",
    "resolve_role",
    "rotate_token",
    "validate_vocabulary",
    "verify_token",
]
