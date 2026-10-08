"""
Security utilities: JWT tokens, password hashing, RBAC, API key generation
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

# bcrypt has a hard 72-byte limit on inputs. We mirror what passlib used to do
# but without the version-introspection that breaks against newer bcrypt
# releases (passlib 1.7.4 reads `_bcrypt.__about__.__version__`, which was
# removed in bcrypt 4.x and causes a misleading 72-byte error to surface even
# for short passwords).
_BCRYPT_MAX_BYTES = 72

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "platform_admin": ["*"],
    # ``admin`` is the role string handed out by the dev-mode demo user
    # (see ``app.api.v1.dev_auth``) and by some legacy seed scripts. It
    # must resolve to the same privileges as ``platform_admin`` so that
    # ``require_permission(...)`` does not silently deny while
    # identity-only deps silently allow — that inconsistency was the
    # source of the P0.3 audit finding.
    "admin": ["*"],
    "tenant_admin": [
        "alerts:read",
        "alerts:write",
        "alerts:delete",
        "cases:read",
        "cases:write",
        "cases:delete",
        "playbooks:read",
        "playbooks:write",
        "playbooks:execute",
        "connectors:read",
        "connectors:write",
        "connectors:delete",
        "users:read",
        "users:write",
        "rules:read",
        "rules:write",
        "reports:read",
        "reports:write",
        "threat_intel:read",
        # Tenant admins must be able to manage their tenant's threat-intel
        # surface (IOCs, actor profiles, feed config). Without :write the
        # admin role could not even add a feed, let alone delete a poisoned
        # IOC injected by a compromised analyst.
        "threat_intel:write",
        "settings:read",
        "settings:write",
        # A tenant admin could not read their own tenant's audit log. Only
        # `platform_admin` and `admin` could, and both hold `*` across every
        # tenant — so on a multi-tenant deployment the only principals who
        # could answer "who changed this?" for a customer were the operator's
        # own staff, and the customer had to ask them. That is a compliance
        # failure (SOC 2 CC7.2 and ISO 27001 A.12.4 both require the control
        # owner to be able to review their own trail) and an MSSP blocker.
        #
        # Safe because the read is tenant-scoped at the query layer: the
        # handler filters on the authenticated `tenant_id`, so this grants
        # visibility of their own history and nothing else.
        "audit_log:read",
        # Workstream 7: tenant lake API. Tenant admins get full access
        # to the warm-tier query surface (POST /api/v1/lake/sql) and
        # the schema discovery endpoint (GET /api/v1/lake/schema). The
        # rewriter still enforces tenant_id predicates and the
        # ClickHouse client still enforces row caps and timeouts; the
        # permission only controls who *can* query at all.
        "hunts:read",
        "lake:query",
        "lake:read_schema",
        # The live-action registry: which vendors can perform which response
        # verbs against this tenant's estate, and what a given action would
        # do. `actions:execute` gates the dry-run preview only — a live
        # containment goes through the approval path, where an approver is
        # bound to the decision.
        "actions:read",
        "actions:execute",
        # POST /knowledge-base/query is a read expressed as a POST (the
        # question is a body), so it was counted as a state-changing
        # route with no authorization decision. It searches this
        # tenant's own knowledge base, so every role that can read an
        # alert can read it.
        "knowledge_base:read",
        # Depth 8.2. A tenant administrator governs access inside their own
        # tenant: who may elevate, who approves, and which attribute
        # conditions narrow a permission.
        #
        # `workload_identities:*` is deliberately NOT here. Those credentials
        # are deployment-wide — a service authenticates before any tenant is
        # known — so minting one from a tenant-scoped session would confer
        # authority over every tenant's data. Only the wildcard roles hold
        # them, which is the one case where "no scoped role holds this" is
        # the decision rather than the oversight it usually is.
        "elevation:read",
        "elevation:request",
        "elevation:approve",
        "access_conditions:read",
        "access_conditions:write",
    ],
    "soc_lead": [
        "alerts:read",
        "alerts:write",
        "cases:read",
        "cases:write",
        "playbooks:read",
        "playbooks:execute",
        "connectors:read",
        "users:read",
        "rules:read",
        "rules:write",
        "reports:read",
        "reports:write",
        "threat_intel:read",
        # SOC leads triage incidents and need to be able to add/expire
        # IOCs derived from investigations without waiting on the threat-
        # hunter or tenant-admin role.
        "threat_intel:write",
        # SOC leads run investigations across the lake routinely.
        "hunts:read",
        "lake:query",
        "lake:read_schema",
        "actions:read",
        "actions:execute",
        # POST /knowledge-base/query is a read expressed as a POST (the
        # question is a body), so it was counted as a state-changing
        # route with no authorization decision. It searches this
        # tenant's own knowledge base, so every role that can read an
        # alert can read it.
        "knowledge_base:read",
        # A lead is the approver an analyst's elevation goes to, which is
        # the role the separation-of-duties rule assumes exists.
        "elevation:read",
        "elevation:request",
        "elevation:approve",
        "access_conditions:read",
    ],
    "soc_analyst": [
        "alerts:read",
        "alerts:write",
        "cases:read",
        "cases:write",
        "playbooks:read",
        "playbooks:execute",
        "connectors:read",
        "threat_intel:read",
        "reports:read",
        # Analysts need lake access to drill into raw events when
        # alerts don't tell the whole story. Schema is read-only and
        # the rate limiter caps abuse.
        "hunts:read",
        "lake:query",
        "lake:read_schema",
        # Analysts already hold playbooks:execute, and a dry run touches no
        # vendor, so previewing a response is within the same envelope.
        "actions:read",
        "actions:execute",
        # POST /knowledge-base/query is a read expressed as a POST (the
        # question is a body), so it was counted as a state-changing
        # route with no authorization decision. It searches this
        # tenant's own knowledge base, so every role that can read an
        # alert can read it.
        "knowledge_base:read",
        # Request, never approve. The analyst asking to isolate a host is
        # not the person who should decide they may.
        "elevation:request",
    ],
    "threat_hunter": [
        "alerts:read",
        "cases:read",
        "cases:write",
        "threat_intel:read",
        "threat_intel:write",
        "rules:read",
        "rules:write",
        "reports:read",
        # Threat hunters live in the lake — this is their primary
        # workspace for hypothesis-driven investigation across raw
        # events, alert metrics, and IOC enrichments.
        "hunts:read",
        "lake:query",
        "lake:read_schema",
        # Read the registry to know what response is available for a finding;
        # hunters hand off rather than respond, so no execute.
        "actions:read",
        # POST /knowledge-base/query is a read expressed as a POST (the
        # question is a body), so it was counted as a state-changing
        # route with no authorization decision. It searches this
        # tenant's own knowledge base, so every role that can read an
        # alert can read it.
        "knowledge_base:read",
        "elevation:request",
    ],
    "viewer": [
        "alerts:read",
        "cases:read",
        "reports:read",
        "threat_intel:read",
        "actions:read",
        # POST /knowledge-base/query is a read expressed as a POST (the
        # question is a body), so it was counted as a state-changing
        # route with no authorization decision. It searches this
        # tenant's own knowledge base, so every role that can read an
        # alert can read it.
        "knowledge_base:read",
    ],
    "api_service": [
        "alerts:read",
        "alerts:write",
        "cases:read",
        "cases:write",
        "threat_intel:read",
    ],
}


def _to_bcrypt_input(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        encoded = encoded[:_BCRYPT_MAX_BYTES]
    return encoded


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(_to_bcrypt_input(plain_password), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(_to_bcrypt_input(password), bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    issued_at = datetime.now(UTC)
    if expires_delta:
        expire = issued_at + expires_delta
    else:
        expire = issued_at + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": issued_at, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    issued_at = datetime.now(UTC)
    expire = issued_at + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": issued_at, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def token_is_revoked(issued_at: Any, sessions_revoked_at: datetime | None) -> bool:
    """Whether a token predates the principal's last session revocation.

    ``iat`` is the only thing distinguishing a token minted before a
    deprovisioning from one minted after it. A token with no ``iat`` at all
    predates this claim being added and is treated as revoked whenever a
    revocation exists, which fails closed: the alternative would let a token
    from before the upgrade outlive the revocation that was supposed to end it.
    """
    if sessions_revoked_at is None:
        return False
    if issued_at is None:
        return True
    try:
        minted = datetime.fromtimestamp(float(issued_at), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return True
    cutoff = sessions_revoked_at if sessions_revoked_at.tzinfo else sessions_revoked_at.replace(tzinfo=UTC)
    # `<=` rather than `<`: `iat` has one-second resolution, so a token
    # minted in the same second as the revocation must not survive it.
    return minted <= cutoff


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# Audience claim required on every realtime WS/SSE ticket. The Node realtime
# verifier (``services/realtime/src/index.ts``) checks for this exact value, so
# a leaked first-party API access token (aud unset) cannot be replayed against
# the realtime edge and vice-versa.
REALTIME_TICKET_AUDIENCE = "aisoc-realtime"


def create_realtime_ticket(
    *,
    secret: str,
    tenant_id: str,
    user_id: str,
    ttl_seconds: int,
) -> str:
    """Mint a short-lived HS256 ticket for the realtime WS/SSE edge.

    Signed with the *shared realtime secret* (``AISOC_REALTIME_JWT_SECRET`` or
    the dev fallback), NOT ``SECRET_KEY``. Carries an ``aud`` claim so it is only
    valid at the realtime boundary, and an ``exp`` clamped by the caller. The
    realtime service derives the subscription tenant from ``tenant_id`` here —
    the browser never gets to choose its own tenant.
    """
    now = datetime.now(UTC)
    expire = now + timedelta(seconds=ttl_seconds)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "aud": REALTIME_TICKET_AUDIENCE,
        "iat": now,
        "exp": expire,
        "type": "realtime_ticket",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new scoped API key.

    Returns:
        (raw_key, prefix, hashed_key)
        - raw_key   – the full secret shown once to the user  (e.g. ``aisoc_<48 hex chars>``)
        - prefix    – first 12 chars for display / lookup     (e.g. ``aisoc_abc123``)
        - hashed_key – SHA-256 hex digest stored in the DB
    """
    token = secrets.token_hex(24)  # 48 hex chars = 192 bits entropy
    raw_key = f"aisoc_{token}"
    prefix = raw_key[:12]  # "aisoc_" + first 6 hex chars
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, prefix, hashed_key


def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def verify_ed25519_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Verify an Ed25519 signature. Raises ValueError on failure."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pub_key = load_pem_public_key(public_key_bytes)
        if not isinstance(pub_key, Ed25519PublicKey):
            raise ValueError("Key is not an Ed25519 public key")
        pub_key.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("Invalid signature") from exc


#: Security analyst / incident handler, declared as a set expression rather
#: than a literal copy so it cannot drift from the analyst and hunter rows
#: above it. The subtraction is the restriction list: no user, role, settings,
#: raw-alert, connector-credential, audit, API-key or platform management.
ROLE_PERMISSIONS["infosec"] = sorted(
    (set(ROLE_PERMISSIONS["soc_analyst"]) | set(ROLE_PERMISSIONS["threat_hunter"]))
    - {
        "alert_source_raw:read",
        "alerts:delete",
        "api_keys:manage",
        "connectors:write",
        "connectors:delete",
        "platform_admin",
        "roles:delete",
        "roles:write",
        "settings:write",
        "users:delete",
        "users:write",
    }
)


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, [])
    if "*" in perms:
        return True
    if permission in perms:
        return True
    # Check wildcard resource (e.g., "alerts:*" covers "alerts:read")
    resource = permission.split(":")[0]
    return f"{resource}:*" in perms
