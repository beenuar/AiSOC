"""HTTP-surface smoke test for the mobile/passkey HITL approver (Theme 2m).

The mobile route module (``app.api.mobile_routes``) is the on-call analyst's
phone-side surface: passkey enrollment, voice readout, and HITL decisions
recorded against ``HitlChannel.MOBILE``. The console HITL routes already
have their own coverage; this file exercises the **distinctive contract** of
the mobile surface end-to-end:

  1.  Unauthenticated requests to a mobile endpoint return **401** — we
      never let an unknown caller list registered passkeys.
  2.  An analyst can register a passkey: ``POST /mobile/passkeys/register/
      challenge`` issues a single-use challenge bound to the JWT subject,
      ``POST /mobile/passkeys/register`` finalizes registration after the
      device signs the challenge.
  3.  Re-using a registration challenge is rejected (challenge is
      single-use). Likewise for assertion challenges.
  4.  ``GET /mobile/passkeys`` is tenant + principal scoped — tenant B
      cannot see tenant A's registered credentials.
  5.  ``GET /mobile/hitl/{id}/readout`` returns the SSML payload and
      structured summary lines for a pending HITL the caller can see; the
      same request from another tenant returns **403** (we never reveal
      that the HITL exists).
  6.  Issuing an assertion challenge for a HITL not in your tenant returns
      **403**.
  7.  Approving a HITL from mobile:
        * Without a registered passkey → **401** (passkey rejected).
        * With a fresh, signed challenge and monotonically-advancing
          sign_counter → **200**, the HITL row transitions to APPROVED with
          ``decided_channel = MOBILE`` and a non-empty receipt hash.
  8.  Replaying the same challenge a second time → **401** (challenge
      single-use), and the HITL state must not regress.
  9.  Denying a fresh HITL from mobile records DENIED with channel MOBILE.
 10.  Revoking a passkey then trying to assert against it returns **401**.

Crypto notes:
    The dev verifier in ``app.hitl.passkey._verify_signature`` is HMAC-SHA256
    over the challenge using the stored ``public_key`` string as the shared
    secret. This test mints credential bytes locally and signs challenges
    with the same primitive — that's intentional: the test exercises the
    *flow* (challenge binding, counter monotonicity, tenant scoping, receipt
    hashing), not the production ECDSA seam.

Usage:

    cd platform/backend
    python -m tests._check_mobile_hitl
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ephemeral DB, strict auth (no anon fallback), stable JWT secret so the
# tokens minted here verify against the same `settings` the API uses.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-mobile-hitl-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "mobile-hitl.db")
os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "false"
os.environ["AISOC_JWT_SECRET_KEY"] = "mobile-hitl-test-secret-do-not-use-in-prod"
os.environ.setdefault("AISOC_ENV", "development")

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.db import engine, init_db
from app.main import app
from app.models.case import Case, Severity
from app.models.hitl import HitlChannel, HitlRequest, HitlState
from app.security.jwt import issue_tenant_token
from fastapi.testclient import TestClient
from sqlmodel import Session


TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ANALYST_A = "alice@cyble.test"
ANALYST_B = "bob@evil.test"


def _mint(tenant_id: str, subject: str) -> str:
    return issue_tenant_token(
        tenant_id=tenant_id,
        subject=subject,
        roles=["analyst"],
    )


def _auth_headers(tenant_id: str, subject: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint(tenant_id, subject)}"}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign(public_key: str, challenge: str) -> str:
    """Mirror app.hitl.passkey._verify_signature's HMAC primitive."""
    return hmac.new(
        public_key.encode(), challenge.encode(), hashlib.sha256
    ).hexdigest()


def _seed_hitl_pending(tenant_id: str, *, tool_name: str = "edr.isolate_host") -> int:
    """Create a pending HITL row for the given tenant and return its id."""
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        case = Case(
            tenant_id=tenant_id,
            title=f"mobile-hitl seed for {tenant_id}",
            severity=Severity.HIGH,
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        assert case.id is not None

        req = HitlRequest(
            tenant_id=tenant_id,
            case_id=case.id,
            agent="responder",
            tool_name=tool_name,
            integration="crowdstrike",
            risk_class="WRITE_SIGNIFICANT",
            params={"host": f"host-of-{tenant_id}", "reason": "C2 beacon"},
            rationale="Confirmed C2 beacon, isolating host",
            blast_radius={"hosts": [f"host-of-{tenant_id}"], "users": []},
            state=HitlState.PENDING,
            expires_at=now + timedelta(minutes=15),
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        assert req.id is not None
        return req.id


def _register_passkey(
    client: TestClient,
    *,
    tenant_id: str,
    subject: str,
    label: str = "iphone-15",
) -> tuple[str, str]:
    """Register a passkey via the real HTTP routes.

    Returns ``(credential_id, public_key)`` so subsequent assertion tests
    can sign challenges with the same HMAC secret the server stored.
    """
    # 1. Challenge.
    r = client.post(
        "/mobile/passkeys/register/challenge",
        headers=_auth_headers(tenant_id, subject),
        json={"user_name": subject},
    )
    assert r.status_code == 200, (r.status_code, r.text)
    body = r.json()
    challenge = body["challenge"]
    assert body["rp"]["id"] == "aisoc.local"
    assert body["user"]["name"] == subject
    assert any(p["alg"] == -7 for p in body["pubKeyCredParams"]), body

    # 2. Generate fake credential bytes locally and finalize.
    credential_id = _b64url(secrets.token_bytes(16))
    public_key = _b64url(secrets.token_bytes(32))
    r = client.post(
        "/mobile/passkeys/register",
        headers=_auth_headers(tenant_id, subject),
        json={
            "challenge": challenge,
            "credential_id": credential_id,
            "public_key": public_key,
            "label": label,
            "transports": "internal,hybrid",
        },
    )
    assert r.status_code == 200, (r.status_code, r.text)
    finalized = r.json()
    assert finalized["credential_id"] == credential_id
    assert finalized["label"] == label
    return credential_id, public_key


# ── Checks ───────────────────────────────────────────────────────────────


def _check_unauth_returns_401(client: TestClient) -> None:
    r = client.get("/mobile/passkeys")
    assert r.status_code == 401, (r.status_code, r.text)
    print("OK  unauth GET /mobile/passkeys → 401")


def _check_register_and_list_is_tenant_scoped(client: TestClient) -> tuple[str, str]:
    cred_a, pubkey_a = _register_passkey(
        client, tenant_id=TENANT_A, subject=ANALYST_A, label="alice-iphone"
    )
    print(f"OK  registered passkey for {ANALYST_A}@{TENANT_A}: cred={cred_a[:8]}…")

    # Tenant A sees their key.
    r = client.get("/mobile/passkeys", headers=_auth_headers(TENANT_A, ANALYST_A))
    assert r.status_code == 200, (r.status_code, r.text)
    rows = r.json()
    assert any(row["credential_id"] == cred_a for row in rows), rows
    assert all(row["label"] != "bob-iphone" for row in rows)

    # Tenant B cannot see tenant A's keys.
    r = client.get("/mobile/passkeys", headers=_auth_headers(TENANT_B, ANALYST_B))
    assert r.status_code == 200, (r.status_code, r.text)
    assert all(row["credential_id"] != cred_a for row in r.json()), r.json()
    print("OK  /mobile/passkeys is tenant + principal scoped")

    return cred_a, pubkey_a


def _check_registration_challenge_is_single_use(client: TestClient) -> None:
    r = client.post(
        "/mobile/passkeys/register/challenge",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={},
    )
    assert r.status_code == 200, r.text
    chal = r.json()["challenge"]
    payload = {
        "challenge": chal,
        "credential_id": _b64url(secrets.token_bytes(16)),
        "public_key": _b64url(secrets.token_bytes(32)),
    }
    ok = client.post(
        "/mobile/passkeys/register",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json=payload,
    )
    assert ok.status_code == 200, ok.text

    # Reuse the same challenge → 400 (challenge consumed).
    payload2 = {
        "challenge": chal,
        "credential_id": _b64url(secrets.token_bytes(16)),
        "public_key": _b64url(secrets.token_bytes(32)),
    }
    reused = client.post(
        "/mobile/passkeys/register",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json=payload2,
    )
    assert reused.status_code == 400, (reused.status_code, reused.text)
    print("OK  registration challenge is single-use (replay → 400)")


def _check_readout_cross_tenant_403(client: TestClient, hitl_id_a: int) -> None:
    # Same-tenant success.
    r = client.get(
        f"/mobile/hitl/{hitl_id_a}/readout",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200, (r.status_code, r.text)
    body = r.json()
    assert body["request_id"] == hitl_id_a
    assert body["tenant_id"] == TENANT_A
    assert body["summary_lines"], body
    assert "<speak>" in body["audio"]["ssml"], body["audio"]
    assert body["audio"]["mode"] == "client-ssml"
    print(f"OK  tenant-A GET /mobile/hitl/{hitl_id_a}/readout returns SSML payload")

    # Cross-tenant 403 — never reveal existence.
    r = client.get(
        f"/mobile/hitl/{hitl_id_a}/readout",
        headers=_auth_headers(TENANT_B, ANALYST_B),
    )
    assert r.status_code == 403, (r.status_code, r.text)
    print(f"OK  tenant-B GET /mobile/hitl/{hitl_id_a}/readout → 403")


def _check_assertion_challenge_cross_tenant_403(
    client: TestClient, hitl_id_a: int
) -> None:
    r = client.post(
        f"/mobile/hitl/{hitl_id_a}/assertion-challenge",
        headers=_auth_headers(TENANT_B, ANALYST_B),
    )
    assert r.status_code == 403, (r.status_code, r.text)
    print(
        f"OK  tenant-B POST /mobile/hitl/{hitl_id_a}/assertion-challenge → 403"
    )


def _check_approve_happy_path(
    client: TestClient,
    *,
    hitl_id: int,
    credential_id: str,
    public_key: str,
) -> None:
    # 1. Issue assertion challenge.
    r = client.post(
        f"/mobile/hitl/{hitl_id}/assertion-challenge",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200, (r.status_code, r.text)
    body = r.json()
    challenge = body["challenge"]
    assert body["rpId"] == "aisoc.local"
    assert body["userVerification"] == "required"
    assert any(c["id"] == credential_id for c in body["allowCredentials"]), body

    # 2. Sign and approve. sign_counter must strictly advance from stored=0.
    signature = _sign(public_key, challenge)
    r = client.post(
        f"/mobile/hitl/{hitl_id}/approve",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={
            "credential_id": credential_id,
            "challenge": challenge,
            "signature": signature,
            "sign_counter": 1,
            "reason": "confirmed beacon",
        },
    )
    assert r.status_code == 200, (r.status_code, r.text)
    decided = r.json()
    assert decided["state"] == HitlState.APPROVED.value, decided
    assert decided["decided_channel"] == HitlChannel.MOBILE.value, decided
    assert decided["decided_by"] == ANALYST_A, decided
    # Receipt hashes are intentionally NOT in the response body (that's an
    # audit-trail concern, not a client one). Verify them via the DB row.
    with Session(engine) as db:
        req = db.get(HitlRequest, hitl_id)
        assert req is not None
        assert req.decided_by_mfa_method == "webauthn", req.decided_by_mfa_method
        assert req.decided_by_mfa_token, "receipt hash must be persisted"
    print(
        f"OK  POST /mobile/hitl/{hitl_id}/approve → APPROVED, channel=MOBILE, "
        "webauthn receipt persisted in audit row"
    )

    # 3. Replay the same (challenge, signature) → 401, state stays APPROVED.
    replay = client.post(
        f"/mobile/hitl/{hitl_id}/approve",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={
            "credential_id": credential_id,
            "challenge": challenge,
            "signature": signature,
            "sign_counter": 2,  # even with a fresh counter, challenge is consumed
            "reason": "replay attempt",
        },
    )
    assert replay.status_code == 401, (replay.status_code, replay.text)
    with Session(engine) as db:
        req = db.get(HitlRequest, hitl_id)
        assert req is not None
        assert req.state == HitlState.APPROVED, req.state
        assert req.decided_channel == HitlChannel.MOBILE
    print(
        f"OK  replay POST /mobile/hitl/{hitl_id}/approve → 401, state unchanged"
    )


def _check_counter_must_advance(
    client: TestClient,
    *,
    credential_id: str,
    public_key: str,
) -> None:
    """A second decision after counter=1 must present counter >= 2 or be rejected.

    We need a *fresh* pending HITL for tenant A because the previous one
    has already terminated as APPROVED.
    """
    fresh_id = _seed_hitl_pending(TENANT_A, tool_name="idp.disable_user")

    # Fresh challenge.
    r = client.post(
        f"/mobile/hitl/{fresh_id}/assertion-challenge",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge"]

    # Present a counter that did NOT advance (stored is 1 from previous test).
    r_stale = client.post(
        f"/mobile/hitl/{fresh_id}/approve",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={
            "credential_id": credential_id,
            "challenge": challenge,
            "signature": _sign(public_key, challenge),
            "sign_counter": 1,
            "reason": "stale counter",
        },
    )
    assert r_stale.status_code == 401, (r_stale.status_code, r_stale.text)
    # HITL stays PENDING — a rejected assertion must never decide the row.
    with Session(engine) as db:
        req = db.get(HitlRequest, fresh_id)
        assert req is not None
        assert req.state == HitlState.PENDING, req.state
    print(
        f"OK  POST /mobile/hitl/{fresh_id}/approve with stale counter → 401, "
        "HITL stays PENDING"
    )


def _check_deny_records_mobile_channel(
    client: TestClient, *, credential_id: str, public_key: str
) -> None:
    """A passkey-backed deny is recorded with channel=MOBILE and state=DENIED."""
    deny_id = _seed_hitl_pending(TENANT_A, tool_name="email.quarantine")

    r = client.post(
        f"/mobile/hitl/{deny_id}/assertion-challenge",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200
    challenge = r.json()["challenge"]

    r = client.post(
        f"/mobile/hitl/{deny_id}/deny",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={
            "credential_id": credential_id,
            "challenge": challenge,
            "signature": _sign(public_key, challenge),
            "sign_counter": 2,  # must strictly advance from previous stale-test stored value (1)
            "reason": "false positive",
        },
    )
    assert r.status_code == 200, (r.status_code, r.text)
    body = r.json()
    assert body["state"] == HitlState.DENIED.value, body
    assert body["decided_channel"] == HitlChannel.MOBILE.value, body
    assert body["decision_reason"] == "false positive"
    print(
        f"OK  POST /mobile/hitl/{deny_id}/deny → DENIED, channel=MOBILE, "
        "reason persisted"
    )


def _check_revoked_passkey_cannot_assert(client: TestClient) -> None:
    """After revoke, the same credential must be rejected on assertion."""
    cred, pubkey = _register_passkey(
        client, tenant_id=TENANT_A, subject=ANALYST_A, label="alice-burner"
    )
    # Revoke it.
    r = client.delete(
        f"/mobile/passkeys/{cred}",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] == cred

    # Try to assert with the revoked credential against a fresh HITL.
    new_hitl_id = _seed_hitl_pending(TENANT_A, tool_name="edr.contain_host")
    r = client.post(
        f"/mobile/hitl/{new_hitl_id}/assertion-challenge",
        headers=_auth_headers(TENANT_A, ANALYST_A),
    )
    assert r.status_code == 200
    challenge = r.json()["challenge"]

    r = client.post(
        f"/mobile/hitl/{new_hitl_id}/approve",
        headers=_auth_headers(TENANT_A, ANALYST_A),
        json={
            "credential_id": cred,
            "challenge": challenge,
            "signature": _sign(pubkey, challenge),
            "sign_counter": 99,
            "reason": "should fail",
        },
    )
    assert r.status_code == 401, (r.status_code, r.text)
    with Session(engine) as db:
        req = db.get(HitlRequest, new_hitl_id)
        assert req is not None
        assert req.state == HitlState.PENDING
    print("OK  revoked passkey → 401 on assert, HITL stays PENDING")


def main() -> None:
    init_db()

    with TestClient(app) as client:
        _check_unauth_returns_401(client)
        cred_a, pubkey_a = _check_register_and_list_is_tenant_scoped(client)
        _check_registration_challenge_is_single_use(client)

        # Seed a pending HITL for tenant A — used for readout + approve flow.
        hitl_id_a = _seed_hitl_pending(TENANT_A)
        print(f"seeded tenant-A HitlRequest id={hitl_id_a}")

        _check_readout_cross_tenant_403(client, hitl_id_a)
        _check_assertion_challenge_cross_tenant_403(client, hitl_id_a)
        _check_approve_happy_path(
            client,
            hitl_id=hitl_id_a,
            credential_id=cred_a,
            public_key=pubkey_a,
        )
        _check_counter_must_advance(
            client, credential_id=cred_a, public_key=pubkey_a
        )
        _check_deny_records_mobile_channel(
            client, credential_id=cred_a, public_key=pubkey_a
        )
        _check_revoked_passkey_cannot_assert(client)

    print("\nALL MOBILE HITL CHECKS PASSED")


if __name__ == "__main__":
    main()
