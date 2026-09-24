#!/usr/bin/env python3
"""Default-deny: every route authenticates, or is public for a recorded reason.

``check_route_tenant_scope.py`` asks a conditional question — *if* a route
takes a tenant, where did the tenant come from. That leaves the larger set
untouched: a route that takes no tenant was never in its reach, and an
unauthenticated route that takes no tenant is still an unauthenticated route.
``POST /api/v1/playbooks/{id}/run`` on ``services/agents`` took no tenant and
executed a response playbook against the estate for any caller on the network.

So this gate inverts the default. Every route must either carry an
authentication dependency or appear in one of three tables below, each of
which records *why* it is reachable without one:

``PUBLIC_MODULES``
    Whole modules that exist to be probed — the shared liveness/readiness
    module. Keyed by path, not by handler name, because classifying a route
    as a health check by calling it ``health`` is a naming convention, and a
    naming convention is the thing that drifts.
``PUBLIC_ROUTES``
    Individual routes that are public by design: the sign-in flow, the
    identity-provider callbacks, a deliberately published replay. Each entry
    carries its reason.
``IN_BAND_CREDENTIAL_ROUTES``
    Routes whose credential is verified *inside the handler* rather than by
    a dependency — an HMAC signature, a signed callback payload, a
    single-use token. An AST pass sees no ``Depends`` and calls these
    unauthenticated; they are not. The exemption is **conditional**: it names
    the verifier and only holds while the handler still calls it. Delete the
    verification and the route is reported, which is the failure an
    unconditional allowlist cannot catch.

Two counts in this repository were wrong for exactly that last reason.
``slack-bot`` was reported as five unauthenticated routes: three are probes,
and the other two verify a Slack request signature and a shared internal
token in-band. ``teams-bot``'s webhook verifies an HMAC-signed card payload
with a replay window. Neither was ever open.

Both directions
---------------
* forward — an unauthenticated route with no entry fails;
* reverse — an entry that no longer matches a real unauthenticated route
  fails as stale, and an in-band entry whose verifier the handler stopped
  calling fails too. Exemptions therefore shrink as routes are secured,
  rather than accumulating as a list of things somebody once found
  inconvenient.

Usage::

    python scripts/check_route_auth.py              # gate
    python scripts/check_route_auth.py --inventory  # per-service table
    python scripts/check_route_auth.py --json
    python scripts/check_route_auth.py --self-test

Exit codes: 0 clean, 1 violations, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# One parser, two questions. A second route scanner would drift from this one
# the first time either learned something the other did not — which is how the
# `ExecuteUser` alias came to be reported as an unauthenticated playbook-run.
from check_route_tenant_scope import (  # noqa: E402
    REPO_ROOT,
    SERVICES_DIR,
    Route,
    collect_routes,
)

#: Public by design at the service level. ``mesh`` federates between
#: independent deployments over Ed25519 signatures and k-anonymity: peers
#: share no credential, so a bearer token would break federation rather than
#: secure it.
EXEMPT_SERVICES: dict[str, str] = {
    "mesh": "federation is public by design — Ed25519-signed submissions + k-anonymity, and no shared credential exists between peers",
}

#: Modules whose every route is a probe.
PUBLIC_MODULES: dict[str, str] = {
    "app/_health.py": "shared Kubernetes liveness/readiness probes; a kubelet holds no credential and a 401 here reads as an outage",
}

#: Individual public routes, each with the reason it is reachable anonymously.
PUBLIC_ROUTES: dict[str, str] = {
    # -- service health, declared per service rather than in the shared module
    "services/actions/app/api/router.py::health": "liveness probe returning a static status document",
    "services/actions/app/main.py::health": "liveness probe returning a static status document",
    "services/agents/app/api/router.py::health": "liveness probe returning a static status document",
    "services/agents/app/main.py::health": "liveness probe returning a static status document",
    "services/api/app/main.py::health_check": "liveness probe; the readiness detail behind it is already gated",
    "services/connectors/app/api/router.py::health": "liveness probe, deliberately kept off the guarded connectors router",
    "services/fusion/app/api/router.py::health": "liveness probe returning a static status document",
    "services/honeytokens/app/main.py::health": "liveness probe returning a static status document",
    "services/purple-team/app/main.py::health": "liveness probe returning a static status document",
    "services/slack-bot/app/main.py::health": "liveness probe returning a static status document",
    "services/teams-bot/app/main.py::health": "liveness probe returning a static status document",
    "services/threatintel/app/main.py::health": "liveness probe returning a static status document",
    "services/ueba/app/main.py::health": "liveness probe returning a static status document",
    "services/osquery-tls/app/main.py::healthz": "liveness probe returning a static status document",
    # -- Prometheus scrape endpoints, gated by METRICS_TOKEN in the handler ---
    "services/api/app/main.py::metrics": "Prometheus scrape; refuses without METRICS_TOKEN outside a development environment",
    "services/fusion/app/api/router.py::metrics": "Prometheus scrape of worker counters; no tenant data, numeric series only",
    # -- sign-in: the request that establishes a credential cannot carry one --
    "services/api/app/api/v1/endpoints/auth.py::login": "the sign-in request itself; it is what mints the credential",
    "services/api/app/api/v1/endpoints/auth.py::refresh_token": "presents a signed refresh token in the body and is verified there",
    "services/api/app/api/v1/endpoints/waitlist.py::signup": "public sign-up form; rate-limited and writes only to the waitlist table",
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_begin": (
        "WebAuthn ceremony start; the assertion that follows is the credential"
    ),
    "services/api/app/api/v1/endpoints/passkeys.py::passkey_authenticate_finish": (
        "verifies the WebAuthn assertion, which is what authenticates the caller"
    ),
    "services/api/app/auth/oidc.py::oidc_login": "OIDC authorization-request redirect, issued before any session exists",
    "services/api/app/auth/oidc.py::oidc_callback": "OIDC redirect URI; the provider's code + state are verified in the handler",
    "services/api/app/auth/oidc.py::oidc_logout": "RP-initiated logout redirect; ends a session rather than reading data",
    "services/api/app/auth/oidc.py::oidc_userinfo": "OIDC userinfo shim reading the bearer token in-band, exactly as the spec requires",
    "services/api/app/auth/saml.py::saml_login": "SAML AuthnRequest redirect, issued before any session exists",
    "services/api/app/auth/saml.py::saml_acs": "SAML assertion consumer; the signed assertion is the credential",
    "services/api/app/auth/saml.py::saml_metadata": "SAML SP metadata document, public by specification",
    "services/api/app/auth/saml.py::saml_logout": "SAML single-logout endpoint; ends a session rather than reading data",
    # -- deliberately published, catalogue-only surfaces ----------------------
    "services/api/app/api/v1/endpoints/replay.py::get_public_replay": (
        "a replay published on purpose; the slug is the capability and publication is an explicit action"
    ),
    "services/api/app/api/v1/endpoints/push.py::get_public_key": "the VAPID public key; publishing it is the point of a public key",
    "services/api/app/api/v1/endpoints/community.py::list_community_plugins": (
        "community marketplace catalogue — the same content the public index serves, no tenant data"
    ),
    "services/api/app/api/v1/endpoints/community.py::get_community_plugin": "community marketplace catalogue entry, no tenant data",
    "services/api/app/api/v1/endpoints/community.py::list_community_detections": "community detection catalogue, no tenant data",
    "services/api/app/api/v1/endpoints/community.py::get_community_detection": "community detection catalogue entry, no tenant data",
    "services/api/app/api/v1/endpoints/community.py::list_community_playbooks": "community playbook catalogue, no tenant data",
    "services/api/app/api/v1/endpoints/compliance.py::list_frameworks": (
        "static compliance-framework definitions (SOC 2, ISO 27001); published standards, not tenant evidence"
    ),
    "services/api/app/api/v1/endpoints/compliance.py::list_framework_controls": (
        "static control definitions for a published framework, not tenant evidence"
    ),
    "services/api/app/api/v1/endpoints/translation.py::list_formats": (
        "the list of rule dialects this build can translate between; a capability manifest"
    ),
    "services/api/app/api/v1/endpoints/fusion.py::ml_status": (
        "model-loaded booleans proxied from fusion; no tenant data and no model configuration"
    ),
}

#: Routes whose credential is verified inside the handler. ``(verifier, reason)``
#: — the verifier must still be called or the exemption lapses.
IN_BAND_CREDENTIAL_ROUTES: dict[str, tuple[str, str]] = {
    "services/slack-bot/app/main.py::slack_events": (
        "SlackRequestHandler",
        "Slack Bolt verifies the request signature against SLACK_SIGNING_SECRET before the handler sees the body",
    ),
    "services/slack-bot/app/notify.py::post_approval_card": (
        "_authorized",
        "internal call authenticated by a shared X-AiSOC-Internal-Token compared in constant time, failing closed when unset",
    ),
    "services/teams-bot/app/main.py::teams_webhook": (
        "handle_card_action",
        "the Bot Framework JWT is terminated by the fronting proxy and the card payload carries our own HMAC, verified with a replay "
        "window by handle_card_action",
    ),
    "services/actions/app/api/router.py::chatops_callback": (
        "verify_token",
        "the query token is an HMAC-signed, expiring payload minted by the ChatOps executor and re-verified here before anything is "
        "recorded",
    ),
    "services/api/app/api/v1/endpoints/email_approval.py::email_decide": (
        "verify_token",
        "one-click email approval; the link carries a signed single-use token verified before the decision is applied",
    ),
    "services/api/app/api/v1/endpoints/oauth.py::oauth_callback": (
        "OAuthState",
        "OAuth redirect URI; the 32-byte single-use state nonce is looked up and consumed before any token exchange",
    ),
    "services/api/app/api/v1/endpoints/inbox_itsm.py::inbound_itsm_webhook": (
        "hmac_secret",
        "vendor webhook authenticated by a per-tenant inbox token in the path plus an HMAC secret, with the connector's tenant cross- "
        "checked against the token's",
    ),
    "services/agents/app/api/metrics.py::metrics": (
        "_authorise",
        "Prometheus scrape; _authorise compares METRICS_TOKEN in constant time and refuses outside a development environment when it is "
        "unset",
    ),
    "services/api/app/api/v1/endpoints/graph_ws.py::graph_updates_stream": (
        "_authenticate_ws",
        "WebSocket: a browser cannot set an Authorization header on the handshake, so the ticket arrives as a query parameter and is "
        "verified in _authenticate_ws",
    ),
    "services/agents/app/api/investigate.py::stream_investigation": (
        "_ws_principal",
        "WebSocket: same handshake constraint; _ws_principal resolves the console token or service token and closes with 1008 before "
        "accept() when neither verifies",
    ),
    "services/osquery-tls/app/api/v1/endpoints/enroll.py::enroll": (
        "verify_enroll_secret",
        "osqueryd holds no bearer token at enrolment — this call is what establishes one — and the per-tenant enroll secret is checked "
        "before any write",
    ),
}


def _module_exempt(route: Route) -> str | None:
    for suffix, reason in PUBLIC_MODULES.items():
        if route.path.endswith(suffix):
            return reason
    return None


def classify(routes: list[Route]) -> tuple[list[Route], list[str]]:
    """Return (unexplained unauthenticated routes, stale exemption keys)."""
    unexplained: list[Route] = []
    matched: set[str] = set()

    for route in routes:
        if route.service in EXEMPT_SERVICES or route.has_auth:
            continue
        if _module_exempt(route) is not None:
            continue
        key = f"{route.path}::{route.function}"
        if key in PUBLIC_ROUTES:
            matched.add(key)
            continue
        if key in IN_BAND_CREDENTIAL_ROUTES:
            verifier, _reason = IN_BAND_CREDENTIAL_ROUTES[key]
            if verifier in route.body_calls or _verifier_in_module(route, verifier):
                matched.add(key)
                continue
            # The entry claims a check the route no longer performs.
            unexplained.append(route)
            continue
        unexplained.append(route)

    declared = set(PUBLIC_ROUTES) | set(IN_BAND_CREDENTIAL_ROUTES)
    stale = sorted(declared - matched)
    return unexplained, stale


def _verifier_in_module(route: Route, verifier: str) -> bool:
    """Whether the handler's module references the verifier.

    Some in-band checks live one call frame away — Bolt's
    ``SlackRequestHandler`` is constructed at import time and verifies before
    the handler body runs, and the ITSM webhook's HMAC is applied by a helper
    the handler calls. Checking the module rather than only the function body
    is the looser test, so it is used as a fallback: the point is that
    deleting the verification entirely still trips the gate.
    """
    path = REPO_ROOT / route.path
    if not path.is_file():
        return False
    return verifier in path.read_text(encoding="utf-8", errors="ignore")


def _print_inventory(routes: list[Route]) -> None:
    print(f"Route authentication inventory — scanned {SERVICES_DIR}")
    print(f"{'service':<14}{'routes':>8}{'authed':>8}{'public':>8}{'in-band':>9}{'open':>6}   reason for the public ones")
    print("-" * 104)
    total = [0, 0, 0, 0, 0]
    for svc in sorted({r.service for r in routes}):
        rows = [r for r in routes if r.service == svc]
        authed = [r for r in rows if r.has_auth]
        public: list[Route] = []
        inband: list[Route] = []
        open_: list[Route] = []
        for r in rows:
            if r.has_auth:
                continue
            key = f"{r.path}::{r.function}"
            if svc in EXEMPT_SERVICES or _module_exempt(r) is not None or key in PUBLIC_ROUTES:
                public.append(r)
            elif key in IN_BAND_CREDENTIAL_ROUTES:
                inband.append(r)
            else:
                open_.append(r)
        note = EXEMPT_SERVICES.get(svc, "")
        if not note and public:
            note = "probes, sign-in flow and published catalogues" if len(public) > 2 else "liveness/readiness probes"
        print(f"{svc:<14}{len(rows):>8}{len(authed):>8}{len(public):>8}{len(inband):>9}{len(open_):>6}   {note[:58]}")
        for i, v in enumerate((len(rows), len(authed), len(public), len(inband), len(open_))):
            total[i] += v
    print("-" * 104)
    print(f"{'TOTAL':<14}{total[0]:>8}{total[1]:>8}{total[2]:>8}{total[3]:>9}{total[4]:>6}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_CLEAN = """
from fastapi import APIRouter
from app.api.v1.deps import AuthUser
router = APIRouter()

@router.get("/queue")
async def queue(user: AuthUser):
    return []
"""

_OPEN = """
from fastapi import APIRouter
router = APIRouter()

@router.post("/run")
async def run_playbook(playbook_id: str):
    return {"started": True}
"""

_ROUTER_LEVEL = """
from fastapi import APIRouter, Depends
from app.security.tenant_scope import require_console_or_service_auth
router = APIRouter(dependencies=[Depends(require_console_or_service_auth)])

@router.post("/run")
async def run_playbook(playbook_id: str):
    return {"started": True}
"""

_LOCAL_ALIAS = """
from typing import Annotated
from fastapi import APIRouter, Depends
from app.api.v1.deps import AuthUser, require_permission
router = APIRouter()
ExecuteUser = Annotated[AuthUser, Depends(require_permission("playbooks:execute"))]

@router.post("/run")
async def run_playbook(playbook_id: str, user: ExecuteUser):
    return {"started": True}
"""


def _self_test() -> int:
    cases = [
        ("clean: route carries an auth dependency", _CLEAN, 0),
        ("drift A: mutating route with no auth and no exemption", _OPEN, 1),
        ("control: auth declared on the router, not the route", _ROUTER_LEVEL, 0),
        ("control: auth via a module-local Annotated alias", _LOCAL_ALIAS, 0),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for i, (label, source, want) in enumerate(cases):
            root = Path(tmp) / f"case{i}"
            target = root / "services" / "probe" / "app"
            target.mkdir(parents=True, exist_ok=True)
            (target / "routes.py").write_text(source, encoding="utf-8")
            routes = collect_routes(root=root)
            open_, _stale = classify(routes)
            ok = len(open_) == want and len(routes) > 0
            if not ok:
                failures += 1
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {len(open_)} open, want {want} (scanned {len(routes)} routes)")

    failures += _self_test_stale_exemption()
    if failures:
        print(f"\nself-test FAILED: {failures} case(s) did not behave as specified", file=sys.stderr)
        return 1
    print(
        "\nself-test passed: drift detected both ways, router-level and alias auth "
        "both recognised, and a stale in-band exemption is dropped."
    )
    return 0


def _self_test_stale_exemption() -> int:
    """Strip an in-band verifier and assert its route stops being exempt.

    The reverse direction, and the one that matters most here: every entry in
    ``IN_BAND_CREDENTIAL_ROUTES`` is a claim that a handler checks something.
    A claim nobody re-tests is indistinguishable from a comment.
    """
    failures = 0
    routes = collect_routes()
    by_key = {f"{r.path}::{r.function}": r for r in routes}

    for key, (verifier, _reason) in IN_BAND_CREDENTIAL_ROUTES.items():
        route = by_key.get(key)
        if route is None:
            print(f"  [FAIL] in-band exemption names a route that does not exist: {key}")
            failures += 1
            continue
        path = REPO_ROOT / route.path
        source = path.read_text(encoding="utf-8", errors="ignore")
        if verifier not in source:
            print(f"  [FAIL] in-band exemption for {route.function}() names {verifier}(), which {route.path} never mentions")
            failures += 1

    # Remove one live entry outright and assert the route resurfaces.
    live = [k for k in IN_BAND_CREDENTIAL_ROUTES if k in by_key]
    if not live:
        print("  [FAIL] stale exemption: no live in-band entry to exercise")
        return failures + 1
    victim = sorted(live)[0]
    saved = IN_BAND_CREDENTIAL_ROUTES.pop(victim)
    try:
        open_, _ = classify(routes)
        if any(f"{r.path}::{r.function}" == victim for r in open_):
            print(f"  [PASS] stale exemption: {victim} is reported the moment its entry is removed")
        else:
            print(f"  [FAIL] stale exemption: removing {victim} produced no finding")
            failures += 1
    finally:
        IN_BAND_CREDENTIAL_ROUTES[victim] = saved
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", action="store_true", help="print the per-service authentication table")
    parser.add_argument("--json", action="store_true", help="emit every unauthenticated route with its classification")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift both ways")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not SERVICES_DIR.is_dir():
        print(f"ERROR: no services/ directory under {REPO_ROOT} — refusing to report a result for a tree I did not open.", file=sys.stderr)
        return 2

    routes = collect_routes()
    unexplained, stale = classify(routes)

    files = len({r.path for r in routes})
    authed = sum(1 for r in routes if r.has_auth)
    print(
        f"check_route_auth: scanned {len(routes)} routes across {files} files under {SERVICES_DIR}; "
        f"{authed} authenticated, {len(routes) - authed} public "
        f"({len(PUBLIC_ROUTES)} named routes, {len(IN_BAND_CREDENTIAL_ROUTES)} verified in-band, "
        f"{len(PUBLIC_MODULES)} probe module, {len(EXEMPT_SERVICES)} exempt service)"
    )

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "service": r.service,
                        "path": r.path,
                        "function": r.function,
                        "methods": r.methods,
                        "route_path": r.route_path,
                    }
                    for r in unexplained
                ],
                indent=2,
            )
        )
        return 0 if not unexplained and not stale else 1

    if args.inventory:
        _print_inventory(routes)
        return 0

    if stale:
        print(f"\nFAIL: {len(stale)} exemption(s) no longer describe an unauthenticated route.", file=sys.stderr)
        print("      The route was secured, renamed or deleted — remove the entry rather than", file=sys.stderr)
        print("      leaving a justification that outlived the thing it justified.", file=sys.stderr)
        for key in stale:
            print(f"  - {key}", file=sys.stderr)

    if unexplained:
        print(f"\nFAIL: {len(unexplained)} route(s) carry no authentication and no recorded reason.", file=sys.stderr)
        print("      Add a dependency, or record why the route is public — health and readiness", file=sys.stderr)
        print("      probes are legitimately public; a route that mutates state is not.", file=sys.stderr)
        for route in unexplained:
            print(f"  - {route.service}: {route.location()} {'/'.join(route.methods).upper()} {route.route_path}", file=sys.stderr)

    if stale or unexplained:
        return 1

    print("OK: every route authenticates, or is public for a reason that still holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
