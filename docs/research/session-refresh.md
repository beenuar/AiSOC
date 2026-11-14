# Browser session renewal

Research date: 2026-11-11. Baseline: `8a06f2eb51cd9f9386b840061070c92bf18c89f0`.

## Observed failure

The console saves both tokens from password, SSO and MFA sign-in, but never
calls `POST /api/v1/auth/refresh`. Its JSON client deletes both credentials on
the first protected request returning 401. With the default 30-minute access
lifetime, a seven-day refresh token is discarded while it can still renew the
session. The raw-response client does not renew either. The desktop and
responder session guards also reject expired access without considering refresh.

The API refresh handler already verifies signature, expiry, token type, active
user and session revocation against the database. Issuing a new pair does not
consume the previous refresh token. This change must preserve those checks and
must not increase either token lifetime.

## Reference and decision

| Implementation | Evidence | Decision |
| --- | --- | --- |
| AiSOC browser client and API | `apps/web/src/lib/api.ts`, `services/api/app/api/v1/endpoints/auth.py`, `services/api/app/core/security.py`; MIT | Extend the existing fetch client and endpoint contract. |
| axios-auth-refresh 5.0.2 | Commit `985a91a79c3b51cc08c948ee38283115a64a4d3e`; MIT | Reference the coordination design only; adopting it would introduce Axios into a fetch client. |

The upstream search was scoped to browser refresh coordination. The inspected
[source](https://github.com/Flyrell/axios-auth-refresh/blob/985a91a79c3b51cc08c948ee38283115a64a4d3e/src/utils.ts)
caches a refresh promise in `createRefreshCall`, queues waiting requests, marks
replays to prevent recursive interception, and clears the cache after completion.
Its [license](https://github.com/Flyrell/axios-auth-refresh/blob/985a91a79c3b51cc08c948ee38283115a64a4d3e/LICENSE)
was checked. No source is copied and no dependency is added.

## Intended behavior

- JSON and raw-response requests use one session-aware transport. Renew on
  access expiry or a protected 401, then replay at most once with the current
  credential. Preserve method, body, tenant, headers and cancellation.
- Concurrent calls share the refresh attempt. A late failure for an older
  credential cannot erase a newer session; an outstanding refresh cannot undo
  an explicit logout or replace a newly signed-in user.
- An authoritative refresh rejection ends the session. Network errors, rate
  limits, server failures and malformed success responses remain errors without
  destroying recoverable credentials. Permission refusals do not trigger refresh.
- Sign-in challenges and independently supplied authorization do not renew or
  clear the stored session. UI guards recognize a usable refresh token as a
  recoverable session; actual authentication remains a server decision.
- The responder uses the same JWT validity decision instead of allowing its
  legacy expiry cache to overrule a renewed access token.

## Verification and boundaries

The web suite passes 1,194 tests across 122 files, including concurrent and late
responses, rejected and transient refresh failures, malformed token responses,
raw bodies, prompt cancellation and changed sessions. TypeScript and the
production build pass. ESLint reports no errors and the same 95 warnings as the
baseline, compared by file, rule, severity and diagnostic. The Python lint/format and mypy baseline gates
pass. The API session lifecycle suite passes all 10 tests against PostgreSQL,
including inactive users, expired credentials and explicit session revocation.

`scripts/check_session_refresh_live.mjs` imports the production client and sends
real HTTP requests to the API with its actual PostgreSQL database. Four
concurrent requests share one refresh; raw responses remain unread; a server
401 is refreshed and replayed; an invalid refresh token ends the session. The
same command fails with the baseline client and passes again with the fixed
client. The fixture comes from an isolated account, with a deliberately expired
access JWT signed by that test API; its credentials are not committed.

This client check uses Node 22.23.4 and simulated browser storage/navigation,
not a rendered browser. The API runs Python 3.11.18, its locked dependencies and
PostgreSQL 17.11 as the runtime role without RLS bypass. The API application is
real, but its lifespan workers are disabled to avoid unrelated service startup.
It is not a full product-stack or operator-deployment validation.

The route gate exposed a pre-existing missing proxy rule for the Explain
stream while these calls moved onto the shared transport. The exact route is
now forwarded to the agents service before the core API catch-all. The route
and wire-contract gates pass with the API and agents importable; their own
documented coverage limits remain unchanged.
