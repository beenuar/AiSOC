# OrcaRouter Cyber Inference

[OrcaRouter](https://www.orcarouter.ai) is an OpenAI-compatible model gateway.
AiSOC exposes it as a first-class per-tenant provider, so a workspace can route
triage, investigation, reports and the explain path through it without changing
any other setting.

* Cyber-tier overview: <https://www.orcarouter.ai/cyber>
* Model catalog: <https://www.orcarouter.ai/models?tier=cyber>
* Inference base URL: `https://api.orcarouter.ai/v1`
* Authentication origin: `https://www.orcarouter.ai`

The two origins are different on purpose. Authentication answers on `www` at
`/auth` and `/api/v1/auth/keys`; inference answers on `api` under `/v1`.
Neither is derived from the other by swapping a hostname — `api.orcarouter.ai/
v1/auth/keys` is a 404.

## Configure it

Settings → **Deployment & AI** → **Configure BYOK**, then pick one of the two
OrcaRouter entries under Provider.

**API key.** Paste a key beginning with `sk-orca-`. It is encrypted with the
platform credential vault before it is stored and is never returned to the
browser.

**Connect with OrcaRouter.** OAuth 2.0 with PKCE (S256), using the
out-of-band flow. AiSOC opens the consent screen; you approve access and paste
the code it shows back into the panel. Out-of-band is used because a
self-hosted AiSOC has no predictable callback address and the API runs in a
container, where a browser loopback redirect cannot arrive.

Either path stores the same durable key in the same per-tenant row, so the rest
of the product does not need to know which one minted it. The connect flow
keeps the PKCE verifier server-side only, in `orcarouter_connect_states`,
deletes the attempt before the code is exchanged (single use), and compares
the `state` in constant time. The code is valid for ten minutes.

## Choose a model

The Model field is a dropdown filled from OrcaRouter's own catalog, fetched
server-side with `?capability=chat` and filtered to models that can serve a
text chat completion — an embedding-only or image-generation id never appears.
Above the catalog the panel offers the provider's routing ids in this order:

| Model | Role |
| --- | --- |
| `orcarouter/auto` | Default. Provider-side routing. |
| `orcacyber-ultra-1.0` | OrcaCyber Ultra — recommended for cyber work. |
| `orcacyber-zero-1.5` | OrcaCyber Zero — recommended for cyber work. |
| `orcarouter/fusion` | General-purpose fallback. |

If live discovery fails, the panel says so and shows a verified fallback list
instead. The two lists are never merged: an entry under "Available models" came
from the provider, and an entry under "Verified fallback models" did not.

## Re-authentication

The key issued by both flows is durable and there is no refresh grant. When
OrcaRouter answers 401 or 403, AiSOC marks that exact credential generation as
needing re-authentication and the panel shows **Re-authentication needed**.
Nothing rotates silently; reconnect or paste a new key. A late failure from an
older key cannot mark a newer one.

## Self-hosted deployments

Leave these unset to use the public origins. They exist only for deployments
that run OrcaRouter themselves, and HTTPS is required except for loopback.

| Variable | Meaning |
| --- | --- |
| `ORCAROUTER_AUTH_BASE_URL` | Authentication origin override. |
| `ORCAROUTER_API_BASE_URL` | Inference origin override. |
| `ORCA_BASE_URL` | One origin for both, used only when the two above are unset. |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/llm/orcarouter/connect/start` | Mint a PKCE attempt; returns the consent URL and `state`. |
| `POST` | `/api/v1/llm/orcarouter/connect/finish` | Redeem the out-of-band code and store the key. |
| `POST` | `/api/v1/llm/orcarouter/models` | Chat-capable catalog for this credential. |

The existing `PUT /api/v1/llm/credentials` accepts `orcarouter` and
`orcarouter-oauth` as providers and fills in the fixed base URL and default
model.
