# ADR-0007: `connectors` and `actions` belong in the CORE profile

- **Status:** accepted
- **Date:** 2026-09-26
- **Supersedes:** the `profiles: ["full"]` marking on `connectors` and the `profiles: ["full", "chatops"]` marking on `actions` in `docker-compose.yml`
- **Related:** [ADR-0006](./0006-llm-gateway-in-core.md), which moved the LLM gateway and then the local model into CORE on the same kind of reasoning and with the same method of measurement

## Context

Gap-closure Phase 4 gives the investigation agent tools that reach the
customer's own SIEM and EDR rather than only AiSOC's event lake. The plan
that asks for it also records why the work is close to pointless on the
default profile:

> On the default CORE profile the agent has no evidence source at all: the
> lake, the graph, `connectors` and `actions` all run in `full`.

Two of those four are this ADR's subject. The plan requires a measured answer
rather than an opinion, and it forbids adding a container to CORE without one:
CORE needs 8 GB, and every service in it is paid for by every self-hoster.

There is a sharper version of the problem than "a feature is absent". CORE
already **configures** both services and then does not start them. `api` in
`docker-compose.yml` carries
`CONNECTORS_SERVICE_URL: http://connectors:8003` and
`AISOC_ACTIONS_BASE_URL: http://actions:8085`, and
`AISOC_FEATURE_FED_SEARCH` defaults to `True` in
`services/api/app/core/config.py`. So on the profile `make up` starts, the
federated-search route is enabled and fans out to a hostname that does not
resolve, and the live-actions proxy answers 502 with a message that names the
profiles an operator would have to switch to. The capability is not switched
off in CORE. It is switched on and pointed at nothing.

## What was measured, rather than assumed

Same method as ADR-0006, on the same class of machine: images pulled from
GHCR, resident memory read with `docker stats --no-stream`.

Host: macOS, Docker Engine 29.5.2, 15.58 GiB available to the engine.
Images pulled fresh on 2026-09-26.

| | Image on disk | Cold-start idle, 45 s after boot | Serving 100 requests | Steady state, 40 h uptime |
|---|---|---|---|---|
| `aisoc-actions` | **539 MB** | **45.99 MiB** | 46.3 MiB | **48.3 MiB** |
| `aisoc-connectors` | **586 MB** | **71.45 MiB** | 71.98 MiB | **76.51 MiB** |
| **both** | **1.13 GB** | **117.4 MiB** | 118.3 MiB | **124.8 MiB** |

For scale, measured on the same host in the same run:

| Service already in CORE | Resident |
|---|---|
| `litellm` | 471.1 MiB |
| `agents` | 223.7 MiB |
| `api` | 213.9 MiB |
| `web` | 86.2 MiB |
| `fusion` | 58.1 MiB |

The `litellm` figure is the useful cross-check: ADR-0006 measured it at
451 MiB and this run reads 471 MiB, so the method reproduces within about 4%.

Two properties were verified rather than assumed, because ADR-0006's mistake
was moving a gateway that then had no model behind it:

- **Both boot and serve with no configuration.** `actions` answers `/health`
  with 200 and `GET /api/v1/live-actions` with 200 and its full capability
  list. `connectors` answers `GET /api/v1/connectors` with 200 and all **84**
  connectors. Neither needs a credential, a vendor account or a key to reach
  a serving state, so adding them cannot break a keyless install.
- **The idle figure is not hiding a serving spike.** This was the trap in
  ADR-0006: `ollama` idles at 9.6 MiB and measures 2.96 GiB while running
  inference, so its idle number was the misleading half of the truth. Neither
  service here moves more than 0.6 MiB under 100 requests. They are network
  front ends over vendor HTTP APIs, and they hold no model and no index.

**124.8 MiB is 1.5% of CORE's 8 GB budget.** The 1.13 GB of image is 5.6% of
the 20 GB disk figure CORE already publishes.

## Decision

**Move `connectors` and `actions` into CORE**, by deleting their `profiles:`
keys so they start with `docker compose up` and `make up`.

`actions` keeps no profile list at all rather than keeping `chatops`: a
service in no profile is included in every profile run, so `chatops` still
gets it and `slack-bot`'s dependency still renders.

### Why not keep both in `full`

Because the alternative to adding them is not "CORE stays lean". It is
"CORE keeps advertising a capability it cannot perform". An evaluator
following the documented first run reaches the federated-search page and the
live-actions surface and gets a 502 naming two compose profiles. Fixing that
by *removing* the configuration would be honest, but it trades a broken
capability for an absent one, and it would leave Phase 4's agent tools
reachable only on a profile the quickstart does not describe.

The measured price of not making that trade is 1.5% of the budget.

### Why not a module inside an existing service

The plan says to prefer a module inside an existing service where that is the
honest answer, and here it is not.

`services/actions` owns twenty-three vendor clients, the executor registry,
the credential-key translation at the dispatch boundary and the blast-radius
gate. `services/connectors` owns the 84-connector registry, each connector's
`normalize()` and the poll scheduler. A module in the API reproducing either
would be a second copy of the thing that decides what a customer's Splunk row
means or what may be done to their estate, and this repository has paid for
second copies of exactly these two several times: a dry-run credential-strip
list that had drifted from what the client factory read, a bundled connector
catalog that was wrong by 58 entries for as long as nobody compared it by
hand, and a capability mirror that needs a CI check to stay in step.

The honest answer is that these are already the right two services. What was
wrong was the profile they were declared in.

### Why not start them conditionally

ADR-0006 rejected a Makefile conditional for two reasons that apply
unchanged: it relocates the manual step rather than removing it, and it makes
`make up` and `docker compose up` disagree about what is running. A condition
here would also be unanswerable, because the thing it would test, whether
this tenant has a vendor connector, is a database row that does not exist until
after the stack is up.

## Consequences

- CORE goes from **14 services to 16**. `full` stays at 22, because both
  services were already in it. Verified with `docker compose config
  --services` on both profiles, and with `--profile chatops` to confirm
  `actions` is still there for `slack-bot`. The README profile table is
  corrected rather than left stale.
- The README's RAM figure stays at **~8 GB**. 124.8 MiB does not move a
  figure published to one significant figure, and inflating it to ~8.2 GB
  would imply a precision the other rows do not have. The disk figure stays
  at 20 GB for the same reason: 1.13 GB against 20 GB.
- Federated SIEM search and the live-actions surface work on the default
  profile the moment a tenant configures a connector, with no profile change.
- **What an evaluator with no vendor account gains is the path, not the
  data.** Both surfaces still show nothing until a real Splunk, Sentinel,
  Elastic, QRadar, CrowdStrike, Defender, Okta, SentinelOne, Entra or Google
  Workspace credential is saved. Phase 4's tool advertisement is scoped to
  the tenant's configured backends, so on a fresh CORE install the agent is
  offered no customer tools and says so. That is the honest behaviour and it
  is unchanged by this ADR. The difference is that configuring a vendor now
  works on CORE instead of requiring a profile switch nobody was told about.
- The connector poll scheduler now runs on the default profile. It is
  per-instance and there are no instances in a fresh install, so it schedules
  nothing until an operator saves a connector. That is the same trigger the
  `full` profile has always used.

## What this ADR does not decide

**The lake and the graph stay in `full`.** They are the other half of the
sentence quoted at the top and they are not in scope here, for a reason that
the numbers above make concrete rather than for convenience: ClickHouse and
Neo4j are stateful stores with their own memory floors, not network front
ends, so they are a different decision needing its own measurement. The
consequence is recorded plainly so nobody reads this ADR as having closed the
whole gap: after this change a CORE deployment's investigation agent can
reach a configured vendor and still cannot reach an event lake, because there
is no event lake in CORE. The eleven lake pivots report that their data class
is not available, which is the behaviour Phase 4's tool handling requires and
is not the same thing as an empty result.
