# Air-gapped deployment

AiSOC ships with first-class support for fully air-gapped deployments — no
outbound HTTP, no LLM phone-home, no SaaS threat-intel feeds — for
customers in regulated, classified, or sovereign environments where
the SOC stack must run with **zero egress**.

This page is the operator runbook for that mode: what gets blocked, what
keeps working, how to verify it, and how to plug in local mirrors and a
local LLM.

## What air-gapped mode is (and isn't)

Air-gapped mode is **defense in depth**, not a substitute for an actual
egress firewall. Treat it as a second layer:

1. Your network policy at the perimeter denies all egress from the SOC
   subnet (this is the load-bearing control).
2. AiSOC's in-process airgap module refuses any outbound HTTP it would
   otherwise issue (this is the loud-failure layer that catches a
   misconfigured `.env`, a vendored client with a hard-coded URL, or a
   forgotten `OPENAI_API_KEY`).

When the in-process check fires it logs a structured `airgap.block`
event with the offending URL and refuses the request before it ever
hits a socket. That's the signal you want in your audit trail.

## Turning it on

Set two environment variables on every AiSOC service that issues outbound
HTTP (`api`, `agents`, `threatintel`, `actions`, `enrichment`):

```bash
AISOC_AIRGAPPED=1
AISOC_AIRGAP_ALLOWLIST=mirror.example.internal,intel.corp
```

Defaults:

- `AISOC_AIRGAPPED` — `false`. The default deployment is **not** air-gapped;
  the policy module is a no-op until you opt in.
- `AISOC_AIRGAP_ALLOWLIST` — empty list. Each entry is a hostname (with
  optional port). Subdomains of an entry are also allowed, so
  `intel.example.com` covers `misp.intel.example.com`. The parent
  `example.com` is **not** widened — we never match upward.

Restart the affected services. There is no migration, no DB change.

## What gets blocked vs. what keeps working

### Always allowed under `AISOC_AIRGAPPED=1`

These are considered "internal by definition" and never need to be in the
allowlist:

- RFC1918 / RFC4193 / loopback / link-local IP literals — `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `127.0.0.0/8`, `::1`,
  `169.254.0.0/16`, etc.
- Hostnames ending in `.local`, `.internal`, `.lan`, `.intranet`,
  `.corp`, `.home`, `.localdomain`, or exactly `localhost`.
- Single-label hostnames with no dots (e.g. `opensearch`, `redpanda`,
  `ollama`) — these are docker-compose / Kubernetes service names and
  cannot route off-cluster.

### Blocked unless allowlisted

- All public DNS names — `api.openai.com`, `api.anthropic.com`,
  `otx.alienvault.com`, `www.cisa.gov`, `www.virustotal.com`, etc.
- IP literals that resolve as public.

### Refused at registration time, not at request time

The threat-intel service goes one step further than just refusing
outbound calls: feeds whose configured URL is public and not on the
allowlist are **never registered with the scheduler** when air-gapped
mode is on. That means there is no boot-time DNS lookup, no failed-poll
pattern, and no 30-minute heartbeat that would otherwise leak
"an AiSOC instance lives at this egress IP." See
`services/threatintel/app/main.py` for the exact registration guards.

## Verifying it's on

Each service exposes its current air-gap policy snapshot on its health
endpoint. This is the cheapest way for an auditor to confirm the policy
is engaged on every pod.

### API service

```bash
curl -s http://aisoc-api.internal/health | jq .airgap
{
  "enabled": true,
  "allowlist": ["mirror.example.internal", "intel.corp"],
  "implicit_private_suffixes": [".local", ".internal", ".lan", ".intranet",
                                 ".corp", ".home", ".localdomain", "localhost"],
  "policy": "All outbound HTTP is blocked except to private/loopback/..."
}
```

### Threat-intel service

```bash
curl -s http://aisoc-threatintel.internal/health | jq .airgap
{
  "enabled": true,
  "allowlist": ["mirror.example.internal", "intel.corp"]
}
```

If `enabled: false` shows up on any pod after you set `AISOC_AIRGAPPED=1`,
that pod is missing the env var — fix that before signing off.

### Dedicated audit endpoint

The API service also exposes a dedicated, unauthenticated, machine-readable
snapshot at `GET /api/v1/airgap/status` for ops tooling and auditor
checklists that want the policy without parsing the rest of the health
envelope:

```bash
curl -s http://aisoc-api.internal/api/v1/airgap/status | jq
{
  "enabled": true,
  "allowlist": ["mirror.example.internal", "intel.corp"],
  "implicit_private_suffixes": [".local", ".internal", ".lan", ".intranet",
                                 ".corp", ".home", ".localdomain", "localhost"],
  "policy": "All outbound HTTP is blocked except to private/loopback/..."
}
```

The endpoint returns no secrets — only the boolean `enabled` flag, the
operator-supplied allowlist, the implicit private suffixes, and a
human-readable `policy` field suitable for embedding in audit reports.

## Plugging in a local LLM

AiSOC's investigator agent, NL detection authoring, NL query, phishing
triage, and detection-loop helpers all call out to an LLM by default
(OpenAI-compatible chat completions). For air-gapped deployments, point
those at a local OpenAI-compatible server — Ollama, vLLM, Llama.cpp's
`server`, LiteLLM, or Cloudflare's local AI Gateway all work.

Example (Ollama running on the same node):

```bash
LLM_BASE_URL=http://ollama:11434/v1
LLM_API_KEY=not-used-but-required-by-client
LLM_MODEL=llama3.1:70b-instruct
```

Because `ollama` is a single-label hostname, the airgap module classifies
it as private and lets the call through. No allowlist entry needed.

If you run a shared internal LLM gateway under a real DNS name
(`llm.corp`), it'll match the `.corp` suffix automatically. If it lives
under a public-looking suffix (`llm.example.com`) you must add it to
`AISOC_AIRGAP_ALLOWLIST`.

When the LLM endpoint is unreachable or refused by airgap policy, every
LLM-using endpoint falls back to a heuristic / template path so the
SOC keeps working with degraded output rather than failing closed. See
`services/api/app/api/v1/endpoints/translation.py`,
`nl_detection.py`, `nl_query.py`, and `phishing.py` for the pattern.

## Plugging in a local threat-intel mirror

The threat-intel service ships clients for AlienVault OTX, CISA KEV,
TAXII 2.x, and MISP. For air-gapped operation, host an internal mirror
of whichever feeds your security program is licensed for and point the
clients at it:

```bash
# CISA KEV — mirror the JSON internally
AISOC_AIRGAP_ALLOWLIST=kev-mirror.internal

# TAXII 2 — your own STIX2 server
TAXII_URL=https://taxii.intel.corp/taxii2/
TAXII_API_ROOT=intel
TAXII_COLLECTION_IDS=indicators

# MISP — your own MISP instance
MISP_URL=https://misp.intel.corp
MISP_API_KEY=…

# OTX has no internal mirror; leave OTX_API_KEY unset to keep the OTX
# feed disabled cleanly. Setting it under air-gapped mode will be
# refused at registration time.
```

When `AISOC_AIRGAPPED=1`, the scheduler logs a structured
`airgap.feed_blocked` event for each feed it refuses to register and
keeps running with the remaining ones.

## Operator audit checklist

Before signing off an air-gapped deployment, walk this checklist:

- [ ] `curl http://aisoc-api/health` returns `airgap.enabled: true`
- [ ] `curl http://aisoc-threatintel/health` returns
  `airgap.enabled: true`
- [ ] Egress firewall denies all outbound from the SOC subnet
- [ ] LLM endpoint is internal (`LLM_BASE_URL` resolves to RFC1918, a
  private suffix, or a single-label service name)
- [ ] No `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in the environment
  unless they point at an internal gateway
- [ ] All threat-intel feed URLs in the env are either internal or
  explicitly listed in `AISOC_AIRGAP_ALLOWLIST`
- [ ] Logs show zero `airgap.block` events under steady-state load
  (any block under steady-state means a code path is still attempting
  egress and should be investigated)

## Trade-offs

Operators should know what they're giving up:

- **No live OTX / VirusTotal / community TI** — your enrichment is only
  as fresh as your internal mirror cadence.
- **No external LLM** — quality depends entirely on the local model.
  AiSOC's eval harness is the right gate here: re-run
  `scripts/run_evals.py` against your local LLM before promoting it to
  production.
- **No outbound webhooks** — the `actions` service can still notify
  internal Slack / Teams / mail relays, but external SaaS notifiers
  (PagerDuty, Opsgenie, etc.) need to go through an internal egress
  proxy that you've allowlisted.

The air-gap policy is intentionally strict on the "loud failure" axis;
relax individual hosts via the allowlist rather than disabling the
feature entirely.
