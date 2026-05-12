---
sidebar_position: 2
title: MISP push (mirror STIX → MISP)
description: Mirror every STIX 2.1 indicator and bundle published by AiSOC into a downstream MISP instance, on demand or automatically.
---

# MISP push

The threat-intel service already **pulls** events from MISP (read-only).
The MISP push integration closes the loop: every STIX 2.1 indicator or
bundle published through `/api/v1/threatintel/stix/...` can be mirrored
into your MISP server as a native MISP event with one or more attributes.

The push runs from the API service (not `services/threatintel`) so it
shares:

- the same air-gap chokepoint (`enforce_airgap_for_url`) used by every
  other outbound HTTP call in the API,
- the same credential conventions (`MISP_*` env vars, never logged),
- the same HTTP timeout budget.

> **Air-gapped deployments.** When `AISOC_AIRGAPPED=1` (or the host is
> not on `AISOC_AIRGAP_ALLOWED_HOSTS`), every push attempt is rejected
> at the air-gap gate before any network I/O happens, and the failure
> is surfaced in the response under `misp.error`.

## Configuration

Add the following to your API service environment (or `.env`):

```bash
# Required
MISP_URL=https://misp.intel.corp
MISP_API_KEY=<your MISP user's API key>

# Optional — defaults shown
MISP_VERIFY_SSL=true
MISP_PUSH_AUTO=false           # mirror every indicator/bundle by default
MISP_PUSH_DEFAULT_DISTRIBUTION=0   # 0=org, 1=community, 2=connected, 3=all, 4=sharing-group
MISP_PUSH_DEFAULT_THREAT_LEVEL=2   # 1=high, 2=medium, 3=low, 4=undefined
MISP_PUSH_DEFAULT_ANALYSIS=1       # 0=initial, 1=ongoing, 2=completed
MISP_PUSH_TIMEOUT_SECONDS=15
```

`MISP_PUSH_AUTO=true` flips the default for every `POST /indicators`
and `POST /bundles` request — useful when AiSOC is the canonical source
of truth and MISP is a downstream consumer. With `MISP_PUSH_AUTO=false`
(the default), the caller opts in per request via `?push_to_misp=true`.

## Endpoints

### Publish an indicator and mirror it to MISP

```bash
curl -X POST \
  "$AISOC_URL/api/v1/threatintel/stix/indicators?push_to_misp=true" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Domain",
    "indicator_types": ["malicious-activity"],
    "pattern": "[domain-name:value = '\''secure-login.example-phish.com'\'']",
    "labels": ["phishing"],
    "confidence": 88
  }'
```

Response (truncated):

```json
{
  "type": "indicator",
  "id": "indicator--…",
  "pattern": "[domain-name:value = '…']",
  "misp": {
    "pushed": true,
    "misp_event_id": "4217",
    "misp_event_uuid": "5fa9c4d2-…",
    "url": "https://misp.intel.corp/events/view/4217"
  }
}
```

If the push fails (auth, 5xx, air-gap, network), the publish itself
still succeeds and `misp.pushed` is `false` with a structured `error`
field — the AiSOC store and the MISP mirror are intentionally decoupled.

### Publish a STIX bundle and mirror it as one MISP event

```bash
curl -X POST \
  "$AISOC_URL/api/v1/threatintel/stix/bundles?push_to_misp=true" \
  -H "Content-Type: application/json" \
  -d @bundle.json
```

The whole bundle becomes a single MISP event whose attributes are the
translatable indicators inside. STIX objects whose patterns can't be
mapped (e.g. complex `OR` predicates, custom observable types) are
counted in `misp.skipped_attributes` so you can audit coverage.

### Health check

```bash
curl "$AISOC_URL/api/v1/threatintel/stix/misp/health"
```

```json
{
  "configured": true,
  "airgapped": false,
  "auto_push": false,
  "url": "https://misp.intel.corp",
  "user": "aisoc-bot@intel.corp",
  "role": "User",
  "ok": true
}
```

The health probe calls MISP's `/users/view/me` so it both verifies
connectivity AND that the API key is still valid. The health response
never echoes the API key back.

### Dry run — preview the MISP event without sending

```bash
curl -X POST "$AISOC_URL/api/v1/threatintel/stix/misp/dry-run" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": {
      "name": "C2 IP",
      "pattern": "[ipv4-addr:value = '\''198.51.100.47'\'']",
      "indicator_types": ["malicious-activity"],
      "confidence": 92,
      "labels": ["c2", "apt-42"]
    }
  }'
```

```json
{
  "event": {
    "Event": {
      "info": "C2 IP",
      "distribution": "0",
      "threat_level_id": "2",
      "analysis": "1",
      "Attribute": [
        {"type": "ip-dst", "category": "Network activity", "value": "198.51.100.47", "to_ids": true}
      ],
      "Tag": [{"name": "tlp:amber"}, {"name": "aisoc:label=c2"}, {"name": "aisoc:label=apt-42"}]
    }
  },
  "attribute_count": 1,
  "skipped_count": 0,
  "would_push_to": "https://misp.intel.corp/events/add",
  "airgap_blocked": false
}
```

Dry run is the safest way to:

- tune the STIX → MISP mapping before flipping `MISP_PUSH_AUTO=true`,
- prove to a reviewer that an air-gapped deployment really will refuse
  to send (`airgap_blocked: true` with a populated `airgap_message`),
- diff event payloads between two AiSOC versions when changing
  pattern parsing.

## STIX → MISP mapping

| STIX pattern | MISP attribute type | MISP category |
|---|---|---|
| `[ipv4-addr:value = '…']` / `[ipv6-addr:value = '…']` | `ip-dst` | Network activity |
| `[domain-name:value = '…']` | `domain` | Network activity |
| `[url:value = '…']` | `url` | Network activity |
| `[email-addr:value = '…']` | `email-src` | Payload delivery |
| `[file:hashes.'MD5' = '…']` | `md5` | Payload delivery |
| `[file:hashes.'SHA-1' = '…']` | `sha1` | Payload delivery |
| `[file:hashes.'SHA-256' = '…']` | `sha256` | Payload delivery |
| `[file:hashes.'SHA-512' = '…']` | `sha512` | Payload delivery |
| `[file:name = '…']` | `filename` | Payload delivery |

STIX `confidence` is mapped onto MISP `threat_level_id` so an
indicator with `confidence ≥ 80` becomes `threat_level_id=1` (high),
`50–79` becomes `2` (medium), `1–49` becomes `3` (low), and `0` or
unset becomes `4` (undefined). STIX `labels` are mirrored as MISP
tags prefixed with `aisoc:label=…`.

## Failure modes

| Symptom | Likely cause | Where to look |
|---|---|---|
| `misp.pushed=false`, `error="MISP push not configured"` | `MISP_URL` or `MISP_API_KEY` missing | `/misp/health` |
| `misp.pushed=false`, `error="Air-gap policy blocked push: …"` | `AISOC_AIRGAPPED=1` and host not on the allow-list | `AISOC_AIRGAP_ALLOWED_HOSTS` |
| `misp.pushed=false`, `error="MISP returned 401 …"` | API key revoked or rotated | MISP → My Profile → Authentication |
| `misp.pushed=true` but event not visible in MISP UI | Distribution scope hides it from your role | `MISP_PUSH_DEFAULT_DISTRIBUTION` |

## Security notes

- The API key is read from environment / vault, never persisted, and
  never logged. Health and dry-run responses do not echo it back.
- Every outbound request runs through `enforce_airgap_for_url` so the
  push pipeline cannot be used to exfiltrate data from an air-gapped
  AiSOC deployment.
- The mirror is intentionally one-way. Pull from MISP still goes
  through the read-only `services/threatintel` client.
