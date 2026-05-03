---
sidebar_position: 1
---

# Plugin Overview

AiSOC's plugin system lets the community extend the platform with new enrichers, actions, and connectors — all without forking the core.

## Plugin Types

| Type | Purpose | Example |
|------|---------|---------|
| **Enricher** | Add context to indicators (IP, domain, hash, email) | VirusTotal lookup, Shodan enrichment |
| **Action** | Execute response steps | Block IP in firewall, disable AD user, create Jira ticket |
| **Connector** | Ingest events from external sources | Pull Splunk alerts, Crowdstrike detections, AWS GuardDuty |

## Plugin Lifecycle

```
Author writes plugin
        │
        ▼
Sign with Ed25519 key (plugin-sdk sign)
        │
        ▼
Publish to community marketplace (plugin-sdk publish)
        │
        ▼
User installs from UI or API
        │
        ▼
Platform loads plugin at runtime — no restart needed
```

## Marketplace

The community marketplace is available at `/marketplace` in the UI. It indexes:

- **Plugins** — enrichers, actions, connectors
- **Detection rules** — community Sigma/YARA/KQL rules
- **Playbooks** — starter automation templates

The marketplace index is committed to the repo at `marketplace/index.json` and synced automatically via GitHub Actions on every release.

## Getting Started

Choose your SDK:

- [Python SDK](./python-sdk) — recommended for data enrichment and API integrations
- [Go SDK](./go-sdk) — recommended for high-throughput connectors

## Security Model

Every plugin must be signed with an Ed25519 keypair before publishing:

```bash
plugin-sdk sign --key ~/.aisoc/signing.key plugin.zip
```

The platform verifies the signature on install. Unsigned plugins are rejected.

## Community Guidelines

- Plugins must include a `README.md` and a `LICENSE` file
- Secrets (API keys, passwords) must be declared in `plugin.yaml` under `secrets:` — never hardcoded
- Plugins should handle errors gracefully and return typed error objects
- Performance-critical enrichers should implement caching

## Example `plugin.yaml`

```yaml
id: my-org/shodan-enricher
name: Shodan IP Enricher
type: enricher
version: 1.2.0
author: My Org <security@myorg.com>
description: Enriches IP indicators with Shodan host data
license: MIT

inputs:
  - name: ip
    type: string
    description: IPv4 or IPv6 address to enrich

outputs:
  - name: ports
    type: list[int]
  - name: vulns
    type: list[string]
  - name: country
    type: string

secrets:
  - name: SHODAN_API_KEY
    description: Your Shodan API key

runtime: python3.11
entrypoint: enricher:run
```
