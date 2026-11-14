# Cyble AiSOC — Integration Matrix & Connector Specifications

**Version:** 2.0 | **Date:** May 2026
**Last updated:** 2026-05-20
**Production version:** v7.3.1 (github.com/beenuar/AiSOC)
**Connector catalog:** 50 vendors (v8.0 wave-1 adds 16 new; wave-2 fixtures added for future activation)
**Part of:** [cyble-aisoc-plan.md](../cyble-aisoc-plan.md)

---

## Changelog

| Date | Change |
|---|---|
| 2026-05-20 | Cross-tenant connector isolation tests added to CI (PR #197) |
| 2026-05-19 | v8.0 wave-1: 6 new connectors shipped (tines, torq, falco, pagerduty, opsgenie, confluence_audit) |
| 2026-05-19 | v8.0 wave-2 fixtures added (cloudflare_zt, sysdig, vault, snowflake) — not yet activated |
| 2026-05-19 | Connector SSRF guard: all outbound HTTP via `ssrf_guard.py` with cloud-metadata block list |
| 2026-05-19 | Connector `callback_url` SSRF CVE fixed |
| 2026-05 | 50-vendor click-and-connect catalog shipped (v7.x line) |
| 2026-04 | Initial integration matrix (v1.0, 20 tools, prototype) |

---

## Overview

AiSOC's connector architecture uses a uniform Python ABC (`BaseConnector`) so that every integration exposes the same tool IDs to the agent layer. Connectors live in `services/connectors/` and are loaded dynamically. Adding a new connector = implement `BaseConnector`, drop the file in, and register in `connector.registry.json`.

```python
class BaseConnector(ABC):
    vendor: str
    risk_class: Literal["READ","WRITE-REVERSIBLE","WRITE-SIGNIFICANT","DESTRUCTIVE"]

    async def test_connection(self) -> bool: ...
    async def call(self, tool_id: str, params: dict) -> ToolResult: ...
```

All connectors:
- Authenticated per-tenant (credentials stored in PostgreSQL `connector_credentials` table, encrypted at rest)
- Rate-limit aware (exponential backoff, jitter)
- SSRF-guarded (all outbound HTTP goes through `ssrf_guard.py`)
- Traced (every call logged with params, result, latency, tenant_id)
- Graceful degradation: if a connector is down, agents note the gap and continue without it

---

## Tier 1 — Day 1 Integrations (production-shipped, v7.x)

### SIEM (Security Information & Event Management)

| Integration | Risk class | Auth | Key tools exposed to agents | Graceful degradation |
|---|---|---|---|---|
| **Splunk Enterprise / Cloud** | READ / WRITE-REVERSIBLE | Token | `siem.query_spl`, `siem.get_raw_events`, `siem.timeline_query`, `siem.notable_events` | Raw event from ingest pipeline |
| **Microsoft Sentinel** | READ / WRITE-REVERSIBLE | OAuth2 (client_credentials) | `siem.query_kql`, `siem.get_incidents`, `siem.update_incident`, `siem.timeline_query` | OpenSearch fallback |
| **IBM QRadar** | READ | AQL token | `siem.query_aql`, `siem.get_offenses`, `siem.get_events` | Raw event from ingest pipeline |
| **Elastic SIEM** | READ | API key | `siem.query_esql`, `siem.get_alerts`, `siem.get_timelines` | OpenSearch fallback |
| **Chronicle / Google SecOps** | READ | Service account JSON | `siem.query_udm`, `siem.get_rule_detections` | Raw event from ingest pipeline |

### EDR / XDR

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **CrowdStrike Falcon** | READ + WRITE-REVERSIBLE + WRITE-SIGNIFICANT | OAuth2 | `edr.get_process_tree`, `edr.get_network_connections`, `edr.contain_host`, `edr.get_file_events`, `edr.quarantine_file` | Alert metadata only |
| **SentinelOne** | READ + WRITE-REVERSIBLE + WRITE-SIGNIFICANT | API key | `edr.get_process_tree`, `edr.isolate_endpoint`, `edr.quarantine_file`, `edr.get_threats` | Alert metadata only |
| **Microsoft Defender for Endpoint** | READ + WRITE-REVERSIBLE | OAuth2 | `edr.get_process_tree`, `edr.isolate_device`, `edr.get_alerts`, `edr.stop_and_quarantine` | Alert metadata only |
| **Palo Alto Cortex XDR** | READ + WRITE-REVERSIBLE | API key + key id | `edr.get_incidents`, `edr.get_file_events`, `edr.isolate_endpoint` | Alert metadata only |
| **VMware Carbon Black** | READ + WRITE-REVERSIBLE | API token | `edr.get_processes`, `edr.isolate_device`, `edr.ban_hash` | Alert metadata only |
| **Elastic Defend** | READ | API key | `edr.get_process_tree`, `edr.get_network_events` | OpenSearch fallback |

### Identity (IDP)

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **Okta** | READ + WRITE-REVERSIBLE | API token / OAuth2 | `idp.get_user_risk`, `idp.get_user_sessions`, `idp.revoke_sessions`, `idp.get_auth_logs`, `idp.suspend_user` | Session revocation skipped |
| **Microsoft Entra ID (Azure AD)** | READ + WRITE-REVERSIBLE | OAuth2 (MSAL) | `idp.get_user_info`, `idp.get_sign_ins`, `idp.revoke_sessions`, `idp.disable_account`, `idp.get_risky_users` | Session revocation skipped |
| **Google Workspace** | READ + WRITE-REVERSIBLE | OAuth2 service account | `idp.get_user_sessions`, `idp.revoke_oauth_tokens`, `idp.get_login_activity` | Session revocation skipped |
| **Ping Identity** | READ + WRITE-REVERSIBLE | OAuth2 | `idp.get_user_risk`, `idp.revoke_sessions` | Session revocation skipped |

### Cyble-Native CTI (the moat)

| Tool | Description | Risk class |
|---|---|---|
| `cti.ioc_lookup` | Cyble Vision IOC reputation (IP, hash, domain, URL) | READ |
| `cti.darkweb_search` | Cyble darkweb intelligence search | READ |
| `cti.asm_lookup` | Attack surface monitoring — exposed asset lookup | READ |
| `cti.brand_lookup` | Brand impersonation / typosquat detection | READ |
| `cti.vuln_lookup` | Vulnerability intelligence + exploit availability | READ |

### Cloud Providers

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **AWS (GuardDuty + CloudTrail + SecurityHub)** | READ | IAM role (assume role) | `cloud.get_guardduty_findings`, `cloud.query_cloudtrail`, `cloud.get_securityhub_findings` | Alert metadata only |
| **Azure (Defender for Cloud + Entra logs)** | READ | Service principal | `cloud.get_defender_alerts`, `cloud.get_audit_logs`, `cloud.get_activity_logs` | Alert metadata only |
| **GCP (Security Command Center + Cloud Audit)** | READ | Service account | `cloud.get_scc_findings`, `cloud.query_audit_logs` | Alert metadata only |

### Ticketing / ITSM

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **Jira** | WRITE-REVERSIBLE | API token (Basic) | `ticket.create_issue`, `ticket.update_issue`, `ticket.get_issue`, `ticket.add_comment` | Slack notification fallback |
| **ServiceNow** | WRITE-REVERSIBLE | OAuth2 | `ticket.create_incident`, `ticket.update_incident`, `ticket.close_incident` | Slack notification fallback |
| **PagerDuty** *(wave-1, 2026-05-19)* | WRITE-REVERSIBLE | API token | `ticket.create_incident`, `ticket.acknowledge`, `ticket.resolve`, `ticket.escalate` | Slack notification fallback |
| **OpsGenie** *(wave-1, 2026-05-19)* | WRITE-REVERSIBLE | API key | `ticket.create_alert`, `ticket.acknowledge`, `ticket.close` | Slack notification fallback |

### Communications / ChatOps

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **Slack** | WRITE-REVERSIBLE | Bot token (xoxb) | `comms.send_message`, `comms.create_thread`, `comms.send_hitl_request`, `comms.get_approval` | Email notification fallback |
| **Microsoft Teams** | WRITE-REVERSIBLE | App registration + Bot | `comms.send_card`, `comms.send_hitl_request`, `comms.get_approval` | Email notification fallback |

### Email Security

| Integration | Risk class | Auth | Key tools | Graceful degradation |
|---|---|---|---|---|
| **Proofpoint TAP** | READ | Service principal | `email.get_clicks`, `email.get_messages`, `email.get_vap` | Alert title/sender only |
| **Microsoft Defender for Office 365** | READ + WRITE-REVERSIBLE | OAuth2 | `email.get_threat_explorer`, `email.soft_delete_message`, `email.get_submissions` | Alert title/sender only |
| **Mimecast** | READ | OAuth2 | `email.get_siem_logs`, `email.get_message_info` | Alert title/sender only |

---

## Tier 2 — Deep Integrations (production-shipped, v7.x)

### Data Platforms

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Snowflake** *(wave-2 fixture, not yet activated)* | READ | Key-pair JWT | `data.query_sql`, `data.list_schemas` |
| **Databricks** | READ | Personal access token | `data.query_sql`, `data.list_catalogs` |

### VCS / DevOps

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **GitHub** | READ | App installation token | `vcs.get_audit_log`, `vcs.get_secret_scan_alerts`, `vcs.get_code_scan_alerts`, `vcs.get_push_events` |
| **GitLab** | READ | Personal access token | `vcs.get_audit_events`, `vcs.get_vulnerabilities` |
| **Bitbucket** | READ | OAuth2 | `vcs.get_audit_log` |

### Container / Infrastructure Security

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Falco** *(wave-1, 2026-05-19)* | READ | gRPC / HTTP | `container.get_runtime_alerts`, `container.get_policy_violations` |
| **Sysdig** *(wave-2 fixture)* | READ | API token | `container.get_threats`, `container.get_policy_events` |
| **Aqua Security** | READ | API key | `container.get_runtime_events`, `container.get_image_scan` |
| **Wiz** | READ | Client credentials | `cloud.get_issues`, `cloud.get_vuln_findings`, `cloud.get_misconfigs` |
| **Orca Security** | READ | API token | `cloud.get_alerts`, `cloud.get_attack_paths` |

### Network Security

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Palo Alto Panorama / NGFW** | READ + WRITE-REVERSIBLE | XML API key | `network.get_threat_logs`, `network.block_ip` |
| **Zscaler** | READ + WRITE-REVERSIBLE | API key | `network.get_web_security_logs`, `network.block_url` |
| **Fortinet FortiGate** | READ + WRITE-REVERSIBLE | REST API token | `network.get_intrusion_events`, `network.block_ip` |
| **Cloudflare Zero Trust** *(wave-2 fixture)* | READ + WRITE-REVERSIBLE | API token | `network.get_gateway_logs`, `network.block_policy`, `network.get_dlp_events` |

### Vulnerability Management

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Tenable** | READ | API keys | `vuln.get_assets`, `vuln.get_vulnerabilities`, `vuln.get_exploitability` |
| **Qualys** | READ | Basic auth | `vuln.get_host_vulns`, `vuln.get_patch_status` |
| **Rapid7 InsightVM** | READ | API key | `vuln.get_assets`, `vuln.get_vulnerabilities` |

### Automation / SOAR

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Tines** *(wave-1, 2026-05-19)* | WRITE-REVERSIBLE | API token | `soar.trigger_story`, `soar.get_run_result`, `soar.list_stories` |
| **Torq** *(wave-1, 2026-05-19)* | WRITE-REVERSIBLE | API key | `soar.trigger_workflow`, `soar.get_workflow_status` |
| **Splunk SOAR (Phantom)** | WRITE-REVERSIBLE | API token | `soar.run_playbook`, `soar.get_container` |

### Knowledge / Docs

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **Confluence (Audit)** *(wave-1, 2026-05-19)* | READ | API token | `docs.get_audit_events`, `docs.search_pages` |
| **Confluence (Runbook RAG)** | READ | API token | `docs.search_runbooks`, `docs.get_page_content` — ingested into Qdrant for RAG |

### Secrets Management

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **HashiCorp Vault** *(wave-2 fixture)* | READ | AppRole / k8s auth | `secrets.get_secret`, `secrets.list_secrets` |

### osquery (host telemetry)

| Integration | Risk class | Auth | Key tools |
|---|---|---|---|
| **osquery-tls server** *(built-in, services/osquery-tls/)* | READ | mTLS | `host.query_osquery`, `host.get_scheduled_queries`, `host.get_host_info` |
| **osquery extensions** *(services/osquery-extensions/)* | READ | mTLS | Custom table extensions for AiSOC-specific host telemetry |

---

## Tier 3 — Future Integrations (roadmap / wave-2+)

| Vendor | Category | Target quarter |
|---|---|---|
| Cloudflare Zero Trust *(activated)* | Network / ZT | v8.0 wave-2 |
| Sysdig *(activated)* | Container | v8.0 wave-2 |
| Snowflake *(activated)* | Data | v8.0 wave-2 |
| HashiCorp Vault *(activated)* | Secrets | v8.0 wave-2 |
| Lacework | Cloud CSPM | Q3 2026 |
| Vectra AI | NDR | Q3 2026 |
| Darktrace | NDR | Q3 2026 |
| Elastic Defend (response) | EDR write | Q3 2026 |
| AWS Organizations | Multi-account | Q3 2026 |
| Azure Arc | Hybrid cloud | Q4 2026 |
| Tanium | Endpoint | Q4 2026 |
| Nessus (Tenable.io) | Vuln | Q4 2026 |
| Armis | OT/IoT | Q4 2026 |
| Claroty | OT/IoT | Q4 2026 |

---

## Connector Security Controls

All connectors enforce the following since v7.x:

| Control | Implementation |
|---|---|
| SSRF prevention (2026-05-19) | All outbound HTTP through `ssrf_guard.py`; cloud-metadata IP block list (169.254.169.254, 100.64.0.0/10, etc.) |
| Credential isolation | Per-tenant encrypted credentials in `connector_credentials` table (AES-256-GCM, key from Vault / env) |
| `callback_url` SSRF fix (2026-05-19) | `callback_url` in connector config validated against allowlist before any HTTP call |
| Cross-tenant isolation (2026-05-20, PR #197) | Every connector call validates JWT `tenant_id` against resource's stored `tenant_id` at application layer, in addition to DB-level RLS |
| Audit trail | Every tool call logged: `connector_id`, `tenant_id`, `tool_id`, `params_hash`, `response_status`, `latency_ms`, `agent_id`, `case_id` |
| Rate limiting | Per-connector token bucket; vendor-specific limits from `connector_rate_limits.json` |
| Circuit breaker | Open after 3 failures in 60s; half-open probe after 30s |

---

## Tool Risk Classification

| Class | Definition | HITL required (default L2) |
|---|---|---|
| **READ** | Query only, no state change | No |
| **WRITE-REVERSIBLE** | Can be undone (unblock IP, re-enable account, restore file) | No (auto at L2+) |
| **WRITE-SIGNIFICANT** | Hard to reverse (disable account, isolate host) | Yes at L2; configurable at L3+ |
| **DESTRUCTIVE** | Permanent / severe impact (reimage host, wipe disk, permanent delete) | Always, regardless of maturity level |

---

*Last updated: 2026-05-20 · Document version: 2.0 · Production version: v7.3.1 · tryaisoc.com*
