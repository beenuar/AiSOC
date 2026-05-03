# AiSOC Enrichment Service

A Go service that enriches IOCs (IPs, domains, URLs, file hashes) by fanning
out to a curated set of open-source and commercial threat-intelligence
providers in parallel, then merging the responses into a single normalized
`EnrichmentResult`.

The service is part of the AiSOC platform and is consumed by the analysis
pipeline, the AI Copilot, the case workspace, and the hunt UI.

---

## Highlights

- **One unified response shape.** Every provider — VirusTotal or Mandiant —
  is mapped to the same `EnrichmentResult` struct with reputation score,
  classifications, evidence, and provenance.
- **Concurrent fan-out.** Per-IOC requests are dispatched to every configured
  provider via goroutines and merged with deterministic precedence.
- **Tiered providers.** Open-source and freemium feeds for community use,
  commercial feeds for enterprise deployments — toggled by environment
  variables.
- **Cache-first.** Redis-backed result cache with per-IOC TTLs; `force=true`
  bypasses the cache for live re-enrichment.
- **Graceful degradation.** Missing API keys are not errors. Each unconfigured
  client returns a "not configured" sentinel that is filtered from the merge.

---

## Supported providers

### Open-source / freemium

| Provider     | IOC types               | Auth      | Env vars                                |
| ------------ | ----------------------- | --------- | --------------------------------------- |
| VirusTotal   | IP, domain, URL, hash   | API key   | `VIRUSTOTAL_API_KEY`                    |
| AbuseIPDB    | IP                      | API key   | `ABUSEIPDB_API_KEY`                     |
| GreyNoise    | IP                      | API key   | `GREYNOISE_API_KEY`                     |
| Shodan       | IP                      | API key   | `SHODAN_API_KEY`                        |
| URLScan      | URL, domain             | API key   | `URLSCAN_API_KEY`                       |
| IPinfo       | IP                      | API key   | `IPINFO_API_KEY`                        |

### Commercial

| Provider                          | IOC types                | Auth                 | Env vars                                              |
| --------------------------------- | ------------------------ | -------------------- | ----------------------------------------------------- |
| Cyble Vision                      | IP, domain, URL, hash    | API key              | `CYBLE_API_KEY`, `CYBLE_BASE_URL`                     |
| Recorded Future                   | IP, domain, URL, hash    | API key              | `RECORDED_FUTURE_API_KEY`                             |
| Mandiant Threat Intelligence v4   | IP, domain, URL, hash    | OAuth client-creds   | `MANDIANT_API_KEY`, `MANDIANT_API_SECRET`             |
| Crowdstrike Falcon Intelligence   | IP, domain, URL, hash    | OAuth client-creds   | `CROWDSTRIKE_INTEL_ID`, `CROWDSTRIKE_INTEL_SECRET`    |
| Anomali ThreatStream              | IP, domain, URL, hash    | Basic (user + key)   | `ANOMALI_USERNAME`, `ANOMALI_API_KEY`, `ANOMALI_BASE_URL` |
| IBM X-Force Exchange              | IP, domain, URL, hash    | Basic (key + pwd)    | `XFORCE_API_KEY`, `XFORCE_API_PASSWORD`               |
| Flashpoint                        | IP, domain, hash         | Bearer token         | `FLASHPOINT_API_KEY`                                  |
| Intel 471                         | IP, domain, hash         | Basic (user + key)   | `INTEL471_USERNAME`, `INTEL471_API_KEY`               |
| DomainTools Iris                  | Domain, IP               | Basic (user + key)   | `DOMAINTOOLS_USERNAME`, `DOMAINTOOLS_API_KEY`         |
| RiskIQ PassiveTotal               | Domain, IP               | Basic (user + key)   | `RISKIQ_USERNAME`, `RISKIQ_API_KEY`                   |

Configure only the providers you have access to. The orchestrator logs which
providers are active at startup.

---

## EnrichmentResult schema

The merged result includes the following fields. Empty fields are omitted by
the JSON encoder.

```go
type EnrichmentResult struct {
    IOCType         IOCType
    IOCValue        string
    ReputationScore int                 // 0–100, higher = more malicious
    Verdict         string              // benign | suspicious | malicious
    Tags            []string
    Sources         []EnrichmentSource  // per-provider provenance + tier

    // Network / infra
    Country         string
    ASN             string
    ASNOrg          string
    IsTor           bool
    IsVPN           bool
    IsDatacenter    bool

    // Time
    FirstSeen       *time.Time
    LastSeen        *time.Time

    // Threat context
    MITRETactics    []string
    MITRETechniques []string
    ThreatActors    []string
    Malware         []string
    Campaigns       []string

    // Commercial-TI extensions
    DarkWeb         *DarkWebContext     // forum mentions, leaks, marketplaces
    Vulnerabilities []VulnerabilityRef  // CVEs with CVSS / EPSS
    BrandRisk       *BrandRisk          // typosquats, impersonation, phishing
    Whois           map[string]string   // registrant, registrar, dates
}
```

Provenance is preserved per-source via `EnrichmentSource{Name, Tier, ...}`
where `Tier` is `oss` or `commercial`.

---

## Fan-out and merge semantics

For each enrich request the service:

1. Looks up the IOC in Redis. On hit, returns cached result (unless
   `force=true`).
2. Selects every provider whose client is configured **and** supports the IOC
   type, and runs them in parallel via `runFanOut`.
3. Merges per-source `EnrichmentResult`s with the following rules:
   - **Reputation** is the maximum across sources, weighted to favor
     commercial-tier verdicts when within a small delta.
   - **Tags / actors / malware / techniques** are unioned, deduped.
   - **Time fields** take the earliest `FirstSeen` and latest `LastSeen`.
   - **Vulnerabilities** are deduped by CVE ID, keeping the highest CVSS.
   - **Dark web / brand risk** sections are concatenated, deduped by
     `(source, identifier)`.
4. Caches the merged result with a TTL based on verdict severity.

---

## API

### Enrich an IOC

```
POST /v1/enrich
Content-Type: application/json

{
  "type": "ip" | "domain" | "url" | "hash",
  "value": "8.8.8.8",
  "force": false
}
```

Response: a JSON-encoded `EnrichmentResult`.

### Health

```
GET /healthz
```

Returns `200 OK` once the cache and at least one provider are reachable.

---

## Local development

```bash
cd services/enrichment

# minimal config: VirusTotal only
export VIRUSTOTAL_API_KEY=...
export REDIS_ADDR=localhost:6379

go run .
```

Run with the full provider set by populating the corresponding environment
variables from `.env.example` at the repo root.

### Build / vet

```bash
go build ./...
go vet ./...
```

### Tests

```bash
go test ./...
```

---

## Notes

- Provider clients are isolated under `internal/enricher`. New providers
  follow the same shape: `New<Provider>Client(...)` constructor, per-IOC
  enrichment methods returning `*EnrichmentResult`, graceful no-op when the
  client is not configured.
- Commercial clients in `commercial.go` are intentionally compact and share
  HTTP plumbing; high-traffic providers (Cyble, Recorded Future, Mandiant)
  live in their own files for clarity.
- All clients honor the request `context.Context` for deadlines and
  cancellation.
