# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AiSOC v4 "Autonomous SOC" planning: AI Multi-Agent Investigator, Visual SOAR Studio, Plugin Platform

---

## [3.0.0] — 2026-05-02

### Added
- **Threat Intelligence Enrichment (13 providers)**
  - Open-source/freemium: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan.io, IPinfo
  - Commercial: Cyble Vision, Recorded Future, Mandiant, Crowdstrike Intel, Anomali, IBM X-Force, Flashpoint, Intel 471, DomainTools, RiskIQ
  - New enrichment types: `DarkWebContext`, `VulnerabilityRef`, `BrandRisk`
  - Concurrent fan-out enrichment engine in Go
- **Go module path migration** — all services updated from `github.com/cyble/aisoc` to `github.com/beenuar/aisoc`
- **SECURITY.md** — vulnerability disclosure policy and security contacts
- `services/enrichment/README.md` — full enrichment service documentation

### Changed
- All GitHub repository references updated to `https://github.com/beenuar/AiSOC`
- Helm chart container images updated from `ghcr.io/cyble/aisoc-*` to `ghcr.io/beenuar/aisoc-*`
- `.env.example` expanded with API keys for all commercial TI providers

---

## [2.0.0] — 2026-05-01

### Added
- **Knowledge Graph** — Neo4j-backed entity relationship visualization (`services/api/app/services/graph_service.py`)
- **ML Fusion Engine** — multi-model alert scoring and deduplication (`services/fusion/app/services/`)
- **Rule Engine** — YAML-based detection rules with MITRE ATT&CK mapping (`services/api/app/services/rule_engine.py`)
- **Attack Graph** viz with D3.js force layout (`apps/web/src/components/graph/`)
- **MITRE ATT&CK Heatmap** on dashboard
- **AI Copilot dock** — streaming LLM assistant integrated into case and alert views
- **Threat Hunt page** — query builder with saved hunts and timeline scrubbing
- **Case Workspace** — full case lifecycle: evidence, timeline, collaborators, MITRE tagging
- **Detection Rule Builder** — visual rule editor with backtesting
- **Settings page** — RBAC, notifications, API key management, threat intel feed config
- **Live Dashboard** — WebSocket-powered real-time alert/event feed
- **Command Palette** (cmd-K) — fuzzy search for navigation and actions
- **Marketing Landing Page** — hero, feature highlights, open-source section, footer
- **Design Token System** — Tailwind + CSS vars, Framer Motion animations, responsive layouts
- **Demo Producer** — synthetic event generator for local development
- `scripts/seed_demo.py` — database seeding for demos

### Changed
- Web app migrated to Next.js App Router
- All API routes versioned under `/api/v1`

---

## [1.0.0] — 2026-04-30

### Added
- Initial release of AiSOC — AI Security Operations Center
- FastAPI backend (`services/api`) with alert ingestion, case management, detection rules
- Next.js 14 frontend (`apps/web`) with dashboard, alerts, cases, connectors, threat-intel pages
- Real-time service (`services/realtime`) using WebSockets
- Ingest service (`services/ingest`) in Go for high-throughput event ingestion
- Enrichment service (`services/enrichment`) in Go
- Docker Compose stack for local development
- Helm chart for Kubernetes deployment (`infra/helm/aisoc/`)
- MIT License

[Unreleased]: https://github.com/beenuar/AiSOC/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/beenuar/AiSOC/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/beenuar/AiSOC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/beenuar/AiSOC/releases/tag/v1.0.0
