# Phase 4 working notes (local, not committed)

Worktree: /Users/beenu/Desktop/AiSOC-agenttools
Branch base: feat/phase4-agent-tools off origin/main @ 1f56e324

## Measured for 4.5 (done)

Images pulled fresh from GHCR 2026-09-26:
- ghcr.io/beenuar/aisoc-actions:latest    539 MB
- ghcr.io/beenuar/aisoc-connectors:latest 586 MB

Resident memory, measured on this machine (16.7 GB host):

| | cold-start idle (45s) | under 100 reqs | 40h steady state |
|---|---|---|---|
| actions | 45.99 MiB | 46.3 MiB | 48.3 MiB |
| connectors | 71.45 MiB | 71.98 MiB | 76.51 MiB |
| total | 117.4 MiB | 118.3 MiB | 124.8 MiB |

Reference on the same host, same method: litellm 471.1 MiB (ADR-0006 measured
451 MiB), agents 223.7 MiB, api 213.9 MiB, web 86.2 MiB, fusion 58.1 MiB.

Zero-config boot verified:
- actions: /health 200, /api/v1/live-actions 200 listing the capability set
- connectors: /api/v1/connectors 200 with all 84 connectors

CORE today already points at both: api has CONNECTORS_SERVICE_URL=http://connectors:8003
and AISOC_ACTIONS_BASE_URL=http://actions:8085, and AISOC_FEATURE_FED_SEARCH
defaults True. Neither hostname resolves in CORE.

## Plan

- [x] worktree, read plan + tracker
- [x] 4.5 measurement
- [ ] PR1: ADR-0007 + compose + docs (4.5)
- [ ] PR2: 4.2 new vendor read verbs in services/actions
- [ ] PR3: 4.1 + 4.3 + 4.4 agent tool surface
- [ ] tracker + claim matrix + changelog
- [ ] eval re-grade deltas
