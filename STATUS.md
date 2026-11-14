
## Upstream review round (14-Nov ~09:00 UTC)
beenuar reviewed all five PRs:
- #1873 truncation gate + #1877 search: ACCEPTED, carried authorship-intact
  in #1879/#1880 (he added ruff + regression tests).
- #1875 FP reopen: DECLINED — disposition has no authorship (ledger.py AI
  writes same column); ungoverned FP exclusion = GHSA side door. HE IS RIGHT.
  Local predicate reverted to upstream (05d8e06aa, fusion redeployed).
  Governed resubmit with disposition_source column -> #1884.
- #1874 thinking env: DECLINED as bundled (suppression flip leaked, extra_body
  race at factory ~226, dup compose hunks). Narrow opt-in resubmit -> #1883.
- #1876 prometheus: DECLINED as shipped (credentials_file unprovisioned breaks
  default stack; METRICS_TOKEN env unread by prometheus). He lands ingest
  retarget himself; bearer config resubmit deferred until his lands.
Site prefs moved to local docker-compose.override.yml (gitignored):
MEMORY_SUPPRESSION=0, LLM_THINKING=0. Agents recreated; env verified live.

## Upstream review round (14-Nov ~09:00 UTC)
beenuar reviewed all five PRs:
- #1873 truncation gate + #1877 search: ACCEPTED, carried authorship-intact
  in #1879/#1880 (he added ruff + regression tests).
- #1875 FP reopen: DECLINED — disposition has no authorship (ledger.py AI
  writes same column); ungoverned FP exclusion = GHSA side door. HE IS RIGHT.
  Local predicate reverted to upstream (05d8e06aa, fusion redeployed).
  Governed resubmit with disposition_source column -> #1884.
- #1874 thinking env: DECLINED as bundled (suppression flip leaked, extra_body
  race at factory ~226, dup compose hunks). Narrow opt-in resubmit -> #1883.
- #1876 prometheus: DECLINED as shipped (credentials_file unprovisioned breaks
  default stack; METRICS_TOKEN env unread by prometheus). He lands ingest
  retarget himself; bearer config resubmit deferred until his lands.
Site prefs moved to local docker-compose.override.yml (gitignored):
MEMORY_SUPPRESSION=0, LLM_THINKING=0. Agents recreated; env verified live.

## Code home moved GitHub -> Bitbucket (14-Nov ~11:30 UTC)
- Canonical repo now git@bitbucket.org:lsg-group-bitbucket/AiSOC.git (origin).
- Full history pushed: all fork branches + 55 tags, SHAs verified vs GitHub.
- bbcloud key installed on fra-hq-soc-01 (~/.ssh/bbcloud, ssh.config entry).
- github remote kept (alexmateescu fork) ONLY until #1883/#1884 settle;
  upstream PRs continue from those branches. After fork deletion, future
  upstream contributions push branches to github remote recreated or via patch.
- GitHub fork deletion: pending #1883/#1884 merge/close (Alexandru).
