# AiSOC maintenance docs — Oct 2026 live session

Working documentation for the deployment on `10.200.0.69`
(`/home/ubuntu/AiSOC`, compose project `aisoc`), covering the Oct 2026
diagnose-and-fix session. Code fixes: branch
`fix/aisoc-live-session-2026-10` on https://github.com/alexmateescu/AiSOC.

| File | Purpose |
|------|---------|
| [fix-log-2026-10.md](fix-log-2026-10.md) | Root cause + fix + verification for all 13 issues fixed |
| [ops-runbook.md](ops-runbook.md) | Live topology, credentials map, deploy & probe recipes |
| [known-gaps.md](known-gaps.md) | Open items, upstream-sync obligations, by-design non-fixes |

Quick orientation:
- Stack: web :3000 · core api :8000 · agents :8001→8084 · litellm :4000 ·
  ollama :11434 (Tesla T4) · postgres · kafka · clickhouse (lake) ·
  opensearch · ingest worker.
- Model routing: agents → LiteLLM aliases → `.env`
  `AISOC_LLM_MODEL_FAST/_DEEP` = `ollama_chat/qwen2.5:7b-instruct`
  (qwen3:8b thinking chains exceeded the 60 s gateway timeout on the T4).
