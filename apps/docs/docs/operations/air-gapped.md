---
title: Air-gapped / Local-LLM Mode
sidebar_label: Air-gapped mode
sidebar_position: 6
---

# Air-gapped / Local-LLM Mode

AiSOC can run **entirely within your network perimeter** with zero outbound LLM
calls.  The feature is controlled by a single environment variable and a
companion Docker Compose overlay that wires in a local inference server (Ollama,
LiteLLM, or vLLM).

---

## Quick start (Ollama + Docker Compose)

The easiest path is the pre-built air-gap overlay shipped in the repository:

```bash
docker compose \
  -f docker-compose.demo.yml \
  -f docker-compose.airgap.yml \
  up -d
```

What it does:

| Component | Action |
|-----------|--------|
| `ollama` service | Starts `ollama/ollama:0.6.7` bound to `127.0.0.1:11434` |
| `ollama-pull` init container | Pulls the pinned model on first boot (cached on restart) |
| `agents` service override | Sets `AISOC_AIRGAPPED=true`, `LLM_BASE_URL`, `LLM_MODEL`, blanks external keys |

The pinned default model is **`llama3.2:3b-instruct-q4_K_M`** (~2 GB).  To use
a larger model:

```bash
AIRGAP_LLM_MODEL=llama3.1:8b-instruct-q4_K_M \
docker compose -f docker-compose.demo.yml -f docker-compose.airgap.yml up -d
```

---

## How air-gap enforcement works

Setting `AISOC_AIRGAPPED=true` activates an allow-list check inside the LLM
resolver (`services/agents/app/security/llm_resolver.py`).  When a credential
set is resolved:

1. **Local providers pass** — any base URL containing `ollama`, `vllm`, or
   `litellm` (or mapped by the `_HOSTED_SUBSTRINGS` table) is classified as
   local and is always permitted.
2. **External providers are blocked** — any credential pointing to a hosted API
   (`api.openai.com`, `*.azure.com`, `generativelanguage.googleapis.com`, etc.)
   raises `AirgapViolationError` before the HTTP call is made.
3. **Deterministic fallback** — if no local LLM is configured either, the
   investigator's deterministic synthesizer fills all LLM response fields with
   canned, reproducible output so the demo seed and evaluation harness complete
   without errors.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AISOC_AIRGAPPED` | `false` | Set to `true` to enforce local-only LLM calls |
| `LLM_BASE_URL` | _(unset)_ | OpenAI-compatible base URL of the local server (e.g. `http://ollama:11434/v1`) |
| `LLM_API_KEY` | _(unset)_ | API key passed to the local server (Ollama ignores it; use any non-empty string) |
| `LLM_MODEL` | _(unset)_ | Model name as understood by the local server (e.g. `llama3.2:3b-instruct-q4_K_M`) |

---

## Plugging in a different local inference server

### Ollama (recommended)

```env
AISOC_AIRGAPPED=true
LLM_BASE_URL=http://ollama.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M
```

### LiteLLM proxy

LiteLLM can front multiple local backends (Ollama, vLLM, GGUF servers) behind a
single OpenAI-compatible endpoint:

```env
AISOC_AIRGAPPED=true
LLM_BASE_URL=http://litellm.internal:4000
LLM_API_KEY=<litellm-master-key>
LLM_MODEL=ollama/llama3.1:70b-instruct
```

### vLLM

```env
AISOC_AIRGAPPED=true
LLM_BASE_URL=http://vllm.internal:8000/v1
LLM_API_KEY=vllm-api-key
LLM_MODEL=meta-llama/Llama-3.1-70B-Instruct
```

---

## Tenant-level overrides (BYOK under air-gap)

Platform operators can allow individual tenants to bring their own local LLM
credentials via **Settings → Deployment & AI → LLM Provider**.  The UI exposes
three local-provider options:

| Provider label | Internal `provider_type` |
|----------------|--------------------------|
| Local Ollama | `local-ollama` |
| Local LiteLLM | `local-litellm` |
| Local vLLM | `local-vllm` |

When `AISOC_AIRGAPPED=true`, the resolver validates that the tenant-supplied
base URL is classified as a local endpoint before allowing it.  If a tenant
tries to configure an external endpoint, the request is rejected with HTTP 422
and the error `"airgap_violation"`.

---

## Verifying air-gap compliance

Call the LLM status endpoint after startup:

```bash
curl -s http://localhost:8000/api/v1/llm/status | jq .
```

A compliant response looks like:

```json
{
  "provider_type": "local-ollama",
  "model": "llama3.2:3b-instruct-q4_K_M",
  "reachable": true,
  "airgap_compliant": true
}
```

`airgap_compliant: false` means the resolved provider would make external calls.
Stop the stack, correct the environment variables, and restart.

---

## Running the demo seed in air-gapped mode

The demo seed script (`scripts/demo_seed.py`) seeds a reference incident and
kicks off an investigation with `"mode": "deterministic"`.  In this mode:

* **Triage, hunt, and enrichment nodes** use the local LLM for scoring if
  `LLM_BASE_URL` is set, otherwise they use pre-computed deterministic stubs.
* **All external connector calls** remain in simulation mode (no live
  integrations are contacted).
* **Zero external LLM calls** are made when `AISOC_AIRGAPPED=true` and the
  local server is healthy.

```bash
# With the air-gap overlay running:
docker exec aisoc-api python scripts/demo_seed.py
```

Expected output includes `investigation_status: closed` and no `openai.com`
entries in the network logs.

---

## Kubernetes / production deployment

For production air-gapped clusters add these env vars to the `agents` Deployment:

```yaml
env:
  - name: AISOC_AIRGAPPED
    value: "true"
  - name: LLM_BASE_URL
    value: "http://ollama.llm-infra.svc.cluster.local:11434/v1"
  - name: LLM_API_KEY
    valueFrom:
      secretKeyRef:
        name: airgap-llm-creds
        key: api-key
  - name: LLM_MODEL
    value: "llama3.1:70b-instruct-q4_K_M"
  # Blank external keys explicitly
  - name: OPENAI_API_KEY
    value: ""
  - name: ANTHROPIC_API_KEY
    value: ""
```

Use a Kubernetes `NetworkPolicy` to deny egress to `api.openai.com` and other
external LLM endpoints as a defence-in-depth measure alongside the software
enforcement.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `AirgapViolationError` in logs | `LLM_BASE_URL` points to an external host | Correct `LLM_BASE_URL` to your local server |
| `reachable: false` in `/api/v1/llm/status` | Local server not running | Check `docker compose ps` and Ollama health |
| Model pull timeout | Large model, slow disk | Use a smaller quantised model or increase `start_period` |
| `connection refused` on port 11434 | Port binding conflict | Change `127.0.0.1:11434` → a free port in the overlay |

---

## Related pages

* [Credentials & Vault](credentials.md) — how tenant secrets are encrypted at rest
* [API configuration](../getting-started/configuration.md) — all environment variables
* [Plugin SDK](../plugins/overview.md) — build connectors that work under air-gap
