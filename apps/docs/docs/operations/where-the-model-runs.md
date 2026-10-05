---
id: where-the-model-runs
title: Where the model runs
sidebar_label: Where the model runs
---

# Where the model runs

AiSOC ships a model and runs it. `make up` needs no account, no key and no GPU,
and triage produces a real verdict from a real model with real token counts.

It is also the slowest of the four options. This page is the other three.

## The four options

| Option | Command | Works on |
|---|---|---|
| Bundled model, CPU | `make up` | everything |
| Bundled model, NVIDIA GPU | `make up-gpu` | Linux, Windows + WSL2 |
| An Ollama you already run | `make up-host-llm` | everything, and the **only** GPU option on a Mac |
| A hosted provider | no command — configure it in the console | everything |

`make doctor` tells you which fits the host you are on, and the setup wizard
tells you which one is in effect right now.

## Why the GPU option is not in the console

Switching the bundled model onto a GPU means restarting that container with
different device reservations. A web service that could do that would need the
Docker socket, which is a container-escape path rather than a feature. So the
console *reports* where the model is running and shows you the command; it does
not run it.

The hosted-provider option is different — that is a database row, so the wizard
configures it outright.

## NVIDIA

```bash
make up-gpu
```

This layers `infra/compose/docker-compose.gpu.yml`, which reserves one NVIDIA
device for Ollama and changes nothing else.

It runs `scripts/check_gpu_runtime.py` first, and that check is the point.
Without it, a host missing the container toolkit gets the daemon's own answer:

```
Error response from daemon: could not select device driver "nvidia" with capabilities: [[gpu]]
```

which names neither a cause nor a next command. The preflight says which of the
four things is missing — card, driver, toolkit, daemon configuration — and what
installs it.

Expose more than one device with `AISOC_GPU_COUNT=all`. The pinned model needs
roughly 3 GB of VRAM; if your card is smaller, Ollama splits the model and the
wizard reports it as *partly on a GPU* rather than pretending otherwise.

## Apple Silicon

`make up-gpu` does nothing useful here, and the preflight will say so rather
than letting you find out slowly. **Docker Desktop cannot pass the Metal GPU
into a Linux container.** No toolkit, driver or setting changes that: a
container on a Mac is CPU-only.

A natively-installed Ollama *does* use Metal:

```bash
brew install ollama
OLLAMA_HOST=0.0.0.0 ollama serve          # in its own terminal
ollama pull llama3.2:3b-instruct-q4_K_M
make up-host-llm
```

`OLLAMA_HOST=0.0.0.0` matters: Ollama binds loopback by default, which a
container cannot reach.

## An Ollama you already run

```bash
make up-host-llm
```

This layers `infra/compose/docker-compose.host-llm.yml`, which moves the
bundled `ollama` and `ollama-pull` into a `bundled` profile so neither starts,
clears the gateway's dependency on the puller, and points
`AISOC_LLM_API_BASE` at `host.docker.internal:11434`.

It is worth doing even without a GPU. `11434` is in the port inventory, so on a
host already running Ollama, `make up` sees the conflict and republishes the
*bundled* one on a free port — leaving you with two Ollamas, the stack talking
to the new one, and yours idle.

Point somewhere else entirely by setting `AISOC_LLM_API_BASE` in `.env`: another
machine on the LAN, or an existing vLLM.

Bring the bundled one back without editing anything:

```bash
docker compose --profile bundled up -d ollama
```

## A hosted provider

Console → **Settings → Deployment & AI**, or the **Choose where the AI runs**
step in the setup wizard. Seven providers: `openai`, `anthropic`,
`azure-openai`, `local-ollama`, `local-vllm`, `local-litellm`, `custom`. The key
is encrypted at rest with the credential vault and never returned by the API —
reads report only `has_api_key`.

**Test it before you rely on it.** The *Test* button places one real
one-token completion and reports what happened:

| Outcome | Means |
|---|---|
| `ok` | the provider answered |
| `refused` | reached it and it said no — usually the key, sometimes the model name |
| `unreachable` | nothing answered at that address |
| `unverified` | air-gapped, so the call was not attempted — the policy working, not a bad key |

Before this existed, the routes validated only *shape*, so a revoked key
surfaced as triage quietly falling back to the deterministic path — a failure
that is hard to attribute to a credential precisely because it is silent.

The same check from the API:

```bash
curl -sX POST localhost:8000/api/v1/llm/credentials/test \
  -H "Authorization: Bearer $TOKEN"
```

It places one token against a fixed prompt, so it costs essentially nothing
and is safe to run from a health check. See the
[REST reference](../api/rest#testing-a-credential) for the full response
shape.

## Checking what is actually running

A GPU reservation is a *request*. A model can still land on the CPU for want of
VRAM or a usable driver, so reading the compose file back would report the
intent and call it the outcome. Ask instead:

```bash
curl -s localhost:8000/api/v1/llm/runtime -H "Authorization: Bearer $TOKEN"
docker compose exec ollama ollama ps     # SIZE and the GPU/CPU split
```

The wizard shows the same thing, and so does the
[REST reference](../api/rest#ai-model--credentials). Five answers, and **not
loaded right now** is one of them: Ollama unloads after a few minutes idle, so an empty answer means
nobody has asked it anything yet — which is not the same as CPU, and reporting
CPU there would be a guess about the exact thing you are deciding on.

## Air-gapped deployments

All four options work air-gapped except a hosted provider on a public address.
`AISOC_AIRGAPPED=true` refuses egress to anything outside
`AISOC_AIRGAP_ALLOWLIST`, while still permitting private hosts — so a
`local-ollama` or `local-vllm` on your own network is allowed by design. See
[air-gapped](./air-gapped.md).
