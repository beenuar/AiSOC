---
title: LLM gateway (LiteLLM)
description: Configure AiSOC's default LLM gateway — assign local or hosted models per task by alias, with centralized latency/token/cost/error metrics for gateway traffic.
---

# LLM gateway (LiteLLM)

AiSOC runs several distinct LLM workloads — triage, recon, investigation, the
contextual copilot, summaries, reports, and natural-language generation. The
**LiteLLM gateway** is the default route for these live workloads. AiSOC asks
for a **logical task alias**; the gateway decides which real provider and model
that alias resolves to. Explicit endpoint/model overrides and the tenant BYOK
paths described below can select a different route.

:::tip Choosing where the model runs

This page is about the **gateway** — which provider and model requests are
routed to. Where that model physically executes (CPU, an NVIDIA GPU, a host
Ollama using Apple's Metal, or someone else's datacentre) is a separate
decision with its own page: [Where the model runs](./where-the-model-runs).

`GET /api/v1/llm/status` reports the client's configured endpoint and model;
it does not discover the upstream provider behind a gateway. It can report
`local-litellm` while LiteLLM routes to Bedrock. `GET /api/v1/llm/runtime`
probes the local Ollama runtime, including whether its loaded model uses GPU
memory. Neither endpoint proves that a hosted model can complete a request.

:::

```
AiSOC task ──▶ alias (e.g. "aisoc-triage") ──▶ LiteLLM ──▶ real model
```

This gives operators two things without any AiSOC code change:

1. **Per-task model assignment.** Point `aisoc-triage` at a cheap local model
   and `aisoc-investigation` at a strong hosted one — or swap either at any time
   — by editing one config file.
2. **Centralized observability.** LiteLLM exports per-task latency, tokens,
   cost, errors, retries, and fallbacks on `/metrics`, scraped by the bundled
   Prometheus (job `aisoc-litellm`). This complements the
   [Investigation Ledger](../concepts/llmops.md), which records *what the agent
   decided*. Gateway metrics cover calls routed through LiteLLM; direct BYOK
   calls do not pass through it.

The automatic triage worker checks the cost governor, deterministic-mode
switch and resolved LLM configuration before making a live call. An unavailable
or failed LLM call falls back to **deterministic triage**. The gateway selects
the backend for a requested alias; it does not decide which alerts need an LLM.

The gateway startup, environment normalization and reload instructions on this
page cover Compose and its overlays. The Helm chart maintains its own gateway
configuration and does not use the Compose startup wrapper.

## Task aliases

The shipped aliases mirror AiSOC's workloads. They live in
`infra/litellm/config.yaml`:

| Alias | Workload | Model variable |
| --- | --- | --- |
| `aisoc-triage` | Auto-triage | `AISOC_LLM_MODEL_FAST` |
| `aisoc-recon` | Recon / enrichment | `AISOC_LLM_MODEL_FAST` |
| `aisoc-investigation` | Deep investigation | `AISOC_LLM_MODEL_DEEP` |
| `aisoc-copilot` | Contextual copilot | `AISOC_LLM_MODEL_FAST` |
| `aisoc-summary` | Summaries | `AISOC_LLM_MODEL_FAST` |
| `aisoc-report` | Reports | `AISOC_LLM_MODEL_DEEP` |
| `aisoc-nl` | NL query / detection generation | `AISOC_LLM_MODEL_FAST` |
| `aisoc-hunt` | Structured hunt plan | `AISOC_LLM_MODEL_FAST` |
| `aisoc-detection` | Detection tuning | `AISOC_LLM_MODEL_FAST` |

Both variables default to `ollama_chat/llama3.2:3b-instruct-q4_K_M`.
A normal `make up` starts the gateway and bundled Ollama without provider keys.
Once the weights are available, the model can answer; if inference is
unavailable, AiSOC uses its deterministic fallback. Gateway liveness alone
is not proof that a model can answer.

## Choose the configuration scope

| Requirement | Configure | Credential used |
| --- | --- | --- |
| Local, no account or key | Default `make up` | None upstream |
| Deployment-wide OpenAI / Anthropic / Bedrock across the bundled aliases | Host `.env`, then `make llm-reload` | Provider-native credential in LiteLLM |
| One tenant's Explain and automatic alert triage | Settings → Deployment & AI; select a provider, its key and any endpoint/model overrides | Tenant key, or a deployment key only for the same complete API base |
| Those tenant paths through another LiteLLM gateway | Select `local-litellm` or `custom`; supply its OpenAI-compatible URL, served model/alias and gateway key | Key issued by that gateway |

**Current BYOK scope:** the Explain paths and automatic alert triage read the
tenant's saved configuration. Copilot and other callers continue to use their
deployment routing; saving BYOK does not switch every AI feature. Leave BYOK
disabled when the tenant should inherit the bundled gateway's Bedrock
configuration. The gateway's FAST/DEEP settings apply to all bundled aliases
that still route through it.

Tenant endpoint, model and credential are resolved together:

- With no enabled override, the tenant uses the deployment route. A default
  Compose installation uses the bundled gateway and Ollama; a gateway configured
  for Bedrock keeps its native AWS authentication.
- For `openai` or `anthropic`, blank endpoint/model fields use that provider's
  hosted defaults. Saving a provider key alone therefore selects the hosted
  route, rather than sending that key to the bundled gateway.
- For a local/custom endpoint, supply its OpenAI-compatible API base and a model
  or alias it serves. A blank model retains the deployment model for Explain
  and the connection test, or the task-role model for automatic triage, so set
  it explicitly when the destination has different model names.
- A saved tenant key wins. A deployment key is available only for the same
  complete API base, including its scheme, hostname, port, path and query;
  matching only the hostname is insufficient. Scheme/hostname case and trailing
  slashes are normalized. URLs containing user information or fragments do not
  qualify. An unreadable saved key cannot expose a deployment key to a different
  destination.

An explicit local/custom endpoint without a saved key can operate without a
secret. If there is no matching deployment key, the clients send the non-secret
`aisoc-no-auth` placeholder so an SDK cannot fill in an ambient provider key.
The endpoint must accept or ignore that placeholder; this is not a guarantee
that the request has no Authorization header.

The UI does **not** implement native Bedrock Converse/Invoke requests or AWS
SigV4 signing. A raw regional Bedrock runtime URL is not an OpenAI Chat
Completions base. Direct Anthropic BYOK uses Anthropic's OpenAI-compatible API.
For Anthropic on Bedrock, configure native credentials on LiteLLM and use its
OpenAI-compatible API.

Bedrock also offers a separate [OpenAI-compatible Chat Completions API](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-chat-completions.html).
For a model that supports it, an explicit `custom` BYOK tuple can use
`https://bedrock-runtime.<region>.amazonaws.com/openai/v1`, the model ID
supported on that endpoint, and a Bedrock API key. The key is valid for that
explicit AWS endpoint; it must not become a generic key on every native
gateway alias. This path uses bearer authentication, not automatic IAM-role
credentials. Check the [model/API compatibility table](https://docs.aws.amazon.com/bedrock/latest/userguide/models-api-compatibility.html)
and the model card: Anthropic models are not listed as Chat Completions
compatible. Bedrock runtime also has no OpenAI-compatible `GET /models`;
enter the model ID explicitly. This direct tuple is based on the documented
protocol and still requires a real Explain/triage acceptance test in the
target AWS account.

The UI's **Test connection** resolves the saved provider defaults and matching
deployment credential with the same routing rules, and exercises an
OpenAI-compatible completion. The authenticated status endpoint reports the
tenant-resolved configuration with secrets redacted. A probe alone does not
exercise the full workload: after saving, verify a real Explain or automatic
triage result as well.

The bundled clients authenticate to LiteLLM using `LITELLM_MASTER_KEY`.
That key is separate from `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and
`AWS_BEARER_TOKEN_BEDROCK`, which authenticate LiteLLM to upstream providers.
For this native gateway configuration, keep each provider's credential in its
own variable.

### OpenAI or Anthropic deployment defaults

Set both model variables and clear the local endpoint in `.env`, for example:

```dotenv
OPENAI_API_KEY=<your-provider-key>
AISOC_LLM_MODEL_FAST=openai/gpt-4o-mini
AISOC_LLM_MODEL_DEEP=openai/gpt-4o
AISOC_LLM_API_BASE=
```

For Anthropic, use `anthropic/<model-id>` and `ANTHROPIC_API_KEY` instead.
The aliases omit `api_key` so LiteLLM selects the matching native credential.
An empty `AISOC_LLM_API_BASE` is normalized to absent at gateway startup;
the provider then selects its default endpoint. A nonempty value is preserved,
including an existing OpenAI-compatible server or a private endpoint.
The shared endpoint applies to both model tiers; mixed-provider deployments
needing different endpoints should configure them per alias in the YAML.

### Amazon Bedrock: instance role, existing profile, or bearer token

Set the models and region for the account where the models are enabled:

```dotenv
AISOC_LLM_MODEL_FAST=bedrock/<model-or-inference-profile-id>
AISOC_LLM_MODEL_DEEP=bedrock/<model-or-inference-profile-id>
AISOC_LLM_API_BASE=
AWS_REGION=us-east-1
```

Replace the angle-bracket values with actual accessible model or inference
profile IDs. For an explicit endpoint, use e.g.
`AISOC_LLM_API_BASE=https://bedrock-runtime.us-east-1.amazonaws.com`.
The region can instead come from `AWS_DEFAULT_REGION` or an existing AWS
profile. The existing `.env.example` also sets `AWS_REGION=us-east-1` for
AWS integrations. Remove or clear `AWS_REGION` and `AWS_REGION_NAME` when
you want `AWS_DEFAULT_REGION` or the profile region to take precedence.

| AWS authentication | Additional configuration |
| --- | --- |
| EC2 instance role | No API key. Keep `AWS_EC2_METADATA_DISABLED=false` (default), and make IMDS reachable from the gateway container. |
| Existing environment credentials | Compose forwards `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN`. Temporary credentials require the session token. |
| Existing host profile / SSO | Use the optional read-only profile overlay below; set `AWS_PROFILE` if needed and refresh SSO on the host before starting. |
| Bedrock API key | Set `AWS_BEARER_TOKEN_BEDROCK`. `AWS_EC2_METADATA_DISABLED=true` is optional and disables only metadata lookup. |

With no bearer, LiteLLM uses the AWS SDK credential chain. With a bearer,
it uses that token; an expired/denied token is an error, not an automatic
fallback to an unrelated IAM identity. To switch back to IAM, remove the
bearer and recreate the gateway. Blank optional AWS values are removed before
LiteLLM starts so empty profile/credential placeholders cannot mask the chain.

Docker does not automatically expose the host's `~/.aws`. To use those files:

```bash
make up COMPOSE="docker compose -f docker-compose.yml -f infra/compose/docker-compose.aws-profile.yml"
```

The overlay mounts the existing directory at `/root/.aws` read-only, only in
LiteLLM. `AISOC_AWS_CONFIG_DIR` can select a different host directory. It fails
if the directory does not exist instead of creating an empty credentials
folder. If you set `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE`, use
container paths (e.g. `/root/.aws/config` and `/root/.aws/credentials`), not
host absolute paths. The read-only SSO cache cannot persist a refreshed token
from inside the container; renew sessions on the host. For unattended EC2
use, prefer the instance role. Keep the same `COMPOSE` value for `make upgrade` and `make llm-reload`
(and include any port/GPU overlays you already use). Remove the host-Ollama
overlay when switching to Bedrock or another hosted provider: it substitutes
the host Ollama address for an empty endpoint. This mount is unnecessary on
EC2 when the instance role is available. Profiles using `credential_process`
need that executable inside the container; mounting its host path alone is
not sufficient.

`AWS_EC2_METADATA_DISABLED=true` does not disable environment or profile
credentials. It **does** disable an EC2 role's metadata source, so do not set
it on a deployment relying on that role. With bridged containers, verify
IMDSv2 reachability and the instance metadata response hop limit; do not
switch off IMDSv2 to work around a networking problem.

A Marketplace/model-access denial is separate from credential discovery.
Bedrock API keys still carry IAM permissions; switching credentials may
change the principal or account. Have an administrator enable the selected
models and grant the runtime principal the necessary invoke permissions.
Marketplace subscription permissions can be needed for first enablement;
the runtime principal need not retain them after that. A successful bearer
request does not prove that the original instance role has the same access.

### Apply and verify gateway changes

```bash
make llm-reload
```

This recreates only LiteLLM, including its environment and mounts.
`make upgrade` also performs this step. A plain restart does not replace a
container's environment, and `compose up` does not detect changed bytes in a
bind-mounted YAML file. Expect active gateway requests to be interrupted
briefly during recreation.

Compare the actual mounted file with the host copy, without printing secrets:

```bash
python3 -c "import hashlib; print(hashlib.sha256(open('infra/litellm/config.yaml','rb').read()).hexdigest())"
docker compose exec -T litellm python -c "import hashlib; print(hashlib.sha256(open('/etc/litellm/config.yaml','rb').read()).hexdigest())"
```

Then test a real completion through the gateway. This incurs one model call
when a paid provider is selected; run it for both FAST and DEEP aliases.
For example, substitute `aisoc-investigation` for `aisoc-triage` below.
Verify that the returned model is the intended FAST or DEEP backend:
`aisoc-investigation` can fall back to `aisoc-triage`, so HTTP success alone
does not prove the DEEP model succeeded:

```bash
docker compose exec -T litellm python - <<'PY_GATEWAY'
import json
import os
import urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:4000/v1/chat/completions',
    data=json.dumps({
        'model': 'aisoc-triage',
        'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
        'max_tokens': 16,
    }).encode(),
    headers={
        'Authorization': 'Bearer ' + os.environ['LITELLM_MASTER_KEY'],
        'Content-Type': 'application/json',
    },
)
with urllib.request.urlopen(request, timeout=90) as response:
    body = json.load(response)
    print('Completion succeeded:', body['model'], 'choices:', len(body['choices']))
PY_GATEWAY
```

The completion checks the active route/authentication; matching config hashes
and a healthy `/health/liveliness` alone do not establish that.

### Calling a provider directly, with no gateway

Pin each role to a concrete provider model. A concrete pin is **not** rerouted
to the gateway, so this keeps working with `LLM_GATEWAY_URL` set:

```bash
AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini
AISOC_MODEL_PIN_INVESTIGATION=gpt-4o
# … one per role: triage, recon, investigation, copilot, summary, report, nl
OPENAI_MODEL=gpt-4o-mini                   # the BYOK / "explain this alert" path, direct too
```

With neither the gateway nor pin overrides configured, AiSOC uses its
deterministic offline path, which reports zero model calls and zero tokens
rather than presenting a heuristic as triage.

### A model the gateway does not define is an error, not a fallback

Two failures used to be indistinguishable from "no LLM available", because both
arrived as an exception a caller turned into a deterministic result:

- An `aisoc-<role>` alias sent to a provider default, which does not know the
  name. AiSOC now raises `UnroutableModelError` naming the alias and the remedy
  instead of building a client destined to fail.
- A concrete model sent to the gateway, which answers `Invalid model name`.
  `preflight_llm()` reports this at boot, in both directions, and
  `scripts/check_llm_model_routing.py` fails the build when a model named in
  `.env.example` or `docker-compose.yml` is not one `infra/litellm/config.yaml`
  defines — or when the gateway defines an alias no role requests.

`OPENAI_MODEL` applies to the BYOK / "explain this alert" path **only**. It is
never a task role's model: the auto-triage worker layers a tenant's BYOK
configuration over the role pin, and only the fields the *tenant* set are
treated as overrides, including the selected hosted provider's defaults.
An environment model default cannot displace a task-role alias.

### Embeddings

The MITRE RAG path calls an embedding endpoint, and `infra/litellm/config.yaml`
declares chat aliases only — so embeddings deliberately do **not** follow chat
traffic to the gateway. They have their own pair of variables,
`AISOC_EMBEDDING_BASE_URL` and `AISOC_EMBEDDING_MODEL` (default
`text-embedding-3-large`), and default to the provider. The routing gate checks
that exclusion in both directions.

## Re-point a task to a local model

Replace the existing alias's backend in `infra/litellm/config.yaml` with a
local backend. The alias name **must stay the same** so AiSOC is unaware of
the swap:

```yaml
- model_name: aisoc-triage
  litellm_params:
    model: ollama/llama3.1
    api_base: http://ollama:11434
```

Commented Ollama, vLLM, and Anthropic examples ship in the config. For a fully
offline deployment, see [air-gapped operation](./air-gapped.md), which fronts a
local Ollama.

## Observe

- **Metrics:** `curl http://localhost:4000/metrics` (or the Grafana/Prometheus
  stack under the `monitoring` profile) shows `litellm_*` counters broken down
  by task alias and model.
- **Health:** `curl http://localhost:4000/health/liveliness`.

## Notes

- Host port `4000` is bound to `127.0.0.1` only, like the rest of the stack.
- No provider key is ever written to `infra/litellm/config.yaml` — aliases
  let LiteLLM resolve the selected provider's native credentials.
