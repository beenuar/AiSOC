# Data flows and egress

Phase 1.4 of the world-class program. This page states exactly what leaves your
perimeter under each configuration, so the README's "runs on your
infrastructure" claim is precise rather than aspirational.

## What never leaves

- AiSOC sends **no telemetry to the AiSOC project** and makes no "model
  improvement" callbacks. There is no phone-home. (Gated: Phase 12 trust
  surface adds a no-telemetry CI assertion.)
- Your database, object storage, graph, cache, and Kafka spine stay on your
  infrastructure.

## The one egress that exists: your chosen LLM

The investigation agent calls an LLM you configure. There are three modes:

1. **Local model (fully air-gapped).** Point `AISOC_LLM_*` at Ollama / vLLM /
   llama.cpp. No evidence leaves your network at all. This is the only mode in
   which the "no data leaves" claim is unconditionally true.
2. **Hosted LLM with redaction (default).** When you configure a cloud provider
   (Anthropic/OpenAI), evidence is pseudonymized before egress by
   `services/agents/app/privacy/redactor.py`: internal IPs, emails, file paths,
   secrets, internal hostnames, and usernames are replaced with opaque,
   per-run, in-memory tokens (`USER_1`, `HOST_2`, `IP_3`). The LLM reasons over
   tokens; the ledger and console re-hydrate real values locally. Public threat
   indicators (external domains/IPs) are preserved so the agent can reason about
   them. Gated: `services/agents/tests/test_privacy_redactor.py` asserts zero
   raw customer PII survives redaction.
3. **Hosted LLM without redaction (opt-out).** If you disable redaction, raw
   evidence reaches the provider. Use only with a provider under a signed
   zero-retention agreement.

## Egress allowlist

The only outbound destinations under normal operation are the LLM provider you
configure and the threat-intel feeds you enable. A rendered Kubernetes
`NetworkPolicy` that enforces this allowlist ships with the Helm chart (Phase 1.4
continuation / Phase 2); until then, restrict egress at your network layer.

## Air-gapped verification (planned gate)

Phase 1.4 continuation adds a CI job that runs a full investigation with network
egress blocked and asserts success on the local-model path — proving mode 1 is
genuinely air-gapped, not just documented.
