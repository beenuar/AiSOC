# Data flows and egress

This page states exactly what leaves your perimeter under each configuration,
so the README's "runs on your infrastructure" claim is precise rather than
aspirational.

The full lifecycle — what is stored, for how long, and how it is encrypted —
is in [`docs/security/data-handling.md`](../security/data-handling.md). This
page is the egress question on its own.

## What never leaves

- **No telemetry to the AiSOC project.** There is no phone-home and no
  "model improvement" callback. Three controls hold it, because each is blind
  where the others see: `scripts/check_default_egress.py` reads every
  service's declared settings defaults and fails on a public host no air-gap
  guard covers; `tests/test_no_default_egress.py` puts a socket guard in front
  of each service's import and ASGI startup, catching URLs built at run time
  that the static gate cannot see; and
  [`container-egress.yml`](../../.github/workflows/container-egress.yml) runs
  images built from the commit under test on a `--internal` Docker network
  with a DNS sinkhole as their only resolver.
- **Your stores.** Database, object storage, graph, cache and the Kafka spine
  stay on your infrastructure.

## The one egress that exists: your chosen model

The investigation agent calls a model. There are three ways to configure it.

### 1. Local model — the default, and fully air-gapped

`make up` ships `llama3.2:3b-instruct-q4_K_M` and runs it in the `ollama`
container beside everything else. No account, no key, no GPU, and **no
evidence leaves your network at all**. This is the only mode in which the "no
data leaves" claim is unconditionally true, and it is what a default install
does.

`infra/compose/docker-compose.airgap.yml` is the same thing with no route off
the host.

### 2. Hosted model, pseudonymized — what you get if you configure a provider

Evidence is pseudonymized before egress.

**This paragraph used to be false, and the correction is worth keeping.** The
reversible pseudonymizer (`services/agents/app/privacy/redactor.py`) existed
and was unit-tested, and **no LLM call site invoked it** — so this page
described a planned control as a shipped one. It is now applied at the
contract layer: `services/agents/app/llm/contract.py` calls
`egress_privacy.open_session`, which is the one place all sixteen agent call
sites already pass through.

Internal IPs, emails, file paths, secrets, internal hostnames and usernames
are replaced with opaque, per-run, in-memory tokens (`USER_1`, `HOST_2`,
`IP_3`). The model reasons over tokens; the ledger and console re-hydrate real
values locally. **Public threat indicators — external domains and IPs — are
preserved deliberately**, because an agent that cannot see the indicator
cannot reason about it.

Gated by `services/agents/tests/test_egress_pseudonymization.py`, which drives
`safe_ainvoke` and inspects what a fake provider actually received rather than
calling the redactor directly. Testing the path rather than the function
immediately found a gap the unit test could not: a bare username in prose
(`running as priya.raghavan`) was going out in the clear, because usernames
were only redacted in the `DOMAIN\user` form or under a user-ish key. The
suite also pins the deliberate exception above, and carries a test that
disables the control and requires the leak assertion to fail, so it cannot
pass vacuously.

### 3. Hosted model, raw — opt-out

If you disable pseudonymization, raw evidence reaches the provider. Use only
with a provider under a signed zero-retention agreement.

## Egress allowlist

Under normal operation the only outbound destinations are the model provider
you configure, the vendors you connected, and the threat-intel feeds you
enable. The only feed on by default is the public CISA Known Exploited
Vulnerabilities catalog, which needs no API key and receives nothing from you
but the request.

A default-deny Kubernetes `NetworkPolicy` ships with the Helm chart at
[`infra/helm/aisoc/templates/networkpolicy.yaml`](../../infra/helm/aisoc/templates/networkpolicy.yaml).
`helm.yml` asserts that it denies by default and that `169.254.169.254/32` —
the cloud metadata endpoint — is excluded from every allowed CIDR.

One limit, stated: it is **opt-in**, because a CNI that does not enforce
NetworkPolicy ignores it silently, and a control that can be silently ignored
must not be presented as one that is always on. On a cluster whose CNI does
not enforce it, or outside Kubernetes, restrict egress at your network layer.

## Air-gapped verification

[`container-egress.yml`](../../.github/workflows/container-egress.yml) is the
CI proof that mode 1 is genuinely air-gapped rather than only documented.

It carries two controls, because zero observations is what a correct run and a
blind probe both look like — and the API's unconfigured startup legitimately
records zero, since it dials Postgres on loopback and needs no DNS:

- a **canary** container wired with the identical network and `--dns` flags
  that *must* be seen by the sinkhole;
- a **red run** against an image that deliberately resolves a public name,
  which the gate must fail on.

One limit, stated: a dial straight to a public IP literal asks no DNS, so it
is *prevented* by the `--internal` network and statically checked by
`check_default_egress.py`, but it is not *observed* by the sinkhole.
