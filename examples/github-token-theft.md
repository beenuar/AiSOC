# Walkthrough — `github-token-theft`

> **GitHub PAT leaked.** A personal-access token tied to
> `carol@example.com` is used from an ASN the org has never previously
> contacted, against six private repositories in 11 seconds. The
> token's `repo` scope is wide enough to ex-filtrate every source
> tree Carol can read.

- **Fixture:** [`examples/alerts/github-token-theft.json`](./alerts/github-token-theft.json)
- **MITRE techniques:** T1078, T1555, T1567
- **Severity at intake:** `high`
- **Confidence band (sandbox):** 87/100, `high`

## Run it

```bash
# Offline simulator:
aisoc-sandbox demo --scenario github-token-theft

# Real stack:
pnpm aisoc:submit examples/alerts/github-token-theft.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

The `github-pat-bulk-clone` detection fires on six private-repo clones
from the same `hashed_token_id` within an 11-second window — well
inside the per-token velocity threshold. Fusion correlates against the
threat-intel feed and notes that the source ASN has appeared in two
other OSS supply-chain incidents in the last 90 days.

### Step 1 · TriageAgent · triage

The graph walk pivots from `carol` to her org memberships and the
repos she has push access to. The triage rationale notes that
infostealer behaviour against the OS-native keystore is consistent
with the access pattern (machine compromised, PAT lifted, used
immediately).

**Decision:** Confidence `high` (87/100).

### Step 2 · HuntAgent · hunt

Sweeps for any other action by Carol's PAT or session in the last
24 h — including pushes, branch creations, and Action triggers. The
hunt confirms the actor has only cloned so far; no malicious code has
been pushed yet, which means there's a window to revoke before
secrets are siphoned out of `acme/secrets-vault`.

### Step 3 · RespondAgent · respond

Proposes a five-action containment that closes both the credential
path and the secrets-at-rest path:

- `github.pat.revoke({"user": "carol", "token_prefix": "ghp_xxxAAAAA"})`
- `github.user.session.revoke_all({"user": "carol"})`
- `github.org.audit_member({"user": "carol", "lookback_days": 30})`
- `secrets.rotate({"repositories": ["acme/secrets-vault", "acme/iam"]})`
- `case.create(...)` at severity `high`

**Decision:** 5 actions proposed; awaiting analyst approval (severity high).

## What the analyst would do next

1. Approve `github.pat.revoke` first — it has zero blast radius for
   anyone other than Carol.
2. Look at every commit + Action run + secret access from the cloned
   repos in the last 7 days; even read-only cloning gives the actor
   any secret that was committed historically (which is why
   `secrets.rotate` is part of the response, not optional).
3. Reach Carol via an out-of-band channel (phone, in-person) — not
   Slack or email — to confirm she didn't run the clones and to
   investigate her machine.
4. Open a separate workstream on the org's PAT lifecycle — the org
   should be on fine-grained GitHub App tokens, not personal-access
   tokens with `repo` scope.
