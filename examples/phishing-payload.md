# Walkthrough — `phishing-payload`

> **Click-through to a credential-harvest page.** A phishing email
> passes perimeter filters because the sender domain was less than
> 14 days old and had valid DMARC alignment for a typosquatted root.
> Bob clicks the link 6 minutes after delivery and arrives at a domain
> that imitates the corporate SSO. The credential POST is captured at
> the proxy.

- **Fixture:** [`examples/alerts/phishing-payload.json`](./alerts/phishing-payload.json)
- **MITRE techniques:** T1566, T1566.002
- **Severity at intake:** `high`
- **What the sandbox computes:** `recorded_domain_age` — the payload records `domain_age_days=9`, under the 14-day threshold (read off the event, not looked up)

> **The step-by-step below describes the full stack.** The offline
> `aisoc-sandbox` run shows the same ledger *shape* but computes only what
> arithmetic over these events can give it — there is no model, no graph, no
> Qdrant and no lake in the wheel, and it emits no confidence score, no
> automation tier and no verdict. Values it cannot compute say so, with the
> reason attached. What it does compute for this scenario is listed above.

## Run it

```bash
# Offline simulator:
aisoc-sandbox demo --scenario phishing-payload

# Real stack (after `make up`, with `pip install -e packages/aisoc-cli`):
aisoc submit examples/alerts/phishing-payload.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

The detection chain fires three rules in sequence: `domain-young`
(domain age &lt; 14 days), `email-spf-pass-but-typosquat` (DMARC passed
because the typosquat owns its own SPF), and `proxy-credential-post`
(form fields `username` + `password` posted to a non-allowlisted
domain). Fusion correlates the three events into one incident with a
deterministic correlation narrative.

### Step 1 · TriageAgent · triage

The triage rationale references the known phishing playbook: the
click happened **inside the standard credential-harvest window from
email delivery** (under 10 minutes), and the destination domain
**registered less than 14 days ago** — both are public indicators of
campaign-style credential phishing.

**Decision (sandbox):** 2 of 4 signals computed from the events, 1 fired. No confidence score: the sandbox runs no model, so it has nothing to calibrate one from.

### Step 2 · HuntAgent · hunt

Pivots on Bob's identity to see whether anyone else in the org
received email from `acme-paychecks.com` in the last 7 days. The hunt
also checks whether Bob's session shows any post-credential-POST API
calls (the attacker hasn't logged in with the stolen credential
yet — there's still a window to revoke).

### Step 3 · RespondAgent · respond

Proposes the canonical phishing containment:

- `proxy.block_domain({"domain": "acme-paychecks.com"})`
- `user.session.revoke_all({"user": "bob@example.com"})`
- `user.require_password_reset({"user": "bob@example.com"})`
- `email.search_and_purge({"sender": "no-reply@acme-paychecks.com"})`
- `case.create(...)` at severity `high`

**Decision (live stack):** 5 actions proposed; awaiting analyst approval (severity high).

**Decision (sandbox):** the same actions are listed as call *shapes*, each marked `executed: false`. The automation tier and the approval posture read `not computed` — the live stack resolves both from the capability contract and the approval matrix, and neither is a thing a severity label can select.

## What the analyst would do next

1. Approve `proxy.block_domain` and `user.session.revoke_all`
   immediately — both have small blast radius.
2. Run the `email.search_and_purge` action with caution: it will
   remove the message from every mailbox in the org. Confirm with the
   IT lead first.
3. Add `acme-paychecks.com` to the perimeter blocklist permanently,
   not just at the proxy.
4. Open a brief learning case from the console's **Threat Intelligence**
   tab (`/threat-intel`) so the org's analysts know to look for similar
   typosquat patterns over the next 30 days.
