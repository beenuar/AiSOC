# Runbook: managed-mode provision failure (re-run)

> **Severity:** non-paging — customer onboarding blocker only.
> **When to use:** the `managed-auto-provision` workflow run for a new
> tenant manifest exited red, or the operator ran `provision.sh`
> locally and one of its steps failed partway through.

## What this runbook does **not** cover

* Day-2 customer-facing incidents on an already-live managed tenant —
  use [`http-5xx-high`](./http-5xx-high.md),
  [`service-down`](./service-down.md), or
  [`database-incident`](./database-incident.md) instead.
* Sovereign-mode tear-down — that workflow lives under
  `infra/terraform/{aws,azure,gcp,byoc}/`, not in this directory.

## Mental model

`provision.sh` is a linear pipeline with **eight checkpoints**:

1. Render templates from the manifest.
2. `flyctl apps create` for api / agents / web / realtime.
3. `flyctl postgres create`.
4. `flyctl postgres attach`.
5. `flyctl redis create` (extract `REDIS_URL`).
6. Mint `AISOC_CREDENTIAL_KEY` (one-time, only if not already set).
7. `flyctl deploy` for each component.
8. `flyctl certs create` for the three public hostnames.

Every step is **idempotent**. Re-running the whole script is the
correct response in almost every failure case. The only "manual fix"
checkpoints are #3 (Postgres) and #6 (Fernet key), because those create
data-bearing resources that must not be silently overwritten.

## First five minutes

```bash
# 1. Look at the GitHub workflow log to find the first failing step.
gh run view --log-failed --job <job-id>

# 2. Confirm the manifest is well-formed (CI should already catch this).
python scripts/audit_managed_tenants.py

# 3. List what already exists for this slug.
SLUG=<slug>
for app in api agents web realtime postgres redis; do
  flyctl apps show aisoc-$SLUG-$app 2>&1 | head -3
done

# 4. Re-run the workflow against the same manifest.
gh workflow run managed-auto-provision.yml \
  -f manifest=infra/fly/managed/tenants/$SLUG.yaml \
  -f action=provision
```

## Recovery matrix — which step failed?

### Step 1 (render)

* `render.sh: envsubst not found` → install `gettext` on the runner.
* `render.sh: invalid slug` → fix the slug in the manifest, push a PR.

### Step 2 (apps create)

* `Name has already been taken` on a slug we don't own → the slug is
  taken in another Fly org. Edit the manifest's slug, push a PR.
* Token error → `FLY_API_TOKEN` repo secret is wrong/expired. Rotate
  it in the Fly dashboard and update the GitHub repo secret.

### Step 3 (postgres create)

* If this is a **fresh** tenant and the create call exited non-zero,
  verify in the Fly dashboard whether the cluster was actually
  created. If it was: rerun `provision.sh`, which will skip create on
  the next attempt. If it wasn't: rerun.
* If this is an **existing** tenant being re-provisioned, the create
  call no-ops by design (it falls through to attach). No action.

### Step 4 (postgres attach)

Usually fails because the Postgres cluster is still bootstrapping.
Wait 60s, rerun.

### Step 5 (redis create)

The `REDIS_URL` is parsed from `flyctl redis create` output. If the
CLI changes its output format, the awk pattern in `provision.sh` will
return empty. Patch the awk pattern; in the meantime extract the URL
by hand:

```bash
flyctl redis status aisoc-$SLUG-redis --json | jq -r '.url'
flyctl secrets set -a aisoc-$SLUG-api REDIS_URL=<url>
flyctl secrets set -a aisoc-$SLUG-agents REDIS_URL=<url>
flyctl secrets set -a aisoc-$SLUG-realtime REDIS_URL=<url>
```

Then rerun `provision.sh` to pick up where it left off.

### Step 6 (Fernet key)

**Do not** rerun the script if the failure happened *after* the secret
was set on the api app but *before* it was mirrored onto the agents
app, because the script gates re-minting on the api app's secret. If
you're in that window:

```bash
KEY=$(flyctl secrets list -a aisoc-$SLUG-api --json | \
        jq -r '.[] | select(.name == "AISOC_CREDENTIAL_KEY") | .digest')
# digest is a hash; you can't recover the key. Instead:
KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
flyctl secrets set -a aisoc-$SLUG-api    AISOC_CREDENTIAL_KEY=$KEY
flyctl secrets set -a aisoc-$SLUG-agents AISOC_CREDENTIAL_KEY=$KEY
```

The connector-credential store is empty at this point in onboarding,
so re-minting is safe.

### Step 7 (deploy)

Per-component deploy failures are application bugs, not provisioning
bugs. Switch to the application runbook:

* api → [`http-5xx-high`](./http-5xx-high.md)
* agents → [`action-executor-failures`](./action-executor-failures.md)
* realtime / web → [`service-down`](./service-down.md)

After the underlying bug is fixed and a new image is pushed,
re-running `provision.sh` will re-deploy from latest.

### Step 8 (cert)

Fly cert issuance can take a few minutes. Re-running `provision.sh`
is safe; the cert verification will eventually succeed once the
CNAME is in place. If the customer hasn't pointed DNS yet, this step
will pending forever — that's expected, not a failure.

## How to give up cleanly

If a provision fails badly enough that you want to start over with the
same slug:

```bash
./infra/fly/managed/deprovision.sh $SLUG
# ... wait 5min for Fly to fully release the app names ...
gh workflow run managed-auto-provision.yml \
  -f manifest=infra/fly/managed/tenants/$SLUG.yaml \
  -f action=provision
```
