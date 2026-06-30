# Live demo at `tryaisoc.com` — uptime, fallbacks, and how to revive it

The community-maintained live demo at <https://tryaisoc.com> is a real
AiSOC instance running on Fly.io, fronted by a Cloudflare Tunnel. It is
**not** an enterprise SLA — it is best-effort, and it can go offline.

## If `tryaisoc.com` is down right now

**Always-on fallback:** open the repo in
[GitHub Codespaces](https://codespaces.new/beenuar/AiSOC?quickstart=1).
The devcontainer at [`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json)
will bring up Node 20, Python 3.11, Go 1.22, Docker-in-Docker, and the
GitHub CLI for you. Then:

```bash
pnpm aisoc:demo --no-open
```

Click the forwarded port `3000` in the **Ports** panel when prompted —
that's the AiSOC console.

If you have Docker locally, the same one-liner works on your machine:

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC && pnpm aisoc:demo
```

## What "down" usually means

In rough order of likelihood:

1. **Fly.io machine went to sleep.** The smallest paid plan can scale to
   zero when idle. First request after sleep is ~30 s slow as the
   machine warms up — wait, then refresh.
2. **The `release_command` (migrations + seed) failed on the latest
   deploy.** Common after a schema migration. Maintainers will roll back
   or hotfix.
3. **Cloudflare Tunnel reconnect.** The tunnel agent occasionally needs
   a restart after a Cloudflare control-plane refresh.
4. **The maintainer's free Fly.io minutes ran out.** Should be rare, but
   not impossible.

## Bringing it back (for maintainers)

You'll need:

- Fly CLI installed (`flyctl auth login` against the AiSOC org)
- Cloudflare API token with `Tunnel:Edit` for the `tryaisoc.com` zone

Then:

```bash
# 1. Check Fly state
flyctl status -a aisoc-api
flyctl status -a aisoc-agents
flyctl status -a aisoc-web
flyctl status -a aisoc-realtime

# 2. Look at the release_command output of the most recent deploy
flyctl releases -a aisoc-api | head
flyctl logs -a aisoc-api | tail -200

# 3. If it's just sleeping, wake it
flyctl machine start --select -a aisoc-api
flyctl machine start --select -a aisoc-agents
flyctl machine start --select -a aisoc-web
flyctl machine start --select -a aisoc-realtime

# 4. If migrations / seed failed, redeploy from main
git checkout main
git pull --rebase origin main
./infra/fly/fly-demo-deploy.sh

# 5. Cloudflare Tunnel: only if DNS / TLS regressed
cloudflared tunnel info tryaisoc
cloudflared tunnel route dns tryaisoc tryaisoc.com
```

The deploy script ([`infra/fly/fly-demo-deploy.sh`](infra/fly/fly-demo-deploy.sh))
is idempotent — re-running is safe. It runs migrations and the demo
seed (`python -m app.scripts.seed_demo`) as the release_command, so
the `INC-RT-001` LockBit case is always present after a successful
deploy.

## After the deploy: customer-journey checklist

The user has repeatedly flagged broken items post-deploy, so after every
deploy to `tryaisoc.com`, walk the journey:

- [ ] Landing page (`/`) renders without console errors.
- [ ] CTAs ("Try the demo", "Run on Fly.io", "Run on Render") all
      resolve.
- [ ] Sign-in button lands on `/dashboard` (deprecated `/signup` should
      redirect there — not 404).
- [ ] `/dashboard` loads the demo with real `/metrics` data and an
      active investigation.
- [ ] `/cases/INC-RT-001` opens with the Investigation Ledger populated
      (this is the canonical screencast path).
- [ ] At least one alert in `/alerts` and at least one hunt in `/hunt`
      load.
- [ ] `/docs` (Docusaurus) and `/papers/*` render.
- [ ] Footer links resolve.

Any broken link in this checklist is a `tryaisoc.com` deploy regression
and should be fixed before declaring the deploy done.

## When the demo will move to a paid SLA

If demand for an always-on hosted demo gets significant enough to
warrant funding it, the funding model lives in
[`.github/FUNDING.yml`](.github/FUNDING.yml). Until then, this file is
the operations runbook.
