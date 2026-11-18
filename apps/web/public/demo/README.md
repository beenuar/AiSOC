# `apps/web/public/demo/` — screencast assets

This directory is the **canonical home** for the AiSOC walkthrough recording
and the preview loop cut from it. The README, the documentation portal and the
onboarding hero link to the paths below; treat them as a stable contract.

| Asset | What it is | Size |
|---|---|---|
| `demo.mp4` | The deployment walkthrough — 2 min 1 s, 1280×720, H.264, no audio | ~2.4 MB |
| `hero.gif` | README preview loop, 17 s, 820×462, cut from the browser segments | ~1.5 MB |
| `demo-poster.png` | 1280×720 still from the recording, used as a thumbnail | ~0.1 MB |

## What the recording shows, and what is real in it

A single host taken from nothing to an AI triage verdict, captured on a
**v23.5.0** stack on 2026-11-18: `make up` on empty volumes pulling the
published `ghcr.io` images, sixteen generated secrets, the schema initialised,
sixteen services up, `docker compose ps` healthy; then the console signed into,
the setup wizard's **Load sample data** pushing five scenarios through the same
ingest endpoint a real connector uses; the alert queue filling, a local-model
triage verdict opened in the investigation rail, the risk-based entity queue
with its seen-on hosts, the live CISA KEV catalogue, the cost dashboard; and
`make smoke` closing on ten green stages.

The stack, the images (pulled from `ghcr.io`, not built locally), the threat
feed, the alerts, the verdicts and the token counts are real. Demo mode was
off and nothing was seeded into the database. The sample events are the
labelled `aisoc_sample` set, authored to be representative and pushed through
the ingest API — everything downstream of them is the product's own work.
Terminal idle waits are capped (disclosed by an on-screen badge); the browser
sections run at real speed.

**The triage verdicts in this recording are real local-model output.** All
five alerts were triaged by the bundled `llama3.2:3b-instruct-q4_K_M` through
the LiteLLM gateway — ~1,245 prompt tokens and ~25 s per investigation on CPU,
persisted to the ledger — not the deterministic fallback an earlier recording
showed. No hosted provider was configured and none has ever been exercised
here. The console footer reads `v23.5.0`, matching the stills in
`apps/web/public/screenshots/` captured from the same release.

## How it was produced

- **Terminal** — `asciinema` recording a real PTY, rendered with `agg`. The
  commands genuinely ran; the only edit is capping idle gaps.
- **Browser** — Playwright screen recordings of the live console.
- **Assembly** — `ffmpeg`, concatenating the segments with title cards
  rasterised in a browser (this `ffmpeg` build has no `drawtext` filter).
- **Secrets** — the generated administrator password was filtered out of the
  terminal stream as it was printed (`sed` in the recorded pipeline), `make
  smoke` reports an ingest credential is available without printing it, and the
  browser shows nothing but a masked password field. The password used to sign
  in was read from the capture host out of band, never on screen.

## Re-recording

There is no unattended job that regenerates these. `.github/workflows/screencast.yml`
records a different, older product tour of a *deployed* instance
(`apps/web/e2e/demo/screencast.spec.ts`) and uploads it as a workflow artefact;
it does not write into this directory. Re-recording the deployment walkthrough
means driving a real deployment again — the written form of every step is in
[`apps/docs/docs/deployment/walkthrough.mdx`](../../../docs/docs/deployment/walkthrough.mdx),
including the recording method, so it can be reproduced rather than guessed at.

Keep the budget in mind if you replace them: these files are committed, so
every byte is cloned by everybody. `demo.mp4` under 8 MB and `hero.gif` under
5 MB are the ceilings; the current files are well inside both.
