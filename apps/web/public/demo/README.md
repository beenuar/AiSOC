# `apps/web/public/demo/` — screencast assets

This directory is the **canonical home** for the AiSOC walkthrough recording
and the preview loop cut from it. The README, the documentation portal and the
onboarding hero link to the paths below; treat them as a stable contract.

| Asset | What it is | Size |
|---|---|---|
| `demo.mp4` | The deployment walkthrough — 2 min 57 s, 1280×720, H.264, no audio | ~1.6 MB |
| `hero.gif` | README preview loop, 17 s, 860×484, cut from `demo.mp4` | ~1.2 MB |
| `demo-poster.png` | 1280×720 still from the recording, used as a thumbnail | ~0.3 MB |

## What the recording shows, and what is real in it

A single host reached by its LAN address rather than `localhost`, taken from
nothing to an AI triage verdict: `make up`, the console signed into, the CISA
Known Exploited Vulnerabilities feed already populated, one event pushed
through the documented ingest path, `make smoke` reporting ten stages, and the
resulting alert with its measured token counts.

The stack, the images (pulled from `ghcr.io`, not built locally), the threat
feed, the alert and the token counts are real. Demo mode was off and nothing
was seeded. The event was **authored to be representative** — everything
downstream of it is the product's own work. Terminal waits are shortened,
disclosed by an on-screen badge for the whole of every segment it applies to;
browser sections run at real speed.

In this recording both triage runs fell back to the deterministic path, which
the console labels (`model_used` reads `kafka:auto_triage:deterministic`), and
the closing card says so.

**That is no longer the common case.** Triage now asks the provider to
constrain its reply to a JSON object: measured over 50 alerts through the
gateway, replies triage could use went from 44 of 50 to 50 of 50. The recording
predates that change and is kept as recorded rather than re-cut to flatter the
product, so it shows the fallback the older build took.

## How it was produced

- **Terminal** — `asciinema` recording a real PTY, rendered with `agg`. The
  commands genuinely ran; the only edit is capping idle gaps.
- **Browser** — Playwright screen recordings of the live console.
- **Assembly** — `ffmpeg`, concatenating the segments with title cards
  rasterised in a browser (this `ffmpeg` build has no `drawtext` filter).
- **Secrets** — the generated administrator password was filtered out of the
  terminal stream as it was printed (`sed` in the recorded pipeline, visible in
  the recording), the ingest token was only ever held in a shell variable, and
  the browser shows nothing but a masked password field.

## Re-recording

There is no unattended job that regenerates these. `.github/workflows/screencast.yml`
records a different, older product tour of a *deployed* instance
(`apps/web/e2e/demo/screencast.spec.ts`) and uploads it as a workflow artefact;
it does not write into this directory. Re-recording the deployment walkthrough
means driving a real deployment again — the written form of every step is in
[`apps/docs/docs/deployment/walkthrough.md`](../../../docs/docs/deployment/walkthrough.md),
including the recording method, so it can be reproduced rather than guessed at.

Keep the budget in mind if you replace them: these files are committed, so
every byte is cloned by everybody. `demo.mp4` under 8 MB and `hero.gif` under
5 MB are the ceilings; the current files are well inside both.
