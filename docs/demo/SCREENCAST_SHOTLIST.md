# 90-second AiSOC demo screencast — shot list

> Phase 4.3 / T6.4 — the canonical script for the public product walkthrough.
>
> If you're recording the screencast, **follow this file frame-by-frame**.
> If you're editing the marketing site to embed the cut, the file path
> the player loads is `apps/web/public/demo/demo.mp4` (master) and
> `apps/web/public/demo/demo-poster.png` (poster). The recorder pipeline
> in `.github/workflows/screencast.yml` writes both to that directory.
>
> Total target runtime: **90s ±2s**. Anything beyond 92s gets re-cut.

## Pre-roll (0:00 — 0:02)

* AiSOC wordmark fades up on a dark background.
* No voiceover. No music sting. Two seconds, dead silent — sets up the
  "we're going to show you, not pitch you" frame.

## Shot 1 · Alert hits (0:02 — 0:14)

* **Visual:** browser at `tryaisoc.com/dashboard/alerts`. A new alert
  card animates in from the top (the seed dataset includes a Crowdstrike
  EDR detection for `wmic.exe` spawn from `winword.exe`).
* **Voice (12 words):** "An EDR detection comes in. AiSOC opens an
  investigation automatically."
* **Cut on:** the alert card finishing its slide-in animation.

## Shot 2 · Auto-investigation timeline (0:14 — 0:30)

* **Visual:** click into the alert. Investigation view opens. The
  timeline ticks through: enrichment → triage agent → correlation → host
  graph. The narration agent panel shows three sentences of natural
  language summary.
* **Voice (15 words):** "The triage agent enriches the event, queries
  the host graph, and writes a plain-language summary."
* **Cut on:** the narration agent finishing the third sentence.

## Shot 3 · Tool calls + audit trail (0:30 — 0:44)

* **Visual:** scroll the right rail. Every tool call the agent made is
  listed with arguments + result. Hover over `crowdstrike.isolate_host`
  shows the audit-trail expandable card with the OPA decision JSON.
* **Voice (13 words):** "Every tool call is logged with arguments,
  result, and the OPA policy decision."
* **Cut on:** the OPA decision JSON visible for two seconds.

## Shot 4 · Human-in-the-loop approval (0:44 — 0:58)

* **Visual:** the agent proposes `isolate_host`. Approval modal appears.
  Show the inline diff (host → isolated), the playbook reference, and
  the "Approve" button. Click Approve.
* **Voice (16 words):** "High-impact actions need a human. The modal
  shows what will change before you say yes."
* **Cut on:** the modal dismissing.

## Shot 5 · Action executor (0:58 — 1:10)

* **Visual:** the timeline shows the executor card running. Status goes
  Pending → Running → Success. The host card updates to "Isolated"
  with the Crowdstrike host ID and a link out to the EDR console.
* **Voice (14 words):** "AiSOC fires the action against Crowdstrike,
  records the response, and updates the host."
* **Cut on:** the host card showing "Isolated".

## Shot 6 · Compliance + report (1:10 — 1:20)

* **Visual:** click the "Generate report" button. The compliance
  dashboard tile updates ("1 contained · 0 escalated"). The PDF report
  opens in a side panel.
* **Voice (12 words):** "Every step is captured for the SOC 2 evidence
  trail. One click. Done."
* **Cut on:** the PDF cover page in frame.

## Outro (1:20 — 1:30)

* **Visual:** fade to the AiSOC wordmark on dark with the URL
  `tryaisoc.com` and "MIT licensed · github.com/beenuar/AiSOC" under
  it.
* **Voice (8 words):** "Try the live demo at tryaisoc.com."

---

## Recorder pipeline

1. The CI workflow `.github/workflows/screencast.yml` runs on a manual
   trigger only (recording is a deliberate human act, not a per-push
   side effect).
2. The workflow spins up a Playwright runner against a pinned dataset
   (`apps/web/e2e/fixtures/demo-seed.json`) so the alert that animates
   in is always the same wmic.exe detection. Without a pinned seed the
   screencast would drift on every record.
3. The runner navigates through Shots 1–6 with hand-tuned timing
   constants in `apps/web/e2e/demo/screencast.spec.ts` and writes
   `demo.webm` + a poster frame.
4. ffmpeg transcodes the webm to mp4 (H.264 / AAC) at 1080p for browser
   compatibility, then uploads both as workflow artifacts. A separate
   PR commits them to `apps/web/public/demo/` so the marketing site can
   serve them.

## Why this lives in `docs/demo/` (not the marketing repo)

The script is engineering-owned because every shot maps to a specific
code path (which means a refactor that moves the host-graph panel
silently breaks Shot 2). Pinning the shot list next to the code keeps
that link visible.
