---
title: Evaluate AiSOC on your own history
sidebar_label: Replay evaluation
---

# Evaluate AiSOC on your own history

The published [benchmark](../benchmark.md) measures AiSOC against a synthetic
corpus, and three of its four axes are substrate self-consistency rather than
agent accuracy. That is a useful regression gate and a poor basis for deciding
whether to trust the product on your estate.

Replay evaluation answers the question that actually matters: **how does AiSOC
triage compare with what your analysts already decided, on your data?**

:::note What exists today
Everything on this page is in the tree and reachable: the history readers, the
replay runner, the scoring report, the `aisoc replay` command, the API job and
the **Evaluate on your history** console page. Nothing here describes a
capability that does not exist.
:::

## The one rule worth reading first

**A label AiSOC cannot name is excluded from accuracy. It is never guessed.**

This is the difference between an evaluation and a sales sheet, and it costs
sample size on purpose.

Every vendor in this list ships a way for an analyst to say "I do not know".
Splunk Enterprise Security has dispositions named *Other* and *Undetermined*.
Microsoft Sentinel has an `Undetermined` classification. Defender XDR has
`Unknown`. An analyst who chose one of those made no claim, and folding it into
`true_positive` because the finding happened to be closed would manufacture
agreement out of an admission of uncertainty.

Those rows are read, counted and reported as `unlabeled`. They never enter the
confusion matrix. If your history is mostly unlabeled, the report tells you
that instead of printing a confident number derived from a handful of rows.

## The canonical taxonomy

Vendor labels map onto the same taxonomy AiSOC already uses when it writes a
disposition back into your SIEM, so a verdict means the same thing in both
directions.

| Canonical | Means |
|---|---|
| `true_positive` | Valid detection of malicious or unauthorised activity. |
| `benign_true_positive` | Valid detection of authorised or expected activity. The rule was **correct**, so this is not a false positive and never counts toward a rule's false-positive rate. |
| `false_positive` | Invalid detection. The intended condition was not present. |
| `benign` | Real but non-threatening activity, making no claim about whether the rule was right. |
| `needs_review` | Insufficient evidence to decide safely. |
| `escalate` | Analyst-forced escalation. |
| `unlabeled` | **Not a verdict.** The analyst recorded nothing this platform can name. Excluded from accuracy. |

## What each vendor needs

### Splunk Enterprise Security

Reads notables at status 5 (Resolved) and 6 (Closed) through the `notable`
macro, which is what resolves the correct index on a customised install.

The six stock dispositions map as follows. Dispositions 5 and 6 are absent on
purpose, and a site that has added custom dispositions from 7 upward will see
them as `unlabeled`.

| Splunk ES | Canonical |
|---|---|
| `disposition:1` True Positive, Suspicious Activity | `true_positive` |
| `disposition:2` Benign Positive, Suspicious But Expected | `benign_true_positive` |
| `disposition:3` False Positive, Incorrect Analytic Logic | `false_positive` |
| `disposition:4` False Positive, Inaccurate Data | `false_positive` |
| `disposition:5` Other | `unlabeled` |
| `disposition:6` Undetermined | `unlabeled` |

Enterprise Security is routinely customised, so the reader accepts a
`search_override`. Supply your own SPL if your site renames statuses or keeps
review state in its own lookup. It must return these fields: `event_id`,
`rule_id`, `rule_name`, `urgency`, `disposition`, `review_time`, `reviewer`,
`comment`.

It should also return the notable's asset and identity fields — `src`, `dest`,
`dvc`, `orig_host`, `user` and `src_user` — which is what the default search
does. `| fields` keeps only what it names, so a search that omits them
produces findings with no host and no user, and triage is then graded on an
alert that says who raised it and nothing about who it happened to.

### Microsoft Sentinel

Reads incidents with `properties/status eq 'Closed'`, following `nextLink` so a
window larger than one page is read whole rather than truncated to whatever
sorted first.

`TruePositive` maps to `true_positive`, `BenignPositive` to
`benign_true_positive`, `FalsePositive` to `false_positive`, and
`Undetermined` to `unlabeled`. `classificationReason` and
`classificationComment` are carried as the analyst's reason.

An incident's `properties` carry no account and no host, so the reader also
calls each incident's `entities` endpoint and attaches the result. The app
registration therefore needs to be able to read entities on the workspace; if
it cannot, the incident still contributes its analyst's classification and
reaches triage without a host or a user rather than failing the window.

### Elastic Security

**Elastic ships no disposition field.** Closing a signal sets
`kibana.alert.workflow_status` to `closed` and records no reason at all.

So an untagged Elastic deployment yields **no labels**, and the reader says so
rather than inferring that a closed signal was a true positive. If you want
your Elastic history graded, adopt one of these values in
`kibana.alert.workflow_tags`:

| Workflow tag | Canonical |
|---|---|
| `true_positive` | `true_positive` |
| `benign_positive` or `benign_true_positive` | `benign_true_positive` |
| `false_positive` | `false_positive` |
| `benign` | `benign` |

A signal carrying two conflicting tags is `unlabeled`, because picking one
would be a guess.

### IBM QRadar

Reads offenses with `status = CLOSED`. An offense carries only a numeric
`closing_reason_id`, so the id-to-text table is read from your appliance at
`/api/siem/offense_closing_reasons` rather than hardcoded, because closing
reasons are site-configurable.

The three stock reasons map as follows. A custom reason, or one the appliance
declines to resolve, is `unlabeled`.

| QRadar closing reason | Canonical |
|---|---|
| False-Positive, Tuned | `false_positive` |
| Non-Issue | `benign` |
| Policy Violation | `true_positive` |

"Non-Issue" is deliberately `benign` and not `benign_true_positive`. It makes
no claim about whether the rule was right, and crediting the detection with
being correct on the strength of an analyst saying only that nothing happened
would inflate the rule's apparent quality.

If the closing-reason lookup is refused, the offenses are still read and every
row lands `unlabeled`. A partial answer beats no answer.

### Microsoft Defender XDR

Reads alerts with `status eq 'Resolved'`, following `@odata.nextLink`.

Defender separates two fields that must not be conflated. `classification` is
the verdict and is what maps to a disposition. `determination` is the reason
(Malware, SecurityTesting, Phishing and so on) and is carried as the analyst's
reason, never scored. Putting a reason code into a confusion matrix would be a
category error.

| Defender classification | Canonical |
|---|---|
| `TruePositive` | `true_positive` |
| `InformationalExpectedActivity` | `benign_true_positive` |
| `FalsePositive` | `false_positive` |
| `Unknown` | `unlabeled` |

## How a replay runs

### Shadow mode writes nothing

A replay runs the same triage path a live alert takes. Not a copy of it: the
same `FusedAlertTriageWorker.triage` the Kafka consumer calls on every fused
alert, constructed with two different sinks.

Persistence is injected. In production the worker holds a writer that records
the verdict to the Investigation Ledger and the `alerts` row, writes the
outcome prior, queues approvals, caches the verdict for deduplication and
pushes the disposition back to your SIEM. In a replay it holds one that counts
each of those and performs none of them. The count is reported, because a
replay that quietly stopped replaying and a replay whose writes were suppressed
both write nothing, and only the count tells them apart.

The full investigation graph is not run during a replay, because every node it
executes records itself to the ledger. That does not change the measurement:
the verdict is fixed before escalation is reached, and a test drives the real
worker with a graph runner that tries to rewrite the verdict to prove it.

### Point-in-time context, so the test window cannot answer itself

History is ordered by close time and cut by time, 70/30 by default. The later
period is the test window. A finding closed at the exact split instant stays on
the train side.

Organisation memory and outcome priors are captured **once**, at the split, and
served from that snapshot for the whole run. Without this, a replay feeds
itself: production writes every verdict back as a per-signature prior and reads
that prior before triage, so the verdict on one alert auto-closes the next
alert with the same evidence, and the evaluation grades an answer it supplied
three seconds earlier. The deduplication cache does the same thing one layer
earlier and leaves no trace in either store.

There is one honest gap. Organisation-memory statements, as the API serves
them, carry no creation time, so a statement cannot be tested against the split
and is kept. The report publishes how many statements were in that position, as
`statements_without_timestamp`, rather than claiming a tighter freeze than the
data supports.

### What the report says

Recall on malicious leads, because it is the number you are deciding on and the
one an imbalanced queue hides. Beside it: per-class precision and recall, a
confusion matrix, the abstention rate, reliability bins with an expected
calibration error, the hallucination rate with the indicators behind it,
per-rule and per-source breakdowns, and bootstrap confidence intervals.

Two rules govern what it prints.

**Below 30 malicious cases in the test window, no headline accuracy is
printed.** The count and the reason are printed instead. On a queue where
almost everything is a false positive, an agent that calls everything benign
scores well, and that figure would describe your queue rather than the product.

**A rate with no denominator reads "not measured", never 0.** A zero in a
recall column says the agent missed every case of that class; having never been
asked is a different fact.

### What a replay is not

A replayed finding is normalized by the same connector `normalize()` your live
pipeline uses, reached over HTTP in the connectors service so there is no
second copy of any vendor's field mapping to drift. What it does not carry is
everything fusion adds to a live alert: correlation across related events, the
fused confidence score, the deterministic narrative and entity resolution.
Every report states this in its method section. Replay measures triage on a
single normalized finding, not the whole pipeline.

## Running one

There are three ways in, and all three drive the same job. The API
orchestrates it, because no single process can hold the three services
involved: `services/actions` owns the SIEM credentials and the readers,
`services/agents` owns triage, and `services/connectors` owns `normalize()`.
All three package their code as a top-level `app`, so a process that imported
two of them would get one of them.

### The console

**Evaluate on your history**, in the left-hand navigation. Pick a connected
source and a window, and the page shows the report when the run finishes.

Two things about how it presents a result are deliberate.

**No number appears without the sample size behind it.** Recall on malicious
renders with the count of malicious cases it was computed over, the headline
accuracy with the count of answered decisions, and the history read with how
many of those findings carried an analyst label at all. A precision of 1.00
over two predictions is not a precision of 1.00 over two hundred, and a panel
that prints only the ratio has thrown that away.

**When the window is too thin for a headline, the page prints the reason
rather than a number.** Below the floor of malicious cases the headline card
reads "withheld" and the sentence explaining why is rendered underneath: how
many malicious cases the window held, how many are required, and why a figure
computed over fewer would describe the queue rather than the agent. It is not
a dash, and it is not a zero. Zero would say the agent got every answer wrong,
which is a different fact with a different remedy.

The method block sits beside the report, not behind a tab: the split point,
the frozen-context counts, the bootstrap seed and resample count, how many
writes shadow mode intercepted, and the list of enrichments a replayed finding
does not carry.

### The CLI

```bash
aisoc replay --connector-id <uuid> --output report.md
```

The tenant comes from the credential (`--api-key`, or `AISOC_API_KEY`). There
is no tenant flag, because a flag would be a value you chose that nothing
checked.

Useful options:

| Option | What it does |
|---|---|
| `--since` / `--until` | Pin the window. Omitting them dates it from now, so a second run covers a different window and produces a different report. |
| `--format markdown\|json\|pdf` | Which export to write. All three come from the artefact stored when the run completed. |
| `--output PATH` | Where to write it. Without it, markdown and JSON go to stdout and every progress line goes to stderr, so `aisoc replay ... > report.md` produces the report and nothing else. |
| `--exclude-latency` | Replace the two wall-clock latency figures with a note. See below. |
| `--no-wait` / `--collect <id>` | Queue a run and collect it later. |
| `--seed` / `--resamples` | Change the bootstrap. Both travel into the report either way. |

### The API

```
POST /api/v1/evaluations/replay        -> 202 with an id
GET  /api/v1/evaluations/replay/{id}   -> poll to `completed` or `failed`
GET  /api/v1/evaluations/replay/{id}/export?format=markdown|json|pdf
GET  /api/v1/evaluations/replay/{id}/decisions
```

Starting a run needs `connectors:write`, the same bar as testing a connector,
because it does the same kind of thing: an outbound call to your SIEM with
stored credentials. Reading a report needs `reports:read`.

Results live in two tenant-scoped tables with row-level-security policies. The
report is stored as the renderer produced it and served back unchanged, rather
than re-rendered on each request: a report re-rendered later by a newer
renderer is a different artefact from the one you read. The per-decision rows
are kept separately, and carry the evidence triage was given, so a number you
disagree with can be re-derived rather than re-argued.

## Reproducibility, stated precisely

**A report reproduces byte for byte between two runs over the same pinned
window, apart from the two wall-clock latency figures.**

Everything else is a property of the input and the code: the bootstrap is
seeded and records its seed, the split is a total order over `(closed_at,
finding_id)`, and the renderer emits no timestamp and iterates nothing
unsorted. Mean and p95 latency measure the machine the replay ran on and will
differ between two runs on one host, let alone two.

`--exclude-latency` on the CLI, and `exclude_latency=true` on the export
route, replace those two figures with a note. That is a filter over the stored
artefact, not a second rendering, and the function that removes the line lives
beside the one that emits it so the two cannot drift.

Two caveats worth stating plainly:

- **Pin the window.** An omitted `--since` or `--until` dates the window from
  now, which is a different window on a second run and therefore a different
  report for a reason that has nothing to do with determinism.
- **Reproducibility is not accuracy.** A deterministic model path reproduces
  because it is deterministic. Pointed at a hosted model, two runs may differ,
  and that is a property of the model rather than of this pipeline.

`tests/e2e/test_replay_cli_end_to_end.py` is what holds this claim up. It runs
the CLI twice against a mocked Splunk ES holding 200 recorded closed notables,
through the API, the actions service, the connectors service and the agents
service, and compares the bytes. It also fetches both reports *without* the
exclusion and asserts that latency is the only line that differs, so the
comparison cannot pass on a stripped artefact that hid something else.

## Privacy: where your data goes

Reading your history happens inside your deployment, against credentials you
already configured for that SIEM. The findings are processed by the services
you are already running.

**Data leaves your deployment only when the model you configured is hosted by
a third party.** If AiSOC is pointed at a hosted provider, the alert content
that triage reasons over is sent to that provider in the ordinary way, exactly
as it is during live triage. If you run a local model, through the bundled
gateway or your own, nothing leaves.

This is a property of your model configuration and not of replay evaluation.
Replay adds no new egress: it reads findings you already own and runs them
through the same triage path production uses.

## Limits

- **Reachability, not completeness.** The readers parse each vendor's
  documented response shape. They cannot know whether your retention window
  holds the period you asked for, or whether your analysts labelled
  consistently.
- **An unparseable close time is an error, not a default.** A silently wrong
  close time would put a finding on the wrong side of a train/test split and
  leak the answer into its own evaluation, so it raises.
- **Elastic yields nothing without tags**, as above.
- **The vendor's own label is kept verbatim** alongside the mapped one, so you
  can audit a mapping you disagree with rather than having to trust it.
- **Fusion's enrichments are absent**, as above. A replay grades triage on one
  normalized finding at a time.
- **Tool calls are structurally zero.** Shadow mode declines escalation, and
  escalation is the only stage of this path that calls tools. The field is
  recorded rather than omitted so a future change that gives triage a tool
  shows up as a number moving off zero.
- **PDF export needs a native stack.** WeasyPrint's Pango, Cairo and GLib
  libraries are installed in the API container image and are routinely absent
  on a local checkout. When they are, the PDF route answers 503 naming them,
  rather than serving an empty file; JSON and Markdown carry the same report
  and need nothing extra.
- **Hallucination counting errs high.** Indicators are extracted from the
  agent's own reasoning with the same pattern set the synthetic-corpus grader
  checks against, so a phrase shaped like a domain is checked and, if absent
  from the evidence, counted. The published rate is a ceiling, and the
  indicators behind it travel with the report so you can re-derive it.
