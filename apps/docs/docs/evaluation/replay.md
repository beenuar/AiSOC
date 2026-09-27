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
This page currently documents the **history readers**, which are the first half
of the feature: the part that reads your closed findings and turns your
analysts' labels into something gradeable. The replay runner, the scoring
report and the `aisoc replay` command land next and this page grows with them.
Nothing here describes a capability that is not in the tree.
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

### Microsoft Sentinel

Reads incidents with `properties/status eq 'Closed'`, following `nextLink` so a
window larger than one page is read whole rather than truncated to whatever
sorted first.

`TruePositive` maps to `true_positive`, `BenignPositive` to
`benign_true_positive`, `FalsePositive` to `false_positive`, and
`Undetermined` to `unlabeled`. `classificationReason` and
`classificationComment` are carried as the analyst's reason.

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
