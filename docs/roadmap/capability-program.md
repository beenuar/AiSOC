# Capability program index

A capability-gap closure program, benchmarked against a reference managed
agentic-security service, runs against this repository from a v23.6.1
baseline. Work ships as one pull request per workstream; the workstream ids
those pull-request titles carry (`WS1` … `WS8`, with dotted sub-items like
`WS4.1`) are defined **here and only here** — no other file in the tree
should need them.

| Id | Workstream | Shipped so far |
|----|------------|----------------|
| WS1 | SIEM detection engineering on the customer's SIEM | WS1.1 — `sync_detection_rule` reaches the vendor it names, verifies by read-back and rolls back ([#1998](https://github.com/beenuar/AiSOC/pull/1998)) |
| WS2 | Long-term lake: archive, rehydration, portability, legal holds | in flight at the time of writing ([#2007](https://github.com/beenuar/AiSOC/pull/2007)) |
| WS3 | Phishing pipeline | in flight at the time of writing ([#2011](https://github.com/beenuar/AiSOC/pull/2011)) |
| WS4 | DLP and insider risk | WS4.1 — the normalized DLP finding, one vocabulary over three vendors ([#2003](https://github.com/beenuar/AiSOC/pull/2003)) · WS4.2 — the M365 audit `DLP.All` per-instance switch ([#2004](https://github.com/beenuar/AiSOC/pull/2004)) · WS4.4 — the insider watchlist as a real control: expiry, elevation, departure review, the HR door ([#2005](https://github.com/beenuar/AiSOC/pull/2005)) · WS4.5 in flight ([#2006](https://github.com/beenuar/AiSOC/pull/2006)) |
| WS5 | AI-security runtime | in flight at the time of writing ([#2009](https://github.com/beenuar/AiSOC/pull/2009)) |
| WS6 | Hunting campaigns | in flight at the time of writing ([#2010](https://github.com/beenuar/AiSOC/pull/2010)) |
| WS7 | Resolution, not escalation | WS7.1 — the evidence-backed case root-cause record ([#1999](https://github.com/beenuar/AiSOC/pull/1999)) · WS7.2 — the resolution contract gating `resolved` ([#2000](https://github.com/beenuar/AiSOC/pull/2000)) · WS7.3 — five investigator strategies for the reference-service surfaces ([#2001](https://github.com/beenuar/AiSOC/pull/2001)) · WS7.4 — case ownership and the attention feed ([#2002](https://github.com/beenuar/AiSOC/pull/2002)) |
| WS8 | Team/provider operating model | in flight at the time of writing ([#2008](https://github.com/beenuar/AiSOC/pull/2008)) |

Phase 0 — the baseline gap verification plus the neutral-reference gate
entry — merged as [#1997](https://github.com/beenuar/AiSOC/pull/1997).
Further WS1 sub-items are in flight as
[#2014](https://github.com/beenuar/AiSOC/pull/2014). Rows marked in flight
get their shipped descriptions here when their pull requests merge.

An earlier, unrelated program used the same `WS<n>` shorthand for the
two-way SIEM/ITSM integration work (bidirectional ticketing, push
capabilities, the connect wizard); those comments have likewise been
rewritten to describe the behaviour, and nothing maps that retired
namespace to this table.

## Convention

Workstream ids and the program brief's rule numbers live in **pull-request
titles only** — never in code comments, docstrings, the published OpenAPI
spec, workflow files or the changelog. Those surfaces describe the
behaviour itself; this index is the one place that maps an id to what
shipped. Labels arriving with in-flight pull requests get a follow-up sweep
at program close-out.
