# Credits

AiSOC is built and improved by a growing community of contributors, security researchers, and operators. This page exists to thank them.

If you've contributed and your name is missing, please open a PR against this file — we'd rather over-credit than miss someone.

---

## Funding and sponsorship

**AiSOC's development is funded and supported by [Cyble](https://cyble.com).**

Cyble provides the engineering time, infrastructure and threat-intelligence
expertise that make this project possible. The platform you can clone and run
today — the ingest spine, the detection corpus, the agent pipeline, the
console — exists because that work was paid for and then released under the
MIT licence rather than kept.

What that does and does not mean:

- **AiSOC is and stays MIT-licensed, and open to anyone.** Sponsorship buys no
  special treatment in the codebase: there are no Cyble-only features, no
  gated modules, and no telemetry reporting back to anyone.
- **You do not need a Cyble relationship to run AiSOC.** `make up` brings up a
  complete, self-hosted stack with a local model and a real public threat feed,
  and the project takes no payment from self-hosters.
- **Cyble also ships a commercial product built on this platform.** That is a
  separate, closed offering; nothing in this repository depends on it, and
  nothing here is a trial of it.

If your organisation depends on AiSOC and wants to support it the same way,
open an issue — contributed engineering time is as welcome as funding.

---

## Security researchers

We deeply appreciate everyone who takes the time to report a security issue responsibly. Reporters listed here have made AiSOC measurably safer for everyone running it.

| Reporter | Contribution |
| --- | --- |
| [**@TanmayZade**](https://github.com/TanmayZade) | Reported [#220](https://github.com/beenuar/AiSOC/issues/220) — prompt injection in classification agents leading to alert auto-close bypass. Also authored the fix in [PR #219](https://github.com/beenuar/AiSOC/pull/219) (prompt sanitiser + untrusted-content wrapping across the five classification agents). |
| [**@mangod12**](https://github.com/mangod12) | Reported [#159](https://github.com/beenuar/AiSOC/issues/159) — proposed cross-tenant isolation tests + nightly CI for RBAC regression. Directly informed the tenant-isolation hardening work that landed in [PR #221](https://github.com/beenuar/AiSOC/pull/221). |
| [**@jay-cyble**](https://github.com/jay-cyble) (Jay Vasant) | Reported [#130](https://github.com/beenuar/AiSOC/issues/130) — a structured review of 13 security & UI issues found via code review + live-site inspection. Multiple findings were used to drive follow-up hardening tickets. |
| [**@pavancharak**](https://github.com/pavancharak) | Reported [GHSA-ghpm-vc6j-hp5r](https://github.com/beenuar/AiSOC/security/advisories/GHSA-ghpm-vc6j-hp5r) — a deprovisioned user kept access through a static role fallback in `has_permission_db()`, and conflicting service-principal permission declarations. Also reported [GHSA-hrc5-w9r3-2g8r](https://github.com/beenuar/AiSOC/security/advisories/GHSA-hrc5-w9r3-2g8r) — re-roling was bounded in one direction only, so a tenant administrator could demote its only peer and then itself, walking the tenant to zero administrators. Verifying the second report also found the last-administrator guard had never worked (it bound text against a `uuid` column and answered 500) and that the audit trail recorded the post-update role as the previous one. Both fixed in [PR #1750](https://github.com/beenuar/AiSOC/pull/1750) (commit `2d034fc`). |

If you want to report a vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/beenuar/AiSOC/security/advisories/new) and read [SECURITY.md](../SECURITY.md) first.

---

## Code contributors

People outside the core maintainer team who have shipped code into AiSOC. Ordered by first merged contribution.

| Contributor | Highlights |
| --- | --- |
| [**@jay-cyble**](https://github.com/jay-cyble) | [PR #135](https://github.com/beenuar/AiSOC/pull/135) — UEBA service environment-variable alignment, closing [#134](https://github.com/beenuar/AiSOC/issues/134). First community contribution to the project. |
| [**@prince30121**](https://github.com/prince30121) | Multiple infrastructure & CI commits (including CI restoration work). 9 commits and counting. |
| [**@ARDA7787**](https://github.com/ARDA7787) | [PR #218](https://github.com/beenuar/AiSOC/pull/218) — Redis-backed scheduler singleton guard + dependency-CVE security-audit CI tooling (`security-audit.yml`, `scripts/security_audit.py`). |
| [**@TanmayZade**](https://github.com/TanmayZade) | [PR #219](https://github.com/beenuar/AiSOC/pull/219) — prompt sanitiser + untrusted-content wrapping across the five classification agents (fix for [#220](https://github.com/beenuar/AiSOC/issues/220)). |
| [**@knowlet**](https://github.com/knowlet) | [PR #1794](https://github.com/beenuar/AiSOC/pull/1794) — removed 66 accidentally-committed wheels (62 MB) from the repository root with an ignore rule so the next one cannot land. [PR #1817](https://github.com/beenuar/AiSOC/pull/1817) — tab deep links kept in sync with navigation across Settings, Cases and the responder shortcuts. [PR #1818](https://github.com/beenuar/AiSOC/pull/1818) — the console renews sessions through the refresh endpoint instead of discarding usable refresh tokens on the first 401. [PR #1797](https://github.com/beenuar/AiSOC/pull/1797) (landed via [#1799](https://github.com/beenuar/AiSOC/pull/1799)) — fixed the Settings → Integrations "Add connector" links that pointed at a route that has never existed, and the onboarding checklist step that navigated to itself. |
| [**@rudycelekli**](https://github.com/rudycelekli) | Independently diagnosed and fixed the issue recorded in the v22.2.0 release notes beside his name. (This credit moved here from a post-tag edit to the released `[22.1.0]` changelog section — released sections are frozen to their tags, and this table is the living credit surface.) |
| [**@officialasishkumar**](https://github.com/officialasishkumar) (Asish Kumar) | Five connector data-loss fixes in the collection-integrity family: the Slack audit cursor (shipped in v23.0.0), [PR #1801](https://github.com/beenuar/AiSOC/pull/1801) — Datadog Cloud SIEM `meta.page.after`, and [PR #1802](https://github.com/beenuar/AiSOC/pull/1802) (landed via [#1805](https://github.com/beenuar/AiSOC/pull/1805)) — Duo `next_offset`, [PR #1815](https://github.com/beenuar/AiSOC/pull/1815) — Cortex XDR/XSIAM offset paging with the shared `read_offset_pages` reader, and [PR #1814](https://github.com/beenuar/AiSOC/pull/1814) (landed via a carry) — Trend Vision One `nextLink`. Each cites the vendor's own paging contract and ships a real transport-level test suite. |
| [**@Toufiqtoufiqbo**](https://github.com/Toufiqtoufiqbo) | [PR #1804](https://github.com/beenuar/AiSOC/pull/1804) — community detection rule `ai-agent-credential-file-read` (T1552.001: an AI agent's file tool reading credential-bearing paths) with positive and negative fixtures, plus two catalogue fixes the rule exposed (a `quarantine_reason` fallback asserting `enabled: false` about files the builder never opened, and the hunt tutorial contradicting the truth-table gate) and LF/POSIX-path portability for five generators whose `--check` was blind to CRLF drift on Windows. |

The full, always-up-to-date list of code contributors lives on the [GitHub contributors page](https://github.com/beenuar/AiSOC/graphs/contributors).

---

## Bug reporters & community feedback

Folks who took the time to file high-signal issues that drove visible improvements in the project:

- [**@cyberdometanza**](https://github.com/cyberdometanza) — Docker / packaging bug reports (e.g. [#82](https://github.com/beenuar/AiSOC/issues/82))
- [**@AMoneronIQBusiness**](https://github.com/AMoneronIQBusiness) — Docker demo / quickstart feedback ([#81](https://github.com/beenuar/AiSOC/issues/81))
- [**@ThiagoDataEngineer**](https://github.com/ThiagoDataEngineer) — Early platform feedback ([#48](https://github.com/beenuar/AiSOC/issues/48))
- [**@alvarofraguas**](https://github.com/alvarofraguas) — Connector / setup feedback ([#44](https://github.com/beenuar/AiSOC/issues/44))
- [**@sonalig-cyble**](https://github.com/sonalig-cyble) — Product feedback ([#131](https://github.com/beenuar/AiSOC/issues/131))
- [**@pitimon**](https://github.com/pitimon) — Three high-signal reports in one day, each stating its own evidence level: the agents metrics endpoint unreachable on default deployments ([#1822](https://github.com/beenuar/AiSOC/issues/1822)), the connector `error_count` semantics mismatch with deployment data proving it ([#1821](https://github.com/beenuar/AiSOC/issues/1821)), and an open-source SIEM connector's pagination gap matched to the fixed class by code inspection ([#1820](https://github.com/beenuar/AiSOC/issues/1820))
- [**@Dhanu188**](https://github.com/Dhanu188) — Two verified first-run breakers reported on [#353](https://github.com/beenuar/AiSOC/issues/353): a fresh install read as behind the whole migration chain because the initdb hook recorded nothing it applied (fixed in [#1808](https://github.com/beenuar/AiSOC/pull/1808)), and `make demo` seeding nothing because the seeder wrote pre-consolidation case statuses the schema refuses (fixed in [#1809](https://github.com/beenuar/AiSOC/pull/1809))

---

## Automation

- [**@dependabot[bot]**](https://github.com/apps/dependabot) — Keeps the dependency tree healthy across every service in the monorepo.

---

## Maintainers

AiSOC is currently maintained by [**@beenuar**](https://github.com/beenuar) (project lead) with help from everyone listed above.

If you'd like to take on ongoing responsibility for an area of the codebase (a connector family, the web console, the agents pipeline, infra, docs), open an issue tagged `maintainership` and let's talk.

---

## How to be added here

You're added automatically if:

- You authored a merged PR
- You reported a security issue that was acknowledged and triaged (via [private advisory](https://github.com/beenuar/AiSOC/security/advisories/new) or a confirmed public issue)
- You filed a high-signal issue that drove a real change in the codebase

If something landed because of you and you're not on this list, that's a bug — please open a PR against `.github/CREDITS.md` and we'll merge it.

Thank you for making AiSOC better.
