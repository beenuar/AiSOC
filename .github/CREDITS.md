# Credits

AiSOC is built and improved by a growing community of contributors, security researchers, and operators. This page exists to thank them.

If you've contributed and your name is missing, please open a PR against this file — we'd rather over-credit than miss someone.

---

## Security researchers

We deeply appreciate everyone who takes the time to report a security issue responsibly. Reporters listed here have made AiSOC measurably safer for everyone running it.

| Reporter | Contribution |
| --- | --- |
| [**@TanmayZade**](https://github.com/TanmayZade) | Reported [#220](https://github.com/beenuar/AiSOC/issues/220) — prompt injection in classification agents leading to alert auto-close bypass. Also authored the fix in [PR #219](https://github.com/beenuar/AiSOC/pull/219) (prompt sanitiser + untrusted-content wrapping across the five classification agents). |
| [**@mangod12**](https://github.com/mangod12) | Reported [#159](https://github.com/beenuar/AiSOC/issues/159) — proposed cross-tenant isolation tests + nightly CI for RBAC regression. Directly informed the tenant-isolation hardening work that landed in [PR #221](https://github.com/beenuar/AiSOC/pull/221). |
| [**@jay-cyble**](https://github.com/jay-cyble) (Jay Vasant) | Reported [#130](https://github.com/beenuar/AiSOC/issues/130) — a structured review of 13 security & UI issues found via code review + live-site inspection. Multiple findings were used to drive follow-up hardening tickets. |

If you want to report a vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/beenuar/AiSOC/security/advisories/new) and read [SECURITY.md](SECURITY.md) first.

---

## Code contributors

People outside the core maintainer team who have shipped code into AiSOC. Ordered by first merged contribution.

| Contributor | Highlights |
| --- | --- |
| [**@jay-cyble**](https://github.com/jay-cyble) | [PR #135](https://github.com/beenuar/AiSOC/pull/135) — UEBA service environment-variable alignment, closing [#134](https://github.com/beenuar/AiSOC/issues/134). First community contribution to the project. |
| [**@prince30121**](https://github.com/prince30121) | Multiple infrastructure & CI commits (including CI restoration work). 9 commits and counting. |
| [**@ARDA7787**](https://github.com/ARDA7787) | [PR #218](https://github.com/beenuar/AiSOC/pull/218) — Redis-backed scheduler singleton guard + dependency-CVE security-audit CI tooling (`security-audit.yml`, `scripts/security_audit.py`). |
| [**@TanmayZade**](https://github.com/TanmayZade) | [PR #219](https://github.com/beenuar/AiSOC/pull/219) — prompt sanitiser + untrusted-content wrapping across the five classification agents (fix for [#220](https://github.com/beenuar/AiSOC/issues/220)). |

The full, always-up-to-date list of code contributors lives on the [GitHub contributors page](https://github.com/beenuar/AiSOC/graphs/contributors).

---

## Bug reporters & community feedback

Folks who took the time to file high-signal issues that drove visible improvements in the project:

- [**@cyberdometanza**](https://github.com/cyberdometanza) — Docker / packaging bug reports (e.g. [#82](https://github.com/beenuar/AiSOC/issues/82))
- [**@AMoneronIQBusiness**](https://github.com/AMoneronIQBusiness) — Docker demo / quickstart feedback ([#81](https://github.com/beenuar/AiSOC/issues/81))
- [**@ThiagoDataEngineer**](https://github.com/ThiagoDataEngineer) — Early platform feedback ([#48](https://github.com/beenuar/AiSOC/issues/48))
- [**@alvarofraguas**](https://github.com/alvarofraguas) — Connector / setup feedback ([#44](https://github.com/beenuar/AiSOC/issues/44))
- [**@sonalig-cyble**](https://github.com/sonalig-cyble) — Product feedback ([#131](https://github.com/beenuar/AiSOC/issues/131))

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
