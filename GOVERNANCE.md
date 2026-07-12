# AiSOC Governance

AiSOC is an open-source, community-maintained project under the MIT license.
This document describes how the project is governed: who makes decisions, how
someone becomes a maintainer, and how the project intends to stay a neutral,
long-lived home for its community.

## Principles

- **Open by default.** Design discussions, roadmaps, and decisions happen in
  public issues and pull requests. The claim-to-gate discipline
  (`docs/audit/CLAIM_TO_GATE_MATRIX.md`) is public: every headline capability is
  backed by a CI gate, and the roadmap (`ROADMAP.md`) tracks what is proven vs.
  planned.
- **Proof over promises.** A capability is not "done" until a CI gate fails when
  it stops being true. Contributions that add a claim add its gate.
- **No single point of failure.** The project aims to grow its maintainer set
  and, over time, move to a vendor-neutral home (see "Neutral home" below).

## Roles

| Role | Who | Rights |
|------|-----|--------|
| **User** | Anyone running AiSOC | Files issues, joins discussions. |
| **Contributor** | Anyone who has landed a PR | Everything a user can do; listed in git history. |
| **Maintainer** | Listed in [`MAINTAINERS.md`](MAINTAINERS.md) | Reviews + merges PRs, triages issues, cuts releases, stewards the roadmap. |

## Decision-making

- **Lazy consensus.** Most changes proceed by lazy consensus: a PR that has been
  open for review, passes CI, and draws no unresolved objections from a
  maintainer may be merged.
- **Substantive changes** (architecture, security posture, breaking API changes,
  new external dependencies, license/trademark) require review from at least one
  maintainer and a passing CI run, including the relevant gate. Breaking API
  changes additionally require the OpenAPI breaking-change gate
  (`openapi-breaking.yml`) to be satisfied deliberately (version bump +
  CHANGELOG BREAKING note).
- **Disagreement** is resolved by discussion in the PR/issue. If maintainers
  cannot reach consensus, the decision escalates to a maintainer vote (simple
  majority; ties fail closed — the change does not land).

## Becoming a maintainer

A contributor may be nominated as a maintainer after a sustained track record of
high-quality contributions and reviews. Nomination is by an existing maintainer
via a PR adding the candidate to `MAINTAINERS.md`; it lands under the same
review rules as any substantive change. Maintainers who are inactive for an
extended period may be moved to emeritus.

## Security

Vulnerabilities are handled per [`SECURITY.md`](SECURITY.md) — do **not** open a
public issue for a security report. The platform + agent threat models live in
`docs/security/`.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Contributions + DCO

All contributions are made under the project license (MIT) and must carry a
Developer Certificate of Origin sign-off (`Signed-off-by:`). See
[`CONTRIBUTING.md`](CONTRIBUTING.md#developer-certificate-of-origin-dco).

## Trademark

The MIT license covers the code; the AiSOC name and marks are governed
separately — see [`TRADEMARK.md`](TRADEMARK.md).

## Neutral home

AiSOC intends to remain vendor-neutral. As the community and maintainer set
grow, the project's explicit goal is to move governance and asset ownership to a
neutral foundation (e.g. a CNCF/OpenSSF-style home) rather than any single
company. This document is the interim governance model until that transition;
changes to it follow the "substantive change" process above.
