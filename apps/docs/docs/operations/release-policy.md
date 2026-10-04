---
id: release-policy
title: Release policy
sidebar_label: Release policy
---

# Release policy

AiSOC ships often. This page is the contract that makes that safe to live
with: what a version number means, which tags move on their own, how long a
release keeps getting security fixes, and how much warning you get before
something you depend on goes away.

It is enforced, not merely stated. `scripts/check_release_policy.py` runs on
every pull request and again at the moment a tag is pushed, and a release whose
version and notes disagree does not publish.

## A major version means an operator must act

The version number answers one question: **do I have to do something before
upgrading?**

| Change | Version |
|---|---|
| You must change configuration, run a command, or accept behaviour you cannot opt out of | **major** |
| New capability, new endpoint, new connector, anything additive | **minor** |
| A fix that changes nothing you were relying on | **patch** |

That is a narrower rule than "big release". A major is a bill for your time,
so a release that costs you nothing does not get one however large it is.

Concretely, these are majors: a removed or renamed API field, a removed
endpoint, a configuration key that no longer works, a default that flips in a
way you cannot turn back, a migration you must run out of band, a minimum
version of PostgreSQL or Kubernetes going up.

These are not: a new endpoint, a new optional setting, a new connector, a
default that changes only for deployments that never set it, a performance
change, or anything behind a feature flag that ships off.

### Both directions are enforced

A major bump requires a `### BREAKING` section in that version's changelog
entry, **and** a `### BREAKING` section requires a major bump.

The second half matters at least as much as the first. Semantic versioning is
the only signal most automated upgrade tooling reads, and a minor is the
version people let a bot merge unattended. A break announced in a note that
nobody opens, on a version everything treats as safe, arrives through an
unreviewed dependency update.

A major with no breaking notes is the mirror image: a version number that
tells an operator to read upgrade instructions that do not exist, so they
upgrade assuming the major was cosmetic.

The rule applies from **10.0.0** onward, which is the first major that carried
a breaking section. Eight earlier majors do not, and the gate prints them as
exempt on every run rather than quietly skipping them. Published history is
not rewritten.

```bash
python3 scripts/check_release_policy.py          # the whole changelog
python3 scripts/check_release_policy.py --tag v12.0.0
```

## Tags and channels

### Container images

Every release publishes `ghcr.io/beenuar/aisoc-<service>:vX.Y.Z`, and moves
two channel tags.

| Tag | Moves | Use it when |
|---|---|---|
| `vX.Y.Z` | Never | Always, in production. Pin it. |
| `latest` | Every release, majors included | You want the newest thing and will read the notes |
| `stable` | Minors and patches automatically; a **major only when promoted deliberately** | You pull by tag and do not want to be moved across a break without deciding to |
| `demo` / `vX.Y.Z-demo` | Demo console only | Never in a real deployment. Demo mode is baked in at build time |

`stable` exists because `latest` cannot be both "newest" and "safe to pull
unattended". A major stops `stable` where it is until a maintainer dispatches
the release workflow with `promote_stable: true`.

**The rule is about a sequence, not a release.** Refusing `vX.0.0` is not
enough on its own: `v16.0.0` correctly declines the tag and `v16.1.0` is a
minor, so it took it the next day and the channel crossed the major with nobody
deciding to. That is how `stable` reached v12, v13 and v15. The workflow now
resolves which major the channel is *on* -- from the registry, because a tag is
a registry fact -- and moves it only within that major.

`tests/test_release_channel_tags.py` lifts the tag-selection block out of
`release.yml` and runs it under bash rather than describing it a second time,
and it replays whole release ladders, because every question asked one release
at a time had the right answer while the sequence did not.

Neither channel tag is ever applied by a repair run. Re-publishing the images
for an older tag moves nothing, because handing a self-hoster older content on
the tag they pull by default is the defect this arrangement exists to prevent.

### The Helm chart

The chart is published to an OCI registry on every release:

```bash
helm show chart oci://ghcr.io/beenuar/charts/aisoc --version stable
helm install aisoc oci://ghcr.io/beenuar/charts/aisoc --version <chart-version> -n aisoc --create-namespace
```

The chart has the same `stable` channel the images do, and it follows the
**chart's** major rather than the application's -- the break it protects an
operator from is a values-schema break, and the chart versions independently of
`appVersion`. `--version stable` resolves to the newest chart within the major
the channel is on; a chart major stops it until a maintainer dispatches with
`promote_stable: true`, exactly as for images. Pin an explicit version in
production; the channel is for the case where you would otherwise have pinned
nothing at all.

The chart's `version` and its `appVersion` move independently. `appVersion`
names the images an unpinned install pulls; `version` is the chart's own. A
chart change that does not touch the services does not force a service
release, and the reverse.

The release job packages and lints the chart on every run and pushes only on a
tag, so the chart cannot quietly stop being publishable between releases. It
also re-checks that `appVersion` names images that exist, because a chart
whose default tag resolves to nothing installs straight into
`ImagePullBackOff`.

## Security fixes: what gets one, and for how long

Security fixes land on the **current minor** and are backported to the
**previous minor** for **90 days** after it is superseded. Older lines get
nothing.

In practice that is a rolling window of two minors. Given the release cadence,
staying inside it means upgrading a minor within about a quarter.

Two things this is not. It is not a paid support commitment, and nothing here
creates one: AiSOC is MIT-licensed software maintained by its community, and
the same MIT warranty disclaimer applies to this page as to the code. And it
is not a statement about compliance certification of any kind.

Report a vulnerability through GitHub's private vulnerability reporting on the
repository, not as a public issue. `SECURITY.md` has the detail.

## Deprecation: one minor of warning, minimum

Nothing is removed without a release in which it still works and says it is
going.

1. **Minor N** ships the deprecation. The old thing keeps working. It warns at
   the point of use: a response header, a log line at `warning`, a console
   notice, or a `DeprecationWarning`, whichever a user of that surface would
   actually see. The changelog entry names the replacement.
2. **Minor N+1** at the earliest, or any later release, removes it. Removal is
   a `### BREAKING` entry and therefore a major, by the rule above.

So the minimum notice is one minor and the removal always costs a major. A
deprecation that a user cannot discover by running the software does not count
as warning them: "it was in the changelog" is not a deprecation path.

Security is the one exception. A control that has to be removed or tightened
because leaving it is unsafe ships immediately, with the reason stated.

## What a release actually publishes

A release is the set of artefacts it published, not the set of jobs that went
green. That distinction is load-bearing here: a release once reported success
having built thirty-two images and published none of them, because a skipped
upstream job propagates the whole way down a `needs` chain.

So `release.yml` ends by asking the registry rather than itself
(`scripts/check_published_images.py --require-fresh --require-network`), and
the release is not considered done until every reference in `docker-compose.yml`,
the chart and the tracked documentation resolves to an image that exists and
carries the version its tag names.

| Artefact | Published |
|---|---|
| 16 service images, `linux/amd64` + `linux/arm64` | Every release |
| Cosign signatures and SBOM attestations | Every release |
| Helm chart, to `oci://ghcr.io/beenuar/charts/aisoc` | Every release |
| Source tarball and SPDX SBOM on the GitHub Release | Every release |
| npm and PyPI packages | Built and validated every release; **uploaded only once the registries are configured**. See [`docs/operations/publishing.md`](https://github.com/beenuar/AiSOC/blob/main/docs/operations/publishing.md) |

## Upgrading

Every pull request that touches a migration runs
`.github/workflows/upgrade-test.yml`: the previous minor's published image
applies its own migration chain, data is seeded, and then the chain from the
pull request is applied over the populated schema. It asserts the rows that
were there are still there by id, that the runtime role can still read them,
and that re-applying the chain is a no-op.

A fresh install applies every migration to an empty schema, which is the one
case that cannot go wrong. The failures that reach operators need data to be
present, so the test carries some.

Operational steps for an upgrade are in [Upgrades](./upgrades.md); the
Kubernetes specifics are in [Kubernetes](../deployment/kubernetes.md).
