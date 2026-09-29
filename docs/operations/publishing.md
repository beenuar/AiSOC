# Publishing AiSOC packages

`.github/workflows/release.yml` builds, packs and validates every publishable
package on each `v*.*.*` tag. Uploading is deliberately gated behind the
one-time setup below, so a release never fails just because a registry
credential has not been configured yet.

Until that setup is done the release still runs: each package is built,
packed and `twine check`ed, and nothing is uploaded. That way the pipeline
cannot silently rot, which is the failure mode that let `npx aisoc` sit in the
README while no such package existed.

## Telling an upload from a skip

A green publish job is not a published package. On the v12.2.0 release run all
59 jobs reported success — eight of them named `npm — publish <pkg>` or
`PyPI — publish <pkg>` — and all eight packages returned 404. Only the final
upload step is credential-gated, so each job built the artefact, reached the
upload, skipped it, and exited 0.

Three things now carry that fact to a reader, all from one decision made in
the `Packages — which uploads are armed` job:

1. **The job title.** With no credential the job is called
   `npm — pack only, NOT uploaded: aisoc`, not `npm — publish aisoc`. Visible
   in the Actions list without opening anything.
2. **The run summary.** `Packages — publication report` writes a table of
   every package, its version in the tree, whether the registry holds it, and
   the reason for each one that was packed and not uploaded.
3. **The registry, asked directly.** That same job runs
   `scripts/check_published_packages.py --require-network`, which is the only
   check here that does not take the workflow's word for anything.

The release still completes without a credential, because the images and the
GitHub Release genuinely do publish and must not be blocked by a package that
cannot.

### `.github/release-packages.yml`

Every package the release uploads is declared there, with `published: true`
or `false` and, when false, the reason. The gate enforces it in three
directions, so none of them can drift in silence:

- against `release.yml`'s npm and PyPI matrices, both ways — a package the
  workflow builds and the file does not declare is one nothing checks;
- `published: true` must resolve on the registry, **at the version in the
  tree**. This is the direction a release run cannot check itself: a job that
  claims an upload and performed none fails here;
- `published: false` must 404. When a credential arrives and an upload
  succeeds, the entry has to be corrected in a commit — the knowingly-absent
  set shrinks visibly rather than quietly ceasing to be true.

So the sequence when you finish the setup below is: publish, then flip that
package's `published` to `true` and delete its `reason`. The gate fails until
you do, and fails again if you do it early.

### Exercising the package half without cutting a tag

```bash
gh workflow run release.yml --ref main -f tag=v0.0.0 -f packages_only=true
```

Builds, packs and validates all eight packages, runs the publication report,
and skips the image rebuild entirely. Nothing is uploaded: the preflight
refuses to arm an upload on a dispatch however well credentialled the
repository is, because a registry will not accept a version twice. `tag` is
required by the form and ignored on this path.

Use it to check that every package is still publishable before tagging —
otherwise a packaging break is discovered on a tag push, which is the worst
possible moment.

## What gets published

npm:

| Package | Source | Notes |
| --- | --- | --- |
| `aisoc` | `packages/aisoc-lite` | The wedge CLI behind `npx aisoc triage --demo` |
| `@aisoc/mcp` | `services/mcp` | MCP server for Claude / Cursor / Cody |
| `@aisoc/sdk` | `packages/sdk-ts` | Generated TypeScript client |

PyPI:

| Package | Source |
| --- | --- |
| `aisoc-sandbox` | `packages/aisoc-sandbox` |
| `aisoc-cli` | `packages/aisoc-cli` |
| `aisoc-sdk` | `packages/sdk-py` |
| `aisoc-plugin-sdk` | `packages/plugin-sdk-py` |
| `aisoc-detections` | `packages/aisoc-detections` |

Package versions move independently of the monorepo `VERSION`. A release that
does not change a package's version simply skips it — npm rejects a duplicate
version outright, and the PyPI step passes `skip-existing`.

## Name availability

`aisoc` on **npm** is unclaimed and is reserved by the first successful
publish. Claim it early.

`aisoc` on **PyPI is already taken** by an unrelated project, which is why the
Python distributions all carry the `aisoc-` prefix. Do not plan around
acquiring it; a PEP 541 name transfer only applies to abandoned projects and
that one is actively maintained.

## One-time setup: npm

npm's trusted publishing is configured **on a package's settings page**, and a
package that has never been published has no settings page. So unlike PyPI,
which supports pending publishers, npm cannot be made token-free before the
first upload. The sequence is therefore: one token, one release, then the
token is deleted and never used again.

**Step 1: the first publish, with a token.**

1. Create (or sign in to) the npm account that will own the packages, and
   create the `@aisoc` organisation so the scoped packages have a home.
2. Generate a **granular access token** scoped to just these three packages,
   with read/write permission and the shortest expiry that covers the release.
3. Add it as the `NPM_TOKEN` repository secret.
4. Tag a release. The first publish claims `aisoc`.

**Step 2: move to trusted publishing, and delete the token.**

For each of `aisoc`, `@aisoc/mcp` and `@aisoc/sdk`, on npmjs.com open
**Settings → Trusted publisher → GitHub Actions** and enter:

- Organization or user: `beenuar`
- Repository: `AiSOC`
- Workflow filename: `release.yml` (the **filename only**, with the
  extension, not a path)
- Environment name: leave blank

For `aisoc` add a **second** trusted publisher with the workflow filename
`publish-cli.yml`, because the CLI also releases on its own `cli-v*` tag and
npm validates the workflow filename rather than the repository alone. A
package may carry up to ten.

Then set the repository **variable** (not a secret)
`AISOC_NPM_TRUSTED_PUBLISHING` to `true`, delete the `NPM_TOKEN` secret, and
on each package set **Publishing access → Require two-factor authentication
and disallow tokens**.

Three things that will bite, all of which fail with `ENEEDAUTH` and nothing
more specific:

- Trusted publishing needs **npm 11.5.1 or later**. Node 22 ships npm 10, so
  the workflow runs `npm install -g npm@latest` on the OIDC path. That step is
  the reason the path works at all, not a tidiness measure.
- The workflow **filename** is matched exactly and is case-sensitive.
  Renaming `release.yml` or `publish-cli.yml` breaks publishing and nothing
  else, and npm does not validate the configuration when you save it.
- Each `package.json`'s `repository.url` must match this repository exactly.
  All three already do; a fourth package must set it too.

On the OIDC path npm generates provenance automatically, so `--provenance` is
not passed and must not be.

## One-time setup: PyPI

PyPI supports **pending** trusted publishers, so the trust relationship can be
registered before a project exists. That is how the first upload of each of
these works without an API token.

For each of the five distributions, go to
<https://pypi.org/manage/account/publishing/> and add a pending publisher:

- PyPI project name: the package name from the table above
- Owner: `beenuar`
- Repository name: `AiSOC`
- Workflow name: `release.yml`
- Environment name: leave blank

Then set the repository **variable** (not secret)
`AISOC_PYPI_TRUSTED_PUBLISHING` to `true`, which arms the upload step.

There is no API token to store or rotate in this path.

## One-time setup: GitHub Marketplace (the Action)

`beenuar/aisoc-action` **does not exist as a repository**, so
`uses: beenuar/aisoc-action@v1` 404s. Until a Marketplace listing exists, the
reference that resolves is the action's directory inside this monorepo:

```yaml
- uses: beenuar/AiSOC/packages/aisoc-action@v8.1.1
```

That form needs no setup and is what the README and
`apps/docs/docs/integrations/github-action.md` show. Publishing the short
alias is a repository-settings action, not an engineering one:

1. On the repo's **Releases** page, edit the release for the tag you want to
   list and tick **Publish this Action to the GitHub Marketplace**. GitHub
   validates `packages/aisoc-action/action.yml` at that point — it needs
   `name`, `description` and `branding`.
2. Accept the Marketplace developer agreement if prompted.
3. Marketplace listings are per-repository and resolve to the repository
   root, so the short `beenuar/aisoc-action@v1` alias additionally requires a
   dedicated repository with the action at its root. Mirroring
   `packages/aisoc-action/` there on each tag is the remaining work; the
   subdirectory form above stays valid either way.

## Cutting a release

The existing tag-driven flow is unchanged — see the release section of
`CONTRIBUTING.md`. Bump the package versions you intend to publish in the same
commit as the `CHANGELOG.md` promotion, then tag:

```bash
git tag vX.Y.Z && git push --tags
```

Bump `appVersion` in `infra/helm/aisoc/Chart.yaml` to the tag you are cutting
in that same commit. Every image tag in the chart's values defaults to it, so
a chart left on the previous release pins operators to the previous release —
and one left on a version that was never published pins them to nothing at
all, which is the state the chart shipped in until v11.1.0: `appVersion` read
`5.2.0`, a tag no image has ever carried, so a default `helm install` could
only reach `ImagePullBackOff`. `scripts/check_published_images.py` resolves
that value the same way the templates do and fails when it names nothing, so
this is a gated step rather than a remembered one.

`honeytokens` and `purpleTeam` pin `latest` rather than an empty tag until
they have a `vX.Y.Z` to point at — they were first published on the merge that
added them to the build matrix, so their first release tag is v11.1.0. Move
them back to `tag: ""` in that release.

## Recovering a release that only partly published

A release is the set of artefacts it published, not the set of jobs that
finished. If `check_published_images.py` reports an image missing at a tag
that has already shipped, republish the images for that tag rather than
cutting a new one:

```bash
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

Dispatch it from `main` so the current workflow definition runs; the build
checks the named tag out for its source. The GitHub Release stays skipped, and
no package is uploaded, because a registry will not accept a package version
twice.

A package half that only partly published has no equivalent repair: npm and
PyPI both refuse a second upload of a version that already exists. Bump the
package's version and cut a new tag. `Packages — publication report` is what
tells you it happened — it fails the release when a package declared
published does not resolve at the version in the tree.

## Verifying a publish

```bash
npm view aisoc version
npx aisoc@latest triage --demo

pip download aisoc-sandbox --no-deps -d /tmp/verify
```

`.github/workflows/readme-gates.yml` runs the first two of those against the
published registry on a schedule, so a broken on-ramp is caught even between
releases rather than by a user.

Signature and SBOM verification for the container images is covered separately
in `docs/operations/verifying-releases.md`.
