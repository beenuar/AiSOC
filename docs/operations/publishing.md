# Publishing AiSOC packages

`.github/workflows/release.yml` builds, packs and validates every publishable
package on each `v*.*.*` tag. Uploading is deliberately gated behind the
one-time setup below, so a release never fails just because a registry
credential has not been configured yet.

Until that setup is done the release still runs: each package is built,
packed and `twine check`ed, and the job emits a warning explaining that the
upload was skipped. That way the pipeline cannot silently rot, which is the
failure mode that let `npx aisoc` sit in the README while no such package
existed.

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

1. Create (or sign in to) the npm account that will own the packages, and
   create the `@aisoc` organisation so the scoped packages have a home.
2. Generate a **granular access token** scoped to just these three packages,
   with read/write permission and a sensible expiry.
3. Add it as the `NPM_TOKEN` repository secret.
4. Tag a release. The first publish claims `aisoc`.

After the first release, switch to trusted publishing and delete the token:
on npmjs.com, open each package's settings, add a trusted publisher pointing
at `beenuar/AiSOC` and the `release.yml` workflow, then remove the `NPM_TOKEN`
secret. The publish step already requests an OIDC token (`id-token: write`),
so nothing in the workflow needs to change.

Every upload is published with `--provenance`, which requires the
`repository` field in each `package.json` to point at this repo. If you add a
fourth npm package, set that field or the publish will fail.

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

## Cutting a release

The existing tag-driven flow is unchanged — see the release section of
`CONTRIBUTING.md`. Bump the package versions you intend to publish in the same
commit as the `CHANGELOG.md` promotion, then tag:

```bash
git tag vX.Y.Z && git push --tags
```

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
