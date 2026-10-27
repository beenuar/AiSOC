# Discoverability — registry descriptors and the social preview

Scope: `services/mcp/**`, root-level registry descriptors, and one static
image. Two items from an external audit, both of whose premises turned out to
be partly wrong. What follows records what is actually true, measured on
2026-10-28, and what is left — every remaining step is blocked on an account
or a credential that no commit can supply.

Nothing here changes how the MCP server runs. A descriptor is how a directory
site indexes the server; an unlisted server still works from a source build.

---

## Item 1 — MCP registry descriptors

### What the audit said, and what is true

The audit reported `services/mcp/server.json` as **not found**. It exists, and
it is valid.

| Audit claim | Verified state |
|---|---|
| `server.json` not found | **Present** at `services/mcp/server.json` and schema-valid. |
| It declares no `packages` and no `remotes`, so the registry would reject it | The first half is true; **the rejection is not**. Neither the JSON Schema nor the registry's semantic validator requires either field. |
| `io.github.beenuar/aisoc` is unpublished | **Confirmed.** |
| `smithery.yaml` and `glama.json` are absent | **Confirmed.** |

Validation evidence, against the schema the file itself names:

```
$ curl -s https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json
HTTP 200, 22090 bytes
$ jsonschema Draft202012Validator(schema).iter_errors(server.json)
errors: 0 → VALID
```

The schema's only required properties are `name`, `description` and `version`
(`definitions.ServerDetail.required`). The registry's semantic validator
(`internal/validators/validators.go` in `modelcontextprotocol/registry`)
iterates `Packages` and `Remotes` and validates each entry it finds; it has no
"at least one" rule. So the file would not be *rejected*.

It would, however, be **useless**, which is the real defect and why the item
still stands: a listing with neither a package nor a remote gives a client
nothing to install. Of 100 servers sampled from the live registry, **0** had
neither — 92 carry `remotes`, 10 carry `packages`.

### The true publication state of the MCP artefact

Read from the registries, not from a workflow. `AGENTS.md` is explicit that a
green workflow is not evidence of publication.

| Distribution channel | Declared where | Registry answer | State |
|---|---|---|---|
| npm `@aisoc/mcp` | `release.yml` `npm-publish` matrix | `registry.npmjs.org/@aisoc%2Fmcp` → **HTTP 404** | **Not published** |
| OCI `ghcr.io/beenuar/aisoc-mcp` | nothing | GHCR v2 tags list → **HTTP 403** | **Does not exist** |
| OCI `ghcr.io/beenuar/aisoc-mcp-server` | nothing | GHCR v2 tags list → **HTTP 403** | **Does not exist** |
| MCP registry `io.github.beenuar/aisoc` | `services/mcp/server.json` | `/v0/servers?search=aisoc` → 200, no matching entry | **Not listed** |

Two notes on reading those answers, because both have misled before:

- **A GHCR 403 is ambiguous on its own** and `AGENTS.md` warns it reads as a
  visibility problem that is not one. It was disambiguated with a control:
  `ghcr.io/beenuar/aisoc-core-api` answers the same anonymous request with
  **200 and a full tag list**. A published package is readable; these two are
  not there. Corroborated structurally — the MCP server appears in **no**
  entry of the `publish-images.yml` build or merge matrix, and both
  `docker-compose.yml` and `infra/helm/aisoc/values.yaml` already carry
  comments saying the image is built locally precisely because no
  `ghcr.io/beenuar/aisoc-mcp` package has been published.
- **The registry search for `aisoc` is not empty**, which is a trap. It returns
  `com.realestateaisociety/follow-up-boss` — an unrelated server matching on
  the substring inside "realestateaisociety". An exact-name query returns
  `{"servers":[],"metadata":{"count":0}}`.

So the npm path is the live one: wired in `release.yml`, built and packed on
every tag, with only the upload gated on a credential that does not exist. The
OCI path would need a publishing job that nobody has written.

### What changed in this branch

**`services/mcp/package.json` — added `"mcpName": "io.github.beenuar/aisoc"`.**

This is the registry's npm ownership check, and it is the one prerequisite that
can be satisfied today. Per the registry's package-type documentation, it
verifies ownership of an npm package by reading `mcpName` from the published
`package.json` and requiring it to equal the `name` in `server.json`. Without
it, `mcp-publisher publish` fails ownership verification even after the package
exists. The field must be in the package *as published*, so it has to be
committed before the npm upload, not after.

The equivalent for the other channels, recorded so nobody has to re-derive it:
PyPI, NuGet and Cargo use an `mcp-name: <server name>` string in the package
README; OCI uses an `io.modelcontextprotocol.server.name` image label. No OCI
label was added here, because nothing publishes that image and a label no
publisher reads is not a prerequisite, it is decoration.

**`glama.json` at the repository root — added.** Validated against the schema it
names:

```
$ curl -s https://glama.ai/mcp/schemas/server.json
HTTP 200, 345 bytes, draft-07
$ jsonschema Draft7Validator(schema).iter_errors(glama.json)
errors: 0 → VALID
```

The schema has exactly one property, `maintainers`, an array of unique GitHub
usernames, and it is required. The value is taken from `.github/CODEOWNERS`,
which assigns `*` to `@beenuar`, rather than guessed. Root placement was
confirmed against ten real repositories carrying the file; all ten have it at
the root.

**`server.json` — deliberately unchanged.** No `packages` entry was invented.
There is no published artefact to name, and a descriptor pointing at a package
that 404s is worse than one that is openly incomplete.

That is not merely a judgement call here — **the repository already enforces
it**, which is worth knowing before anyone "helpfully" adds the entry.
`services/mcp/tests/registry.test.ts` asserts that an empty `packages` and the
"ready, unpublished" line in `services/mcp/README.md` move together: add a
package entry while the README still says the package is unpublished and the
test fails, and vice versa. The same file already asserts the version
agreement this work was asked to check for — `expect(manifest.version).toBe(
pkg.version)` — so no new gate was needed, and none was written. It also caps
`description` at the registry's 100 characters and pins the schema URL.

All 8 of its cases pass with the `mcpName` addition, as do all 167 tests across
the 13 files in `services/mcp/tests/`.

### `smithery.yaml` — not added, and why

The audit asked for one. It is not in this branch, because Smithery no longer
documents the file and writing one would mean guessing at fields.

Evidence. Smithery is now part of Arcade.dev and its documentation was
restructured; the page that used to document the file,
`smithery.ai/docs/build/project-config`, now returns **404**, as do
`/docs/config`, `/docs/deployments` and `/schemas/smithery.yaml`. All 59 pages
listed in `smithery.ai/docs/llms.txt` were fetched — 11,809 lines — and the
string `smithery.yaml` appears **0 times**, as do `startCommand` and
`runtime: typescript`.

The shipped CLI tells the same story from the other side. `@smithery/cli`
4.11.1 does still read a `smithery.yaml` from the working directory, but only
to pull an optional `name` string used to pre-fill a prompt; publishing itself
refuses anything that is not a URL or a bundle (`publish target must be an MCP
server URL or .mcpb bundle`). The file is a prompt hint, not a configuration
format.

Smithery's two current paths and how they sit against this project:

- **URL** — Smithery's gateway proxies to a public HTTPS streamable-HTTP
  endpoint. AiSOC is self-hosted and operates no public MCP endpoint, so there
  is no URL to register. This is an architectural mismatch, not a missing
  credential, and it should not be "fixed" by standing one up casually: the MCP
  server is a standing read path into a tenant's alerts and event lake, which
  is why `docker-compose.yml` puts it behind its own opt-in profile.
- **MCPB bundle** — a `.mcpb` of the local stdio server, uploaded through
  Smithery's flow. This one *is* applicable and is the route to take if a
  Smithery listing is wanted. It needs a bundle build that does not exist yet
  and a Smithery account.

Recorded as refused with reasons rather than shipped, on the same principle the
detection corpus uses.

### Remaining steps, who runs them, and what each is blocked on

All three are account actions. None can be done from a commit.

**1. Publish `@aisoc/mcp` to npm.** *Blocked on: an npm credential.*
Owner action. The pipeline exists — `release.yml` builds and packs the package
on every tag and gates only the upload, on `secrets.NPM_TOKEN`. The first
upload of a never-published package must use a token, because npm's trusted
publishing is configured on a package's settings page and a package that does
not exist has no settings page. So: create the `@aisoc` scope on npm, mint a
publish token, set `NPM_TOKEN` in repository secrets, and cut a release. After
the first upload, set the `AISOC_NPM_TRUSTED_PUBLISHING` repository variable to
`true` and the token can be removed.

Verify at the registry, not in the workflow log:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/@aisoc%2Fmcp
# 200 means published; 404 means it is not, whatever the run says
```

**2. List the server in the MCP registry.** *Blocked on: step 1, then a GitHub
device-code login.* Once npm serves the package, add a `packages` entry to
`services/mcp/server.json` naming the exact published version — the registry
rejects ranges — of the shape:

```json
"packages": [
  {
    "registryType": "npm",
    "identifier": "@aisoc/mcp",
    "version": "0.1.0",
    "transport": { "type": "stdio" }
  }
]
```

then, from a machine logged in as a GitHub account with write access to this
repository:

```bash
brew install mcp-publisher     # or the release binary from the registry repo
mcp-publisher login github     # device-code flow
cd services/mcp
mcp-publisher validate         # checks server.json without publishing
mcp-publisher publish
```

Verify:

```bash
curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=io.github.beenuar/aisoc'
# currently {"servers":[],"metadata":{"count":0}}
```

**3. Optional — a Smithery listing.** *Blocked on: an MCPB bundle build and a
Smithery account.* See the section above for why the URL route does not apply.

### Not done here, and why

**No version gate was added**, because one already exists and is better placed
than anything that would have been written: `services/mcp/tests/registry.test.ts`
asserts `server.json` and `package.json` agree, and runs in the `services/mcp`
leg of `ci.yml`. `check_release_policy.py` was checked and does *not* cover
this — it binds `VERSION` to `apps/web/package.json` only, and nothing in
`scripts/` reads `server.json` at all — so the obvious place to look is the
wrong one. Adding a second assertion in `scripts/` would have duplicated a
working check in a directory another branch currently owns.

One adjacent observation, not in scope: the regeneration command recorded in
`apps/docs/static/img/aisoc-social-card.svg` cannot run on a machine whose
ImageMagick has no Freetype or ghostscript delegate. It does not fail cleanly —
it emits `non-conforming drawing primitive definition 'text'` and drops every
text element, so a card regenerated that way loses all its wording while still
producing a plausible-looking file. The new card is rendered with headless
Chromium instead — faithful, and what a crawler effectively uses — and its own
source comment records that command and the reason.

---

## Item 2 — GitHub social preview

The repository has no custom social preview (`usesCustomOpenGraphImage` is
`false`), so links to it unfurl with the generic owner-avatar card.

**There is no API for this field.** It is Settings → General → Social preview
in the web UI, and only the repository owner can set it. This item is therefore
**owner action, and is not done.** Nothing in this branch makes the preview
live, and it should not be reported as live.

### What is committed

`apps/docs/static/img/aisoc-github-social-preview.png` — 1280x640, the size
GitHub specifies for this field, with its source alongside it as
`aisoc-github-social-preview.svg`.

It is a separate file from the existing `aisoc-social-card.png` rather than a
resize of it: that one is 1200x630 and is wired into `docusaurus.config.ts` as
the docs site's Open Graph image, and GitHub renders this card much smaller in
link unfurls, so it carries less text at a larger size.

Content is the wordmark, the logo mark from `img/logo.svg`, one value
proposition, one line naming what the system does, and a footer. The palette is
lifted from the existing card: background `#0b1220` → `#111c33`, accent
`#2563eb`, headline `#93b4f5`, body `#c3cede`, footer `#8fa0bb`.

It carries no metrics, no fabricated logos, no customer names, no testimonials
and no third-party product names — the same discipline the existing card's
source comment records, and for the same reason: a crawler caches a card for a
long time and no gate can regenerate it, so a number baked into it becomes a
stale claim on a surface nobody re-reads. Each capability named is one the tree
implements: fusion is `services/fusion`, agent triage is `services/agents`, and
the replayable decision ledger is what `aisoc_replay_decision` reads back.

Legibility was checked by rendering the card down to 320x160, roughly what a
chat unfurl shows; the wordmark and the value proposition stay readable.

### The instruction for the owner

> Go to <https://github.com/beenuar/AiSOC/settings> → General → Social preview →
> Edit → Upload an image, and upload
> `apps/docs/static/img/aisoc-github-social-preview.png` from a checkout of this
> branch.

Confirm it took with:

```bash
gh api repos/beenuar/AiSOC --jq '.usesCustomOpenGraphImage'
# false today; true once the upload succeeds
```

---

## Verification summary

| Check | Result |
|---|---|
| `server.json` against `server.schema.json` (2025-12-11) | 0 errors, valid |
| `glama.json` against `glama.ai/mcp/schemas/server.json` (draft-07) | 0 errors, valid |
| Every URL added by this branch | fetched, all 200 |
| npm `@aisoc/mcp` | 404, not published |
| GHCR `aisoc-mcp` / `aisoc-mcp-server` | 403, absent (control `aisoc-core-api` → 200) |
| MCP registry `io.github.beenuar/aisoc` | absent, count 0 |
| Social preview PNG | 1280x640, legible at 320x160 |
