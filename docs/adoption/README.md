# Adoption snapshot — the ledger lives on the `adoption-data` branch

The monthly adoption ledger is committed to the unprotected
[`adoption-data`](https://github.com/beenuar/AiSOC/tree/adoption-data/docs/adoption)
branch, not to `main`:

- [`docs/adoption/README.md` (rendered latest row)](https://github.com/beenuar/AiSOC/blob/adoption-data/docs/adoption/README.md)
- [`docs/adoption/snapshot.json` (full history)](https://github.com/beenuar/AiSOC/blob/adoption-data/docs/adoption/snapshot.json)

Collected by `scripts/adoption_snapshot.py`, refreshed monthly by
`.github/workflows/adoption-snapshot.yml`. Everything in it comes from public
GitHub and registry APIs — the project ships no usage telemetry that phones
home. A value of **not measured** means the source could not be read on that
run; it does not mean zero.

Why a branch: `main` is branch-protected with no bypass actors, so the
workflow's direct push fails (GH006), and a PR opened with `GITHUB_TOKEN`
can never merge because events created by that token do not trigger the
`pull_request` workflows the required checks come from. Every path that keeps
the data on `main` needs an owner-provisioned credential; the data branch
needs none, and nothing on `main` reads these files programmatically. The
history is carried inside `snapshot.json` itself, so the ledger is complete
wherever it lives.
