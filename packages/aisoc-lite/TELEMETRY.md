# Telemetry in the `aisoc` CLI

**Telemetry is OFF by default. Nothing leaves your machine unless you explicitly turn it on.**

We built this the way we'd want a security tool built for us: the default is silence, the opt-in is a single flag, and what we collect is documented to the field.

## How to turn it on (and off)

| Action | Result |
|---|---|
| _(do nothing)_ | **Off.** No network calls for telemetry. |
| `aisoc triage --telemetry` | On for that run. |
| `AISOC_TELEMETRY=1` | On for the session. |
| `aisoc triage --no-telemetry` | **Forced off** — beats every other setting. |
| `AISOC_TELEMETRY=0` | Off for the session. |

Precedence (highest first): `--no-telemetry` → `--telemetry` → `AISOC_TELEMETRY=0` → `AISOC_TELEMETRY=1` → default off.

## Exactly what is sent (when enabled)

Only aggregate counts and run metadata. This is the entire payload — there is no other field:

```json
{
  "event": "triage",
  "version": "0.1.0",
  "source": "demo",
  "total": 200,
  "truePositive": 12,
  "needsReview": 17,
  "suppressed": 171,
  "deterministic": true,
  "elapsedMs": 63
}
```

## What is **never** collected

- Alert titles, descriptions, or any raw event text
- IOCs (IPs, domains, hashes, URLs)
- Hostnames, usernames, or any identity
- File paths, file names, or file contents
- Your API keys or any credentials
- Detection rules you translate
- Any per-alert data whatsoever

The payload builder is unit-tested (`src/telemetry.test.ts`) to assert that no alert content can appear in it.

## Where it goes

**Nowhere, unless you point it somewhere.** There is no default endpoint and
the project operates no collector. Enabling telemetry without setting
`AISOC_TELEMETRY_ENDPOINT` performs no network call at all.

If you do set an endpoint — for your own collector, in your own infrastructure
— the payload above is POSTed to it with a 2-second timeout. The request can
never fail or slow down the CLI; errors are silently ignored.

> This used to default to a hosted collector that no longer resolves, which
> meant an opted-in payload was discarded while this page claimed it was
> collected. Quietly dropping data someone consented to send is a worse trust
> failure than not collecting it, so sending now requires an explicit
> destination.

## Why we ask at all

Aggregate run counts and verdict distributions tell us whether the tool is useful and where the verdict bands need tuning. That's it. If you'd rather not, the default already has you covered.
