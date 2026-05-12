---
sidebar_position: 2
title: Hello, connector — write your first AiSOC integration
description: A walkthrough that builds a real, runnable AiSOC connector against httpbin.org. No vendor account, no API key, just the BaseConnector contract front to back.
---

# Hello, connector

This tutorial walks you end-to-end through the work of adding a new data source to AiSOC. By the end you will have:

- A subclass of `BaseConnector` that implements every method the platform calls.
- A self-describing schema that the connector wizard renders into a configuration form.
- A `test_connection()` path that the wizard hits before it lets you save.
- A `fetch_alerts()` path that the polling scheduler hits every five minutes.
- A `normalize()` step that converts vendor JSON into AiSOC's common alert shape.
- A smoke test that pins all of the above against mocked HTTP traffic.

Everything points at [httpbin.org](https://httpbin.org), a free, no-auth HTTP testing service. The point isn't to ingest httpbin events into your SOC — the point is to walk every line of the connector contract against a backend that:

- responds without authentication,
- returns deterministic JSON shapes you can assert on,
- has been up roughly forever.

When you're ready to wire up a real vendor, copy the example, swap the URLs, and add an authentication step. The shape stays the same.

## Where the example lives

The reference implementation lives at:

```text
services/connectors/app/connectors/_examples/hello_connector.py
```

The `_examples/` directory is **deliberately not** registered in [`services/connectors/app/connectors/__init__.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/app/connectors/__init__.py). Anything under `_examples/` exists for documentation only and never appears in the connector catalog, the polling scheduler, or the marketplace index. There is a smoke test ([`tests/test_hello_connector_example.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/tests/test_hello_connector_example.py)) that pins this invariant — if someone accidentally promotes the example into the live registry, CI fails.

## Step 1 — Pick identity attributes

A connector identifies itself with three class-level strings:

```python
class HelloConnector(BaseConnector):
    connector_id = "hello"
    connector_name = "Hello (Tutorial)"
    connector_category = "saas"
```

- **`connector_id`** is the wire identifier. It shows up in database rows, plugin manifests, and API URLs. Treat it like a primary key: lowercase, hyphen- or underscore-separated, **never changes** after first release.
- **`connector_name`** is the human label rendered in the catalog grid.
- **`connector_category`** must be one of the existing categories: `identity`, `cloud`, `vcs`, `siem`, `edr`, `xdr`, `network`, `posture`, `saas`. The category drives grouping in the wizard and downstream routing hints in detection rules. If your tool genuinely doesn't fit one of these, raise it in a PR before inventing a new one — the taxonomy is shared with the detection layer.

## Step 2 — Declare the schema

`schema()` is what the connector wizard renders. It tells the UI which fields to draw, which ones are secret, and where to find the docs page (which is this page, in our case).

```python
@classmethod
def schema(cls) -> ConnectorSchema:
    return ConnectorSchema(
        connector_id=cls.connector_id,
        connector_name=cls.connector_name,
        category=cls.connector_category,
        description=(
            "Tutorial connector that polls httpbin.org. Use this as a "
            "reference when writing a new connector — it implements "
            "every BaseConnector method against a public, no-auth API."
        ),
        docs_url="/docs/connectors/hello-connector",
        fields=[
            Field(
                "api_token",
                "secret",
                "API Token",
                help_text=(
                    "Pretend credential. httpbin doesn't actually "
                    "validate it — this field exists so the tutorial "
                    "exercises the credential vault."
                ),
            ),
            Field(
                "base_url",
                "string",
                "Base URL",
                required=False,
                default="https://httpbin.org",
                placeholder="https://httpbin.org",
                help_text="Override only when running against a self-hosted httpbin.",
            ),
        ],
    )
```

A few things worth pointing at:

- **`type="secret"`** on `api_token` does two things: the wizard renders a masked input, and the [credential vault](/docs/operations/credentials) encrypts the value with `Fernet` before it touches the database. The tutorial declares the field as a secret even though httpbin ignores it — the goal is to exercise that code path so you can see exactly what happens with a real vendor.
- **`required=False`** plus `default=...` on `base_url` matches a common pattern for self-hosted vendor support. The wizard shows the default in placeholder text and skips validation if the field is left blank.
- **`docs_url`** is the link the wizard surfaces as "Documentation" in the connector card. Always point it at the per-connector page, not the catalog.

## Step 3 — Declare capabilities

Capabilities are the set of action verbs the agent layer is allowed to ask the connector to perform. The tutorial connector is read-only, so it declares one:

```python
@classmethod
def capabilities(cls) -> tuple[Capability, ...]:
    return (Capability.PULL_ALERTS,)
```

Real connectors will frequently add things like `PULL_AUDIT`, `PIVOT_USER`, or `READ_AUDIT_TRAIL`. Anything **kinetic** (isolating a host, blocking a hash, deleting a session) requires a real backend that can act on those verbs and is out of scope for this example by design — the goal is to not give a brand-new contributor a half-implemented "isolate host" path that they then ship by mistake.

## Step 4 — Constructor

The constructor must match the schema field names exactly. The router decrypts `auth_config` and unpacks it as keyword arguments, so a typo here turns into a 500 at poll time:

```python
def __init__(self, api_token: str, base_url: str | None = None):
    self._api_token = api_token
    # Strip trailing slash so we can compose URLs with simple `+`.
    self._base_url = (base_url or "https://httpbin.org").rstrip("/")
```

We strip trailing slashes so URL composition stays boring (`f"{self._base_url}/anything"` always works).

## Step 5 — `test_connection()`

`test_connection()` is the pre-save liveness check. It is called by `POST /connectors/test` **before** the row is written to the database. Returning `success: false` here blocks the save, so keep this cheap and deterministic — one round trip, short timeout, no pagination:

```python
async def test_connection(self) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{self._base_url}/status/200")
    except httpx.HTTPError as exc:
        return {
            "success": False,
            "connector": self.connector_id,
            "error": f"network error: {exc.__class__.__name__}",
        }

    if resp.status_code != 200:
        return {
            "success": False,
            "connector": self.connector_id,
            "error": f"unexpected status: HTTP {resp.status_code}",
        }
    return {"success": True, "connector": self.connector_id}
```

Three rules to internalize for `test_connection()`:

1. **Always return a dict.** Never raise. The wizard uses the `success` flag to decide whether to render the error inline; an unhandled exception bubbles up as a 500 and the operator sees a useless "request failed" toast.
2. **Always include `connector: self.connector_id`.** Multiple connectors can be tested in parallel; the response key lets the UI route the result to the right card.
3. **Categorise failures.** `network error: ConnectError` is a different problem from `unexpected status: HTTP 401`. The first is an infrastructure issue; the second is a credential issue. Surface the difference so the operator knows whether to call IT or the vendor.

## Step 6 — `fetch_alerts()`

This is the polling read path. The scheduler calls it every `poll_interval_seconds` (default 300) with the elapsed window since the last successful poll. Real connectors translate `since_seconds` into a vendor-native time filter (Auth0 uses a Lucene query string, Cloudflare uses `since=<ISO-8601>`, GitHub uses cursor pagination, etc.).

httpbin doesn't store events, so the example just hits `/anything` once and treats the response body as a single synthetic event:

```python
async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self._base_url}/anything",
                params={"since_seconds": since_seconds},
            )
    except httpx.HTTPError as exc:
        logger.warning("hello.fetch_alerts.network_error", error=str(exc))
        return []

    if resp.status_code != 200:
        logger.warning(
            "hello.fetch_alerts.bad_status",
            status=resp.status_code,
            body=resp.text[:300],
        )
        return []

    try:
        payload = resp.json() or {}
    except ValueError:
        logger.warning("hello.fetch_alerts.invalid_json")
        return []

    return [self.normalize(payload)]
```

The most important thing here is the failure model: **polling failures must be non-terminal**. Network errors, 5xx responses, and bad JSON all return `[]` rather than raising. The scheduler logs the failure, records it on `health_status`, surfaces it in the UI on the connector card, and tries again next interval. If `fetch_alerts()` raises, the entire job slot is poisoned — you'll see the connector go red until the next reload (up to 30 seconds), and any other connectors sharing that thread will be delayed.

Keep the `since_seconds` parameter in the signature even if your vendor doesn't expose a time-window filter — the scheduler always passes it.

## Step 7 — `normalize()`

`normalize()` maps vendor JSON to AiSOC's common alert shape:

```python
def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
    url = raw.get("url") or "(no url)"
    return {
        "source": "hello",
        "category": self.connector_category,
        "severity": "info",
        "title": f"Hello connector: pinged {url}",
        "description": "Synthetic event from the hello-connector tutorial.",
        "alert_id": f"hello:{raw.get('origin', '?')}:{url}",
        "host": None,
        "raw": raw,
    }
```

The contract for the returned dict is documented in `services/ingest` and includes (at minimum):

| Field | Notes |
|---|---|
| `source` | Stable string, almost always `cls.connector_id`. |
| `category` | Same taxonomy as the schema. Detection rules match against this. |
| `severity` | One of `info`, `low`, `medium`, `high`. **Four tiers, not five.** Vendor 5-tier ladders (Azure, SCC, etc.) collapse here. |
| `title` | Short, human-readable. Operators read this in a list. |
| `description` | Optional context. Can be the raw event description, the actor, the IP, etc. |
| `alert_id` | Stable identifier for de-duplication. Use the vendor's ID when one exists; otherwise build a deterministic hash from event content. |
| `host` | Hostname or IP if relevant; `None` if not. |
| `raw` | **Always** include the original payload. Detection rules and the [explain endpoint](/docs/api/rest) both rely on it. |

A few patterns worth copying:

- **`severity` is hard-coded `info`** in the example because httpbin doesn't carry a severity signal. Real connectors derive severity from the vendor's risk score, status code, anomaly flag, etc. — see the [Auth0 connector](https://github.com/beenuar/AiSOC/blob/main/services/connectors/app/connectors/auth0.py) for an example of a simple rule-based mapping.
- **`alert_id` should be stable across re-fetches** when the vendor exposes a unique ID. httpbin doesn't, so the example cheats: it uses `origin + url` as a poor-but-stable hash. If you do this, document it — the next person to look will assume you forgot.
- **`raw` is forensics**. Don't summarise it, don't truncate it, don't drop fields you didn't recognise. The detection layer and the explain endpoint both treat it as the source of truth for "what actually happened".

## Step 8 — Pin the contract with a smoke test

The example is paired with a smoke test at [`services/connectors/tests/test_hello_connector_example.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/tests/test_hello_connector_example.py). It uses [`respx`](https://lundberg.github.io/respx/) (already a dev dependency in `services/connectors/pyproject.toml`) to mock httpx and exercise every method end-to-end:

```python
@respx.mock
@pytest.mark.asyncio
async def test_test_connection_success():
    respx.get("https://httpbin.org/status/200").mock(return_value=httpx.Response(200))
    conn = HelloConnector(api_token="t")
    result = await conn.test_connection()
    assert result == {"success": True, "connector": "hello"}
```

The test file pins three different things, in order of importance:

1. **`HelloConnector` is not in the registry.** This catches the "I copied the example into the catalog by accident" failure mode.
2. **The schema shape doesn't drift.** Field names, secret flags, default values, and the docs URL are all asserted explicitly. If a tutorial reader copies the example and changes one of these without thinking, the test tells them.
3. **Every method behaves the way the tutorial says it does.** Happy path, bad status, network error, invalid JSON, and the `since_seconds` query parameter all have dedicated cases.

When you write your own connector, copy the test layout. The volume isn't large — fifteen short tests cover the entire surface — and the cost of *not* having them is that you ship a connector that silently regresses six months later when a vendor changes their JSON shape.

Run the suite locally:

```bash
cd services/connectors
.venv/bin/python -m pytest tests/test_hello_connector_example.py -v
```

You should see 15 tests pass in well under a second.

## Graduating from `_examples/` to a real connector

When you're ready to ship a real connector, here is the exact checklist:

1. **Move the file.** From `services/connectors/app/connectors/_examples/<your_connector>.py` to `services/connectors/app/connectors/<your_connector>.py`.
2. **Register it.** Add the class to `_CONNECTOR_CLASSES` in `services/connectors/app/connectors/__init__.py`. Keep the tuple alphabetised by `connector_id` to keep diffs predictable. Add the class name to the `__all__` list at the bottom of the same file.
3. **Add a marketplace manifest.** Create `plugins/<connector-id>/plugin.yaml` mirroring your `schema()`. The fields and secret flags must match. Use [`plugins/auth0/plugin.yaml`](https://github.com/beenuar/AiSOC/blob/main/plugins/auth0/plugin.yaml) as a template.
4. **Sync the marketplace.** Run `pnpm marketplace:sync` from the repo root. This regenerates the static catalog under `apps/web/public/marketplace/` so the catalog grid in the UI picks up the new entry.
5. **Write a docs page.** Add `apps/docs/docs/connectors/<your-connector>.md` and wire it into `apps/docs/sidebars.ts` under the `Connectors` category. Use [`apps/docs/docs/connectors/cloudflare.md`](https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/connectors/cloudflare.md) as a template — `What you get` table → `Prerequisites` → `Setup walkthrough` → `Polling details` → `Severity heuristics` → `Troubleshooting`.
6. **Add real tests.** Use `respx` to mock the vendor API. At minimum, exercise `test_connection()` (success + auth failure + network failure), `fetch_alerts()` (happy path + empty + 5xx + auth expiry), and `normalize()` (every severity branch).
7. **Open a PR.** The code review will check that schema fields are wizard-renderable, that secrets are marked `secret=True`, that the category fits the existing taxonomy, that polling failures are non-terminal, and that the docs page exists.

That's the full path. If any of those steps feels heavier than you expected, file a bug — the goal is for adding a connector to feel mechanical, not heroic.

## Related

- [Connectors overview](/docs/connectors/) — the catalog, polling architecture, and category taxonomy.
- [Credential vault](/docs/operations/credentials) — what `secret=True` actually does at the database layer.
- [Plugin SDK overview](/docs/plugins/overview) — for connectors distributed outside the monorepo.
- [Contributing guidelines](/docs/contributing/guidelines) — broader expectations for PRs that touch `services/connectors/`.
