# aisoc-sdk

[![PyPI version](https://img.shields.io/pypi/v/aisoc-sdk)](https://pypi.org/project/aisoc-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Async Python client SDK for [AiSOC](https://github.com/beenuar/AiSOC).

## Installation

```bash
pip install aisoc-sdk
```

## Quick start

```python
import asyncio
from aisoc_sdk import AiSOCClient

async def main():
    async with AiSOCClient(
        base_url="https://your-aisoc.example.com",
        token="aisoc_...",
    ) as client:
        # List critical open alerts
        alerts = await client.alerts.list(severity="critical", status="open")
        print(f"Found {alerts.total} critical alerts")

        # Create a case
        case = await client.cases.create(
            title="Suspicious lateral movement",
            priority="high",
        )

        # Trigger a playbook
        run = await client.playbooks.run(
            "isolate-host",
            trigger_data={"host_id": "srv-prod-42", "case_id": case.id},
        )
        print("Playbook run:", run.run_id)

asyncio.run(main())
```

## GraphQL

```python
async with AiSOCClient(base_url="...", token="...") as client:
    result = await client.graphql("""
        query {
            alerts(pageSize: 10, status: "open") {
                items { id title severity }
            }
        }
    """)
```

## API reference

All resource methods are `async` and return typed Pydantic models.

| Attribute | Methods |
|---|---|
| `client.alerts` | `list(filters?)`, `get(id)`, `update(id, **data)` |
| `client.cases` | `list(filters?)`, `get(id)`, `create(**data)`, `update(id, **data)`, `delete(id)` |
| `client.detections` | `list(page, page_size)`, `get(id)` |
| `client.connectors` | `list(page, page_size)`, `get(id)` |
| `client.playbooks` | `list(page, page_size)`, `get(id)`, `create(**data)`, `update(id, **data)`, `delete(id)`, `run(id, trigger_data?)`, `get_run(run_id)` |
| `client.api_keys` | `list()`, `create(req)`, `revoke(id)` |

## Development

```bash
pip install -e ".[dev]"
pytest
```
