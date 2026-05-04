---
sidebar_position: 3
---

# WebSocket API Reference

AiSOC streams real-time events over an authenticated WebSocket connection served by the `realtime` service (port 8086).

## Connection

```
wss://your-domain.com/ws?token=<jwt>
```

Locally:

```
ws://localhost:8086/ws?token=<jwt>
```

Pass a valid JWT in the `token` query parameter. The connection is rejected with `4001 Unauthorized` if the token is missing or expired.

## Message Format

All messages are JSON objects with a `type` field:

```json
{
  "type": "alert.created",
  "payload": { ... },
  "tenant_id": "uuid",
  "ts": "2026-05-03T10:00:00Z"
}
```

## Server → Client Events

### Alerts

| Type | Description |
|------|-------------|
| `alert.created` | New alert ingested |
| `alert.updated` | Alert status / severity changed |
| `alert.assigned` | Alert assigned to analyst |

### Cases

| Type | Description |
|------|-------------|
| `case.created` | New case opened |
| `case.updated` | Case fields updated |
| `case.comment` | Comment added |
| `case.closed` | Case closed |

### Investigations (AI Copilot)

| Type | Description |
|------|-------------|
| `investigation.started` | Agent investigation begun |
| `investigation.step` | Intermediate reasoning step |
| `investigation.finding` | Finding added to case |
| `investigation.completed` | Investigation finished |
| `investigation.error` | Investigation failed |

### Detections

| Type | Description |
|------|-------------|
| `detection.triggered` | Rule fired |
| `detection.suppressed` | Detection suppressed by a rule |

### UEBA

| Type | Description |
|------|-------------|
| `ueba.anomaly` | Behavioral anomaly detected |
| `ueba.baseline_updated` | Baseline recalculated |

### Honeytokens

| Type | Description |
|------|-------------|
| `honeytoken.touched` | Token accessed / triggered |

### Playbooks

| Type | Description |
|------|-------------|
| `playbook.started` | Playbook execution started |
| `playbook.step` | Step completed |
| `playbook.completed` | Playbook finished |
| `playbook.failed` | Playbook failed |

### System

| Type | Description |
|------|-------------|
| `ping` | Server keepalive (every 30 s) |
| `error` | Protocol or server error |

## Client → Server Messages

### Subscribe to a channel

```json
{
  "type": "subscribe",
  "channel": "alerts"
}
```

Available channels: `alerts`, `cases`, `detections`, `investigations`, `ueba`, `honeytokens`, `playbooks`, `all`.

### Unsubscribe

```json
{
  "type": "unsubscribe",
  "channel": "alerts"
}
```

### Pong (keepalive reply)

```json
{ "type": "pong" }
```

## Example (Browser)

```javascript
const ws = new WebSocket(`ws://localhost:8086/ws?token=${jwt}`);

ws.onopen = () => {
  ws.send(JSON.stringify({ type: "subscribe", channel: "all" }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === "alert.created") {
    console.log("New alert:", msg.payload);
  }
};
```

## React Hook

The Next.js frontend exposes a `useRealtimeEvents` hook:

```typescript
import { useRealtimeEvents } from "@/hooks/useRealtimeEvents";

function AlertFeed() {
  const events = useRealtimeEvents(["alert.created", "alert.updated"]);
  return <ul>{events.map(e => <li key={e.payload.id}>{e.payload.title}</li>)}</ul>;
}
```
