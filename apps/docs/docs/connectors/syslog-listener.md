---
id: syslog-listener
title: Syslog listener (RFC 5424, RFC 3164, CEF, LEEF)
sidebar_label: Syslog listener
---

Firewalls, proxies, load balancers, legacy IDS and a great deal of custom
gear emit syslog and will never grow a webhook. The ingest service accepts
syslog directly over UDP and TCP, so the appliance reaches AiSOC itself
rather than needing a forwarder in front of it.

Four wire formats are read:

| Format | What it is | How it is recognised |
|---|---|---|
| **RFC 5424** | The current standard: version digit, RFC 3339 timestamp, structured data | the `1 ` version digit after the priority |
| **RFC 3164** | The one most gear emits; no year, no zone, optional hostname | the three-letter month |
| **CEF** | ArcSight key/value, carried inside a syslog line | a `CEF:` anchor |
| **LEEF** | IBM QRadar key/value, with a delimiter the header may redefine | a `LEEF:` anchor |

A line matching none of them is kept as an unstructured message with its
text intact. It is never reported as a structured record with invented
fields — a mis-split line puts half the message in the hostname column, and
an analyst reading that record sees a host that does not exist.

## One listener, one tenant

The tenant comes from a minted ingest token you put in the service's
configuration, and from nowhere else.

That is not a limitation to work around, it is the point. Syslog carries no
authenticated principal and no header, so **anything read off the wire is
sender-controlled**: a tenant taken from the hostname, the application name
or a structured-data parameter would be a cross-tenant write that needs no
attacker effort at all. A multi-tenant deployment runs one listener port per
tenant.

## Setting it up

**1. Mint a token.** Use the `syslog` template:

```bash
curl -sS -X POST https://your-aisoc/api/v1/inbox/tokens \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"template_id": "syslog", "label": "edge firewalls"}'
```

The response carries the token once. One token covers all four formats: a
single appliance commonly emits RFC 3164 for its daemons and CEF for its
security events, and making you mint two tokens and run two ports for one
device would be a configuration no vendor documents.

**2. Turn the listener on.** In the ingest service's environment:

```bash
AISOC_SYSLOG_ENABLED=true
AISOC_SYSLOG_TOKEN=<the token from step 1>
AISOC_SYSLOG_UDP_ADDR=0.0.0.0:5514
AISOC_SYSLOG_TCP_ADDR=0.0.0.0:5514
```

Port **5514**, not 514, is the default on purpose: 514 is privileged, so
binding it needs either `CAP_NET_BIND_SERVICE` on the container or a
published port mapping `514` to `5514` on the host. Publish the UDP and TCP
ports in your compose file or Service, and remember that a UDP port
published by Docker needs `/udp` spelled out.

Set `AISOC_SYSLOG_UDP_ADDR` or `AISOC_SYSLOG_TCP_ADDR` to an empty string to
run only one transport. Setting both to empty is refused rather than
accepted as a no-op: a listener bound to nothing looks identical to a
listener nobody is sending to.

**3. Point the device at it.** On most Linux senders:

```
*.* @@aisoc-ingest.internal:5514    # TCP
*.* @aisoc-ingest.internal:5514     # UDP
```

**4. Check `/readyz`.** The listener appears by name under
`subscriptions`, with what it bound, how many messages it has received and
what it last failed on:

```json
{
  "subscriptions": {
    "syslog": {
      "attached": true,
      "not_resolving": false,
      "detail": "listening on udp 0.0.0.0:5514, tcp 0.0.0.0:5514; received 1842, rejected 0"
    }
  }
}
```

A receiver is legitimately silent for hours, so "no messages" proves nothing
either way — which is why readiness reports the counters rather than only a
boolean.

## What happens to a message

| Parsed as | Template | OCSF class |
|---|---|---|
| RFC 5424, RFC 3164, unstructured | `syslog` | 1007 Process Activity (category 1) |
| CEF | `cef-syslog` | 2001 Security Finding (category 2) |
| LEEF | `leef-syslog` | 2001 Security Finding (category 2) |

The split matters. Category 2 is promoted to an alert unconditionally, so
filing a firewall's routine daemon chatter as a Security Finding would turn
every line into an alert — exactly the noise the platform exists to remove.
A plain syslog line becomes an alert when a detection rule fires on it. A
CEF or LEEF line is promoted because a device emitting one of those has
already decided the line is a security event.

The original line is kept verbatim on every event as `raw_data`. Every
parse here is a lossy summary, and an appliance emitting something the
parser misreads is itself the finding.

## Limits worth knowing before you rely on it

- **TCP framing**: both of RFC 6587's framings are read — octet-counting
  (`123 <34>1 ...`) and newline-delimited. Octet-counting is the one that
  survives a message containing a newline; prefer it if your sender offers
  it.
- **A failed publish loses the message.** Syslog has no acknowledgement to
  withhold, so if Kafka is unreachable the batch is dropped, counted on
  `aisoc_ingest_syslog_rejected_total` and named in the `/readyz` detail.
  Nothing can make that lossless at this layer; use the HTTP inbox routes
  for a source where loss is unacceptable.
- **RFC 3164 timestamps carry no year.** The receiver's year is filled in,
  with a day of slack so a line arriving just after midnight on 1 January is
  dated to the year it was written rather than to the next one. The original
  text stays in `raw_data`.
- **Connections are capped** (`AISOC_SYSLOG_MAX_CONNECTIONS`, default 256)
  and a connection over the cap is refused immediately rather than held
  open, so a sender finds out instead of believing it is delivering.
