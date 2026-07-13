---
title: Syslog / CEF
description: Ingest generic syslog + ArcSight CEF into AiSOC (syslog_cef connector).
---

# Syslog / CEF

The **Syslog / CEF** connector (`syslog_cef`, category `network`) pulls generic syslog + ArcSight CEF and normalizes each into the AiSOC alert shape, mapping the source severity onto the five-tier ladder (`info | low | medium | high | critical`).

## Setup

1. In **Connectors -> Add connector**, choose **Syslog / CEF**.
2. Fill in the connection fields shown in the wizard (endpoint URL + API token; secrets are stored in the credential vault, never in plaintext).
3. Click **Test connection** to verify credentials, then **Save**. The in-process scheduler begins polling on the default cadence.

Events flow through ingest (OCSF normalize) -> Kafka -> fusion, where detections fire and alerts are auto-triaged (copilot).
