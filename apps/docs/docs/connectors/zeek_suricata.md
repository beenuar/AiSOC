---
title: Zeek / Suricata NDR
description: Ingest Zeek notice + Suricata eve.json alerts into AiSOC (zeek_suricata connector).
---

# Zeek / Suricata NDR

The **Zeek / Suricata NDR** connector (`zeek_suricata`, category `ndr`) pulls Zeek notice + Suricata eve.json alerts and normalizes each into the AiSOC alert shape, mapping the source severity onto the five-tier ladder (`info | low | medium | high | critical`).

## Setup

1. In **Connectors -> Add connector**, choose **Zeek / Suricata NDR**.
2. Fill in the connection fields shown in the wizard (endpoint URL + API token; secrets are stored in the credential vault, never in plaintext).
3. Click **Test connection** to verify credentials, then **Save**. The in-process scheduler begins polling on the default cadence.

Events flow through ingest (OCSF normalize) -> Kafka -> fusion, where detections fire and alerts are auto-triaged (copilot).
