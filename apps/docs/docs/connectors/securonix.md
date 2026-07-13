---
title: Securonix
description: Ingest incidents (priority→severity) into AiSOC (securonix connector).
---

# Securonix

The **Securonix** connector (`securonix`, category `siem`) pulls incidents (priority→severity) and normalizes each into the AiSOC alert shape, mapping the source severity onto the five-tier ladder (`info | low | medium | high | critical`).

## Setup

1. In **Connectors -> Add connector**, choose **Securonix**.
2. Fill in the connection fields shown in the wizard (endpoint URL + API token; secrets are stored in the credential vault, never in plaintext).
3. Click **Test connection** to verify credentials, then **Save**. The in-process scheduler begins polling on the default cadence.

Events flow through ingest (OCSF normalize) -> Kafka -> fusion, where detections fire and alerts are auto-triaged (copilot).
