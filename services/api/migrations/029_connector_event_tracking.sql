-- Workstream 1 (verify-data-flowing) + Workstream 5 (freshness SLO) +
-- Workstream 6 (universal capture) groundwork.
--
-- last_event_at:   timestamp of the most recently ingested raw event for
--                  this connector, distinct from `last_sync` (which ticks
--                  every poll cycle, including empty polls). This is what
--                  the onboarding "verify data flowing" screen polls and
--                  what feeds the freshness-SLO badge in the UI.
--
-- last_event_kind: short label for the event source ("alert", "audit",
--                  "webhook", "push") so the UI can render a meaningful
--                  "first event landed" preview without joining the raw
--                  events table.
--
-- ingest_token:    opaque per-connector token used by services/ingest's
--                  `/v1/inbox/{tenant_token}` push endpoint. Generating
--                  it lazily (NULL until first call to /push/refresh)
--                  keeps existing rows valid.
ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS last_event_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_event_kind TEXT,
    ADD COLUMN IF NOT EXISTS ingest_token TEXT UNIQUE;

CREATE INDEX IF NOT EXISTS connectors_last_event_at_idx
    ON connectors (tenant_id, last_event_at DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS connectors_ingest_token_idx
    ON connectors (ingest_token)
    WHERE ingest_token IS NOT NULL;
