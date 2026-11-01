-- Migration 133: cloud-security findings as triage context (depth2 8.1)
--
-- `posture_findings` has existed since migration 017 with RLS, six indices and
-- a REST surface. It has had exactly one writer in the whole tree: the route
-- `POST /posture/findings`, which a human calls by hand. No collector, no
-- scheduler and no connector has ever written a row, so `GET /posture/summary`
-- answered eight confident zeros on every deployment and `GET /posture/scans`
-- read a table with no writer at all.
--
-- This migration does not add a second store. It adds the four columns a
-- collector needs to write the table idempotently and the one column a verdict
-- needs to find a finding from an alert, then gives `posture_scan_runs` the
-- meaning it needs so "nobody has collected" and "collected, nothing found"
-- stop being the same answer.
--
-- Read-only by construction: wave-2 Phase 8.x produces findings and context
-- only, so nothing here records an intent to change a cloud resource.

BEGIN;

-- 1. Provenance --------------------------------------------------------------
-- Which collector produced the row. `manual` is the honest default for every
-- row that exists today, because the hand-called route is the only thing that
-- could have written one.
ALTER TABLE posture_findings
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';

-- What kind of finding it is. A misconfiguration, a secret and a runtime
-- detection are three different questions about one resource and a verdict
-- weighs them differently; collapsing them into one bucket would make the
-- prompt say "there is a finding here" and mean nothing by it.
--
-- `vulnerability` is deliberately NOT in this list. Per-asset CVE state has
-- its own store (`asset_vulnerabilities`), its own collection hook
-- (`fetch_vulnerability_findings`) and its own patch-window policy, and a
-- second home for it would be a second answer to "are we exposed to this CVE".
ALTER TABLE posture_findings
    ADD COLUMN IF NOT EXISTS finding_class TEXT NOT NULL DEFAULT 'misconfiguration';

ALTER TABLE posture_findings
    DROP CONSTRAINT IF EXISTS posture_findings_finding_class_check;
ALTER TABLE posture_findings
    ADD CONSTRAINT posture_findings_finding_class_check
    CHECK (finding_class IN ('misconfiguration', 'secret', 'runtime_detection', 'issue'));

-- The vendor's own id for the finding, so a re-poll updates one row instead of
-- appending a duplicate every five minutes.
ALTER TABLE posture_findings
    ADD COLUMN IF NOT EXISTS external_id TEXT;

-- 2. Finding a finding from an alert ------------------------------------------
-- An alert names a resource in whatever shape its own vendor used: a cloud
-- provider id, an ARN, a bare instance name, a hostname. A CNAPP names the
-- same resource by its own graph id *and* the provider's id *and* a display
-- name. Matching one column against one column would miss on nearly every
-- pair, so the collector writes every key it knows, lowercased, and the lookup
-- is an array overlap against the keys the alert carries.
ALTER TABLE posture_findings
    ADD COLUMN IF NOT EXISTS resource_keys TEXT[] NOT NULL DEFAULT ARRAY[]::text[];

-- 3. Freshness ----------------------------------------------------------------
-- `last_evaluated_at` already exists and the trigger moves `updated_at`, but
-- neither answers "when did the collector last see this finding still open",
-- which is what decides whether a finding is worth putting in a prompt.
ALTER TABLE posture_findings
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- 4. Idempotent re-poll --------------------------------------------------------
-- Partial, because rows written by hand through the REST route carry no vendor
-- id and must not collide with each other.
CREATE UNIQUE INDEX IF NOT EXISTS uq_posture_findings_vendor
    ON posture_findings (tenant_id, source, external_id)
    WHERE external_id IS NOT NULL;

-- Overlap lookups need GIN; a btree on a text[] cannot serve `&&`.
CREATE INDEX IF NOT EXISTS idx_posture_resource_keys
    ON posture_findings USING GIN (resource_keys);

CREATE INDEX IF NOT EXISTS idx_posture_class
    ON posture_findings (tenant_id, finding_class, status);

-- 5. "Never collected" is not "zero findings" ----------------------------------
-- `posture_scan_runs` had no writer, so there was no way to tell a tenant that
-- has never connected a CNAPP from one whose cloud estate is clean. The
-- collector now writes a run per poll, and the summary reads it to decide
-- whether it may report a count at all.
ALTER TABLE posture_scan_runs
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';

ALTER TABLE posture_scan_runs
    ADD COLUMN IF NOT EXISTS finding_classes TEXT[] NOT NULL DEFAULT ARRAY[]::text[];

CREATE INDEX IF NOT EXISTS idx_scan_tenant_source
    ON posture_scan_runs (tenant_id, source, started_at DESC);

COMMIT;
