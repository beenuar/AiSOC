-- Migration 028: Human-readable case identifiers on aisoc_cases
--
-- The web console (and demo deeplinks like /cases/INC-RT-001 or /cases/INC-007)
-- need to look up a case by a stable, short, human-readable identifier — not a
-- UUID. The ORM `cases` table already has a `case_number` column (e.g.
-- CASE-1042), but the canonical demo table `aisoc_cases` does not.  Adding it
-- here lets the API resolve `/api/v1/cases/INC-RT-001` (or any `INC-NNN` from
-- the seeded catalogue) against `case_number` while still accepting raw UUIDs,
-- without breaking any existing rows.

ALTER TABLE aisoc_cases
    ADD COLUMN IF NOT EXISTS case_number TEXT;

-- Backfill any pre-existing rows so the column is never NULL going forward.
-- Use the row's own UUID prefix as a fallback so we don't violate UNIQUE.
UPDATE aisoc_cases
SET case_number = 'CASE-' || substr(id::text, 1, 8)
WHERE case_number IS NULL;

-- Now enforce uniqueness + an index for fast lookup by external id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_aisoc_cases_case_number
    ON aisoc_cases (case_number);
