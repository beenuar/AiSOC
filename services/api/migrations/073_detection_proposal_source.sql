-- AiSOC: the column three proposal writers already name
-- Author: Beenu - beenu@cyble.com
--
-- `detection_rule_proposals` has never had a `source` column, and three raw
-- INSERT statements name it:
--
--   * app/api/v1/endpoints/rule_tuning.py   writes 'auto-tuner'
--   * app/workers/hunt_scheduler.py         writes 'hunt-finding'
--   * app/api/v1/endpoints/detection_loop.py writes 'detection-loop'
--
-- Each raises UndefinedColumnError on the first row it tries to write, so
-- none of the three automated authoring paths can produce a proposal on any
-- deployment. Nothing caught it: no CI job runs `services/api/tests/`
-- against a real database, and the one test covering the insert asserted
-- only that the table name appeared somewhere in the SQL string.
--
-- `scripts/check_raw_sql_columns.py` found it, and now holds raw SQL to the
-- same table-and-column contract `check_orm_migration_parity.py` already
-- holds the ORM models to.
--
-- Nullable with no default: rows written before this migration have no
-- provenance to claim, and NULL is the honest value for "not recorded" —
-- distinct from a proposal an analyst authored by hand.

ALTER TABLE detection_rule_proposals
    ADD COLUMN IF NOT EXISTS source TEXT;

COMMENT ON COLUMN detection_rule_proposals.source IS
    'Which automated path authored this proposal: auto-tuner (analyst disposition history), hunt-finding (a scheduled hunt that hit), detection-loop (a false-positive fix). NULL for a hand-authored proposal or any row predating this column.';
