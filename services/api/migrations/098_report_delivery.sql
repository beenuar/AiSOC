-- 098_report_delivery.sql — record whether a generated report reached anybody.
--
-- Depth plan 5.2. `report_artefacts.delivered_at` existed and nothing set
-- it, because nothing delivered. Now that the scheduler does, a timestamp
-- alone is not enough to read the row honestly: "no SMTP relay is
-- configured", "the template names no recipients" and "the relay rejected
-- the address" are three different facts, and all three leave
-- `delivered_at` NULL exactly as a successful delivery that has not
-- finished would.
--
-- So the outcome is a column with a closed vocabulary and the reason is
-- beside it. A console rendering "generated, not delivered: no SMTP relay
-- is configured" sends an operator to the right place; one rendering a
-- blank timestamp sends them nowhere.
--
-- `skipped` is deliberately distinct from `failed`: the first is a choice
-- the deployment made (or did not make) and the second is something going
-- wrong. Collapsing them would make an unconfigured relay look like an
-- outage every five minutes.
--
-- Reversible: DROP COLUMN IF EXISTS on both.

ALTER TABLE report_artefacts
    ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'not_attempted'
    CHECK (delivery_status IN ('not_attempted', 'sent', 'skipped', 'failed'));

ALTER TABLE report_artefacts
    ADD COLUMN IF NOT EXISTS delivery_detail TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN report_artefacts.delivery_status IS
    'Whether the generated report reached anybody. `skipped` is a choice the deployment made '
    '(no relay, no recipients); `failed` is something going wrong. Collapsing the two would '
    'make an unconfigured relay look like an outage on every pass.';
