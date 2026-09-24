-- 063: how a recorded LLM cost is known, alongside the cost.
--
-- Until now a cost figure arrived with no provenance, and the only producer
-- guessed it: `CostTracker` looked the **model name** up in a table of hosted
-- list prices, and the name it looked up was an `aisoc-<role>` alias, which is
-- not a model. No alias was in the table, so every call took a `(0.001,
-- 0.002)` default — a price nobody charges, for a model nobody named. A
-- 903-token completion on an operator's own hardware was stored here as
-- $0.000999, and that figure fed the cost dashboard, the funnel insights, the
-- per-run ledger and the budget circuit breaker.
--
-- The gateway resolved the alias, so the gateway is the only party that knows
-- what ran and what it cost; it reports both on the response headers. This
-- migration gives both tables somewhere to put that, and — following the
-- precedent set for MTTR, where a mean over zero rows was shipping as a
-- confident 0.0 until the sample count travelled with it — somewhere to put
-- the count of calls each sum was computed over.
--
-- Three provenances, mutually exclusive per call:
--
--   measured   the gateway reported the cost. Real money. A measured 0.0 (a
--              local model) is a fact, not a missing value.
--   estimated  re-priced from a public list price for a **concrete** model id.
--              Labelled an estimate on every surface it reaches.
--   unpriced   neither. Rendered "not measured", never as zero.
--
-- Back-compat and the existing rows
-- ---------------------------------
-- Every column is additive with a default, so nothing that reads these tables
-- today breaks. Crucially the new counters default to 0, which means every
-- pre-existing row reads as **not measured** on the new surfaces — which is
-- the truth about it. The historical `total_cost_usd` values are left in
-- place rather than deleted (they are the record of what was reported), but
-- no read path treats a figure as measured unless its counter says so.
--
-- From here on `total_cost_usd` carries **measured** cost only. It cannot also
-- carry the estimate: one column named for money cannot be labelled two ways,
-- and adding a guess to a measurement is how the guess stops looking like one.

ALTER TABLE aisoc_run_costs
    ADD COLUMN IF NOT EXISTS measured_cost_usd    DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS measured_call_count  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_cost_usd   DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unpriced_call_count  INTEGER NOT NULL DEFAULT 0,
    -- What the gateway resolved the requested alias to, e.g. `ollama/qwen2:1.5b`
    -- or `openai/gpt-4o-mini`. The alias asked for is not the model billed, and
    -- without this nothing downstream can say which it was.
    ADD COLUMN IF NOT EXISTS resolved_model       TEXT;

COMMENT ON COLUMN aisoc_run_costs.total_cost_usd IS
    'Measured (gateway-reported) cost only. Rows written before migration 063 '
    'hold a list-price guess keyed on a gateway alias; measured_call_count = 0 '
    'marks them as not measured.';
COMMENT ON COLUMN aisoc_run_costs.measured_call_count IS
    'Calls the measured sum was computed over. 0 means not measured, which is '
    'a different fact from a measured zero.';
COMMENT ON COLUMN aisoc_run_costs.estimated_cost_usd IS
    'List-price estimate for calls the gateway did not price. Must be labelled '
    'an estimate wherever it surfaces.';

ALTER TABLE investigation_runs
    ADD COLUMN IF NOT EXISTS measured_call_count  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_cost_usd   NUMERIC(10, 4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS estimated_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unpriced_call_count  INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN investigation_runs.total_cost_usd IS
    'Measured (gateway-reported) cost only; see measured_call_count. Deep '
    'investigations never passed a value here at all before 063, so the column '
    'held a hard-coded 0 that the console rendered as $0.0000 for runs that had '
    'made real model calls.';
