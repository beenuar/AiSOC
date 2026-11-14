-- Migration 027: Per-case investigation/response tasks
--
-- The web console renders a "Tasks" panel in the case workspace where SOC
-- analysts can capture follow-up work (run forensic image, contact owner,
-- block IP at the edge, …) tied to a specific case. Tasks are simple — a
-- title, an optional assignee/due date, and a three-state status.

CREATE TABLE IF NOT EXISTS aisoc_case_tasks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'todo'
                    CHECK (status IN ('todo','in_progress','done')),
    assignee    TEXT,
    due_at      TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT
);

CREATE INDEX IF NOT EXISTS idx_aisoc_case_tasks_case   ON aisoc_case_tasks (case_id);
CREATE INDEX IF NOT EXISTS idx_aisoc_case_tasks_status ON aisoc_case_tasks (status);
