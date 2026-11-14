-- AiSOC WS-B4: Detection-as-Code git PR path
-- Author: Beenu - beenu@cyble.com
--
-- Adds `github_pr_url` to `detection_rule_proposals` so the promote
-- endpoint can link each promoted proposal to the GitHub Pull Request
-- that carries the Sigma/YARA rule file into the detections/ directory.
-- The URL is optional — deployments without AISOC_GITHUB_TOKEN configured
-- will leave it NULL and the UI omits the link.

ALTER TABLE detection_rule_proposals
    ADD COLUMN IF NOT EXISTS github_pr_url TEXT;

COMMENT ON COLUMN detection_rule_proposals.github_pr_url IS
    'GitHub Pull Request URL created when this proposal was promoted (e.g. https://github.com/org/repo/pull/42). NULL when GitHub integration is not configured.';
