# Top-level Makefile — convenience targets for the AiSOC repo.
#
# The bulk of the build / test / deploy surface still lives in the
# per-service Dockerfiles and CI workflows. This Makefile only carries
# the few targets that benefit from being a single command on a
# developer laptop or in CI.
#
# Phase 4.3 (papers + demo) lands the `make papers` target the public
# white-paper README has been promising since v8.0.

.DEFAULT_GOAL := help

PYTHON ?= python3

.PHONY: help papers papers-install demo-script

help:
	@echo "Common targets:"
	@echo "  make papers           — render every public white paper to PDF"
	@echo "  make papers-install   — install the Python deps render_white_paper needs"
	@echo "  make demo-script      — emit the 90s demo screencast shot list"
	@echo ""
	@echo "Service-level targets live under each service directory:"
	@echo "  services/api, services/agents, apps/web, apps/docs, ..."

# --- Public papers ---------------------------------------------------------
# `make papers` rebuilds every PDF under apps/web/public/papers/ from the
# matching markdown source under apps/web/content/papers/. The script is
# idempotent — it overwrites existing PDFs in place — and the CI workflow
# `.github/workflows/papers.yml` runs the same command on push to main.
papers:
	$(PYTHON) scripts/render_white_paper.py --all

papers-install:
	$(PYTHON) -m pip install --quiet 'markdown>=3.5' 'weasyprint>=60'

# --- 90s demo screencast --------------------------------------------------
# Emit (to stdout) the shot list / narration / timings that drive the
# 90-second product walkthrough. The recorder uses this file as the
# canonical script so the cut never drifts from what the engineering team
# considers the on-message demo.
demo-script:
	@cat docs/demo/SCREENCAST_SHOTLIST.md
