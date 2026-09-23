# AiSOC — one command per thing you actually want to do.
#
# There is exactly one canonical answer to "how do I run this", and it lives
# here. `docker compose` still works directly; these targets are the supported
# spelling and are what the README and CI use, so they cannot drift from the
# documentation without a red build.
#
# Profiles (see docs/architecture/README.md):
#   core  — default. postgres, redis, kafka, ingest, fusion, api, web, agents.
#           The smallest deployment that can take an event and produce an
#           alert. ~6GB RAM.
#   full  — core plus the event lake (ClickHouse), entity graph (Neo4j),
#           vector store (Qdrant), search (OpenSearch), enrichment, connectors
#           and the LLM gateway. ~12GB RAM.
#   demo  — core plus clearly-labelled synthetic data.

.DEFAULT_GOAL := help

PYTHON  ?= python3
COMPOSE ?= docker compose
PROFILE ?=

# `--profile full` when PROFILE=full, nothing otherwise.
PROFILE_ARG := $(if $(PROFILE),--profile $(PROFILE),)

.PHONY: help install up up-full down restart status doctor smoke demo logs clean \
        test test-unit test-integration test-e2e stats papers papers-install demo-script

help:
	@echo ""
	@echo "  Getting started"
	@echo "    make install        Install prerequisites, configure, start, and verify"
	@echo "    make up             Start the CORE stack (postgres, kafka, ingest, fusion, api, web)"
	@echo "    make up-full        Start CORE plus lake, graph, vector, search and enrichment"
	@echo "    make smoke          Push one real event through the pipeline and check it becomes an alert"
	@echo "    make doctor         Diagnose the deployment and say what to fix"
	@echo ""
	@echo "  Running it"
	@echo "    make status         Show every service and its health"
	@echo "    make logs           Follow logs (SERVICE=fusion to narrow)"
	@echo "    make restart        Restart the stack"
	@echo "    make down           Stop the stack, keep the data"
	@echo "    make clean          Stop the stack and delete all volumes"
	@echo "    make demo           Load clearly-labelled synthetic data"
	@echo ""
	@echo "  Developing"
	@echo "    make test           Unit tests for every service"
	@echo "    make test-e2e       The golden pipeline against a running stack"
	@echo "    make stats          Recount the figures the README publishes"
	@echo ""

# ── Getting started ────────────────────────────────────────────────────────

install:
	./install.sh

up:
	$(COMPOSE) up -d
	@echo ""
	@echo "Waiting for services to become healthy…"
	@$(MAKE) --no-print-directory _wait
	@echo ""
	@echo "  Console:  http://localhost:3000"
	@echo "  API:      http://localhost:8000/docs"
	@echo ""
	@echo "Prove the pipeline works:  make smoke"

up-full:
	$(COMPOSE) --profile full up -d
	@$(MAKE) --no-print-directory _wait
	@echo "Full profile up. Prove the pipeline works: make smoke"

# Waits on the services that declare a healthcheck. Silent on success.
_wait:
	@for i in $$(seq 1 60); do \
	  unhealthy=$$($(COMPOSE) ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk '$$2=="starting"||$$2=="unhealthy"{print $$1}'); \
	  [ -z "$$unhealthy" ] && exit 0; \
	  sleep 3; \
	done; \
	echo "Still not healthy after 3 minutes: $$unhealthy"; \
	echo "Run 'make doctor' to find out why."; \
	exit 1

down:
	$(COMPOSE) --profile full --profile monitoring --profile chatops --profile extras --profile osquery down

restart: down up

status:
	@$(COMPOSE) ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'

doctor:
	@./scripts/doctor.sh $(if $(filter full,$(PROFILE)),--full,)

# The golden pipeline. One real event, through the real spine, observed from
# outside. This is the only claim of "it works" the project makes.
smoke:
	@$(PYTHON) tests/e2e/golden_pipeline/run_golden_pipeline.py

demo:
	@echo "Loading synthetic demo data. Every row is tagged is_synthetic=true"
	@echo "and the console labels it. See 'Real vs synthetic data' in README.md."
	$(COMPOSE) run --rm -e AISOC_ALLOW_SEED=1 api python -m app.scripts.seed_demo

logs:
	$(COMPOSE) logs -f --tail=200 $(SERVICE)

clean:
	$(COMPOSE) --profile full --profile monitoring --profile chatops --profile extras --profile osquery down -v
	@echo "Stack stopped and volumes deleted."

# ── Tests ──────────────────────────────────────────────────────────────────

test: test-unit

test-unit:
	@set -e; for svc in api agents fusion actions connectors; do \
	  if [ -d "services/$$svc/tests" ]; then \
	    echo "── services/$$svc"; \
	    (cd "services/$$svc" && $(PYTHON) -m pytest tests/ -q) || exit 1; \
	  fi; \
	done

test-integration:
	@$(PYTHON) -m pytest tests/ -q --ignore=tests/e2e

test-e2e: smoke

# ── Project figures ────────────────────────────────────────────────────────
# Every quantitative claim in the README is produced by this, so a figure
# cannot be edited by hand into something the tree does not support.
stats:
	@$(PYTHON) scripts/project_stats.py

# ── Papers + demo script (pre-existing) ────────────────────────────────────

papers:
	$(PYTHON) scripts/render_white_paper.py --all

papers-install:
	$(PYTHON) -m pip install --quiet 'markdown>=3.5' 'weasyprint>=60'

demo-script:
	@cat docs/demo/SCREENCAST_SHOTLIST.md
