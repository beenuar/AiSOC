# AiSOC — one command per thing you actually want to do.
#
# There is exactly one canonical answer to "how do I run this", and it lives
# here. `docker compose` still works directly; these targets are the supported
# spelling and are what the README and CI use, so they cannot drift from the
# documentation without a red build.
#
# Profiles (see docs/architecture/README.md):
#   core  — default. postgres, redis, kafka, ingest, fusion, api, web, agents,
#           the LLM gateway and the local model behind it, and the threat-intel
#           feed with its vector store. The smallest deployment that can take an
#           event, produce an alert, and triage it with a real model — with no
#           credentials at all. ~8GB RAM.
#   full  — core plus the event lake (ClickHouse), entity graph (Neo4j),
#           full-text search (OpenSearch), enrichment and scheduled connectors.
#           ~12GB RAM.
#   demo  — core plus clearly-labelled synthetic data.

.DEFAULT_GOAL := help

PYTHON  ?= python3
COMPOSE ?= docker compose
PROFILE ?=

# `--profile full` when PROFILE=full, nothing otherwise.
PROFILE_ARG := $(if $(PROFILE),--profile $(PROFILE),)

.PHONY: help install env up up-full down restart status doctor smoke demo logs clean \
        bootstrap ingest-token test test-unit test-integration test-e2e stats papers \
        papers-install demo-script

help:
	@echo ""
	@echo "  Getting started"
	@echo "    make install        Install prerequisites, configure, start, and verify"
	@echo "    make env            Create .env and generate its secrets (run by make up)"
	@echo "    make up             Start the CORE stack (postgres, kafka, ingest, fusion, api, web)"
	@echo "    make up-full        Start CORE plus lake, graph, vector, search and enrichment"
	@echo "    make bootstrap      Create the first administrator and print its password once"
	@echo "    make ingest-token   Mint the credential POST /v1/ingest/batch requires"
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

# Creates .env from .env.example and writes a real random value for each secret
# that is empty or still a placeholder. Idempotent: a second run leaves values
# it already generated alone, so `up` can depend on it unconditionally.
#
# This runs *before* compose because compose only interpolates `.env`; there is
# no `env_file` directive anywhere in docker-compose.yml. A value that is wrong
# at `up` time is baked into every container's environment until the next `up`.
env:
	@$(PYTHON) scripts/ensure_env.py

# The port check runs before compose, not after it fails. `docker compose up`
# reports a conflict as `Bind for 127.0.0.1:5432 failed: port is already
# allocated` against whichever container lost the race, which names neither the
# process holding the port nor what to do about it. Half the stack is running
# by then, so the error also arrives after a minute of unrelated output.
up: env _ports
	$(COMPOSE) up -d
	@echo ""
	@echo "Waiting for services to become healthy…"
	@$(MAKE) --no-print-directory _wait
	@echo ""
	@echo "  Console:  http://localhost:3000"
	@echo "  API:      http://localhost:8000/api/docs"
	@echo ""
	@echo "Prove the pipeline works:  make smoke"
	@$(MAKE) --no-print-directory bootstrap

# Creates the first administrator and prints the password once. Idempotent: a
# second run reports the existing account and changes nothing, which is why
# `up` can call it unconditionally.
#
# Failure here is reported but does not fail `up`. The stack is genuinely
# running at this point, and a `make up` that exits non-zero over an account
# the operator can create with one more command would be the wrong signal —
# but it must say so, because silence would leave them at a login form with no
# credential and no explanation.
# `make bootstrap ARGS=--reset-password` replaces the password of an account
# that already exists, which is the answer to "the terminal scrolled away".
bootstrap:
	@$(COMPOSE) run --rm -T api python -m app.scripts.bootstrap_admin $(ARGS) || { \
	  echo ""; \
	  echo "Could not create the administrator — the stack is up, but you cannot sign in yet."; \
	  echo "Run 'make doctor' to find out why, then 'make bootstrap' again."; \
	}

# The lake and graph writers target stores that exist only in `full`, so the
# flags travel with the profile. In CORE they default off rather than
# retrying forever against a host that is not there.
#
# `_ports` runs here for the same reason it runs for `up`, more so: this
# starts twenty-one services, so the bind failure compose reports arrives
# even later and against even more unrelated output. Observed: a conflict on
# 8123 stopped the stack after eight containers had already started, with
# `Bind for 0.0.0.0:8123 failed: port is already allocated` naming neither the
# process holding it nor what to do.
up-full: env _ports
	AISOC_LAKE_WRITER_ENABLED=true AISOC_GRAPH_ENABLED=true $(COMPOSE) --profile full up -d
	@$(MAKE) --no-print-directory _wait PROFILE=full
	@echo ""
	@echo "  Console:  http://localhost:3000"
	@echo "  API:      http://localhost:8000/api/docs"
	@echo ""
	@echo "Prove the pipeline works:  make smoke"
	@$(MAKE) --no-print-directory bootstrap

# Names a port conflict before compose hits it. Silent when every port is
# either free or already held by this deployment's own containers — re-running
# `make up` on a running stack must not be reported as a conflict with itself.
_ports:
	@./scripts/doctor.sh --ports-only || { \
	  echo ""; \
	  echo "Not starting: the ports above are taken by something else."; \
	  echo "Stop that process, or edit the host port in docker-compose.yml."; \
	  echo "(A docker-compose.override.yml needs 'ports: !override' — a plain"; \
	  echo " override appends, leaving the conflicting binding in place.)"; \
	  exit 1; \
	}

# Waits on the services that declare a healthcheck, and refuses to call a
# stack up while any container is dead.
#
# The old loop read `ps` without `-a` and looked only at Health. An *exited*
# container is absent from that listing entirely and a *restarting* one
# reports no health, so both were invisible: `make up-full` printed
# "Full profile up." with OpenSearch OOM-killed and threatintel in a crash
# loop. A container that is not running is the one thing a wait loop must
# never score as success.
#
# `exited` alone is not that thing, though, and reading it as such broke the
# documented command on every machine. `ollama-pull` is a one-shot: it fetches
# the model and exits 0, and `litellm` waits on
# `service_completed_successfully`, so by the time `docker compose up -d`
# returns the puller has *always* exited. `make up` therefore ended in
# "These services are not running: ollama-pull" on the first run and every
# run after it — a stack that was entirely healthy, reported as broken, by
# the step whose job is to say whether it is healthy. The exit code is what
# separates the two cases: 0 is a one-shot that did its job, anything else is
# a container that died.
#
# The fields are `|`-separated rather than space-separated because a service
# with no healthcheck prints an *empty* Health, and awk's default splitting
# collapses the run of whitespace — so `ollama-pull exited  0` parsed as three
# fields with the exit code in $$3 and nothing in $$4, and the new exit-code
# test read an empty string on exactly the row it was written for.
_wait:
	@for i in $$(seq 1 60); do \
	  status=$$($(COMPOSE) $(PROFILE_ARG) ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' 2>/dev/null); \
	  pending=$$(echo "$$status" | awk -F'|' '$$3=="starting"{print $$1}'); \
	  broken=$$(echo "$$status" | awk -F'|' '($$2=="exited"&&$$4!="0")||$$2=="dead"||$$2=="restarting"||$$3=="unhealthy"{print $$1}'); \
	  if [ -n "$$broken" ]; then \
	    echo ""; \
	    echo "These services are not running: $$broken"; \
	    for s in $$broken; do echo "  docker compose logs $$s | tail -30"; done; \
	    echo "Run 'make doctor' for the full picture."; \
	    exit 1; \
	  fi; \
	  [ -z "$$pending" ] && exit 0; \
	  sleep 3; \
	done; \
	echo "Still not healthy after 3 minutes: $$pending"; \
	echo "Run 'make doctor' to find out why."; \
	exit 1

down:
	$(COMPOSE) --profile full --profile monitoring --profile chatops --profile extras --profile osquery down

restart: down up

status:
	@$(COMPOSE) ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'

doctor:
	@./scripts/doctor.sh $(if $(filter full,$(PROFILE)),--full,)

# The credential POST /v1/ingest/batch requires. Idempotent: an existing
# active push token is returned rather than a second one being minted, so
# `smoke` can call it on every run. `make ingest-token ARGS=--rotate`
# replaces it.
ingest-token:
	@$(COMPOSE) run --rm -T api python -m app.scripts.mint_ingest_token $(ARGS)

# The golden pipeline. One real event, through the real spine, observed from
# outside. This is the only claim of "it works" the project makes.
#
# The token is minted first because ingest is authenticated: the endpoint
# takes a credential that carries its own tenant rather than a header
# naming one. Minting here keeps `make smoke` a single command.
smoke:
	@token="$$($(COMPOSE) run --rm -T api python -m app.scripts.mint_ingest_token --quiet)" || { \
	  echo "Could not mint an ingest token — is the stack up? Try 'make doctor'."; \
	  exit 1; \
	}; \
	AISOC_INGEST_TOKEN="$$token" $(PYTHON) tests/e2e/golden_pipeline/run_golden_pipeline.py

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
