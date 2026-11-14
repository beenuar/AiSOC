# Cyble AiSOC — developer runbook
# `make dev` starts everything. `make demo` populates a populated dashboard.

BACKEND_DIR := backend
FRONTEND_DIR := frontend
BACKEND_PORT ?= 8478
FRONTEND_PORT ?= 8479
PYTHON ?= python3

.PHONY: help install dev backend frontend stop clean demo seed status open check

# Sanity-check modules. Order is deliberate: cheap+isolating checks first,
# integration-level HTTP+DB checks last so a failure earlier saves time.
CHECK_MODULES := \
	tests._check_reverse_registry \
	tests._check_tenancy \
	tests._check_autopop \
	tests._check_connector_registry \
	tests._check_route_tools \
	tests._check_rollback \
	tests._check_rollback_http \
	tests._check_prompt_injection \
	tests._check_realtime \
	tests._check_detection_author

help:
	@echo "Cyble AiSOC — common targets"
	@echo "  make install   — create venv and install backend deps"
	@echo "  make dev       — start backend (port $(BACKEND_PORT)) and frontend (port $(FRONTEND_PORT))"
	@echo "  make stop      — kill running services"
	@echo "  make demo      — start dev servers + run agents on a curated case set"
	@echo "  make check     — run backend sanity suite (tenancy, rollback, prompt-injection, ...)"
	@echo "  make clean     — wipe local DB to start fresh"
	@echo "  make open      — open the analyst console in your browser"
	@echo "  make status    — show health of running services"

install:
	cd $(BACKEND_DIR) && $(PYTHON) -m venv .venv && \
		. .venv/bin/activate && \
		pip install --quiet --upgrade pip && \
		pip install --quiet -r requirements.txt
	@echo "✓ Backend dependencies installed."

backend:
	@if [ ! -d "$(BACKEND_DIR)/.venv" ]; then $(MAKE) install; fi
	@echo "▶ Backend starting on http://localhost:$(BACKEND_PORT)"
	cd $(BACKEND_DIR) && . .venv/bin/activate && \
		uvicorn app.main:app --host 0.0.0.0 --port $(BACKEND_PORT) --log-level warning

frontend:
	@echo "▶ Frontend serving on http://localhost:$(FRONTEND_PORT)"
	cd $(FRONTEND_DIR) && $(PYTHON) -m http.server $(FRONTEND_PORT) --bind 0.0.0.0

dev:
	@if [ ! -d "$(BACKEND_DIR)/.venv" ]; then $(MAKE) install; fi
	@echo "▶ Starting Cyble AiSOC..."
	@./scripts/dev.sh

stop:
	-@pkill -f "uvicorn app.main" 2>/dev/null
	-@pkill -f "http.server $(FRONTEND_PORT)" 2>/dev/null
	@echo "✓ Services stopped."

clean: stop
	rm -f $(BACKEND_DIR)/data/aisoc.db
	@echo "✓ Database wiped."

seed:
	@curl -s http://localhost:$(BACKEND_PORT)/health > /dev/null || (echo "Backend not running — try 'make dev' first" && exit 1)
	@echo "Seeded on backend startup. Use 'make demo' to run agents on cases."

demo:
	@curl -s http://localhost:$(BACKEND_PORT)/health > /dev/null || (echo "Backend not running. Run 'make dev' in another terminal first." && exit 1)
	@echo "▶ Running agents on curated case set (this takes ~30s)..."
	@for cid in 1 4 5 7 11 14 16 17 19 20; do \
		curl -s -X POST http://localhost:$(BACKEND_PORT)/cases/$$cid/rerun > /dev/null; \
		printf "."; \
		sleep 1.2; \
	done; \
	echo ""; \
	sleep 4; \
	echo "✓ Demo populated. Open http://localhost:$(FRONTEND_PORT)"

open:
	@open http://localhost:$(FRONTEND_PORT) 2>/dev/null || xdg-open http://localhost:$(FRONTEND_PORT) 2>/dev/null || echo "Visit http://localhost:$(FRONTEND_PORT)"

status:
	@curl -s -o /dev/null -w "Backend  (8478): %{http_code}\n" http://localhost:$(BACKEND_PORT)/health || echo "Backend  (8478): down"
	@curl -s -o /dev/null -w "Frontend (8479): %{http_code}\n" http://localhost:$(FRONTEND_PORT)/index.html || echo "Frontend (8479): down"

check:
	@if [ ! -d "$(BACKEND_DIR)/.venv" ]; then $(MAKE) install; fi
	@echo "▶ Running backend sanity suite..."
	@set -e; cd $(BACKEND_DIR) && . .venv/bin/activate && \
		for mod in $(CHECK_MODULES); do \
			printf "  • %s ... " "$$mod"; \
			$(PYTHON) -m $$mod > /tmp/aisoc-check.log 2>&1 && echo "ok" || \
				(echo "FAIL"; cat /tmp/aisoc-check.log; exit 1); \
		done
	@echo "✓ All sanity checks passed."
