# Generated from infra/fly/managed/template/agents/fly.toml.tpl
# DO NOT EDIT — regenerate via `./infra/fly/managed/render.sh <tenant.yaml>`.
#
# Managed-mode AiSOC Agent orchestrator (LangGraph) for tenant ${TENANT_SLUG}.

app = "aisoc-${TENANT_SLUG}-agents"
primary_region = "${REGION}"
kill_signal    = "SIGINT"
kill_timeout   = "10s"

[env]
  ENVIRONMENT       = "managed"
  LOG_LEVEL         = "info"
  PORT              = "8084"
  AISOC_TENANT_SLUG = "${TENANT_SLUG}"
  AISOC_AGENT_MODE  = "live"
  # Agents reach the API over the internal 6PN DNS so the request never
  # leaves the Fly network. This is the tenant-isolation contract: agent
  # decisions are scoped to a single Fly app boundary.
  CORE_API_URL      = "http://aisoc-${TENANT_SLUG}-api.internal:8000"

[http_service]
  internal_port       = 8084
  force_https         = false   # internal-only; no public traffic
  auto_stop_machines  = "off"
  auto_start_machines = true
  min_machines_running = 1
  processes           = ["app"]

  [[http_service.checks]]
    grace_period = "30s"
    interval     = "15s"
    method       = "GET"
    timeout      = "5s"
    path         = "/readyz"

[[vm]]
  size      = "${AGENTS_VM_SIZE}"
  memory_mb = 2048
