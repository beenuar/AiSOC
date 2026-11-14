# Generated from infra/fly/managed/template/realtime/fly.toml.tpl
# DO NOT EDIT — regenerate via `./infra/fly/managed/render.sh <tenant.yaml>`.
#
# Managed-mode AiSOC realtime (WebSocket fanout) for tenant ${TENANT_SLUG}.

app = "aisoc-${TENANT_SLUG}-realtime"
primary_region = "${REGION}"

[env]
  PORT = "4000"
  NODE_ENV = "production"
  AISOC_TENANT_SLUG = "${TENANT_SLUG}"
  ALLOWED_ORIGINS = "https://${BASE_DOMAIN},https://api.${BASE_DOMAIN}"

[http_service]
  internal_port       = 4000
  force_https         = true
  # WebSockets must never be auto-stopped: a stopped machine 502s the
  # browser's existing socket because Fly's request-driven auto-start
  # hook only fires on HTTP requests, not on WS frames.
  auto_stop_machines  = "off"
  auto_start_machines = true
  min_machines_running = ${REALTIME_MIN_MACHINES}
  processes           = ["app"]

  [[http_service.checks]]
    grace_period = "20s"
    interval     = "15s"
    method       = "GET"
    timeout      = "5s"
    path         = "/healthz"

[[vm]]
  size      = "shared-cpu-1x"
  memory_mb = 512
