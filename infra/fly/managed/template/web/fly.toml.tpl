# Generated from infra/fly/managed/template/web/fly.toml.tpl
# DO NOT EDIT — regenerate via `./infra/fly/managed/render.sh <tenant.yaml>`.
#
# Managed-mode AiSOC web console (Next.js) for tenant ${TENANT_SLUG}.

app = "aisoc-${TENANT_SLUG}-web"
primary_region = "${REGION}"

[build]
  dockerfile = "apps/web/Dockerfile"
  [build.args]
    NEXT_PUBLIC_API_URL = "https://api.${BASE_DOMAIN}"
    NEXT_PUBLIC_WS_URL  = "wss://ws.${BASE_DOMAIN}"
    NEXT_PUBLIC_TENANT_SLUG = "${TENANT_SLUG}"
    NEXT_PUBLIC_TENANT_DISPLAY_NAME = "${TENANT_DISPLAY_NAME}"

[env]
  PORT = "3000"
  NEXT_TELEMETRY_DISABLED = "1"
  AISOC_TENANT_SLUG = "${TENANT_SLUG}"

[http_service]
  internal_port       = 3000
  force_https         = true
  auto_stop_machines  = "stop"
  auto_start_machines = true
  min_machines_running = 0
  processes           = ["app"]

  [[http_service.checks]]
    grace_period = "30s"
    interval     = "15s"
    method       = "GET"
    timeout      = "5s"
    path         = "/api/healthz"

[[vm]]
  size      = "shared-cpu-1x"
  memory_mb = 1024
