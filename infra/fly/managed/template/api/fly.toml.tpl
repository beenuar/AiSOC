# Generated from infra/fly/managed/template/api/fly.toml.tpl
# DO NOT EDIT — regenerate via `./infra/fly/managed/render.sh <tenant.yaml>`.
#
# Managed-mode AiSOC API (FastAPI) for tenant ${TENANT_SLUG}.

app = "aisoc-${TENANT_SLUG}-api"
primary_region = "${REGION}"
kill_signal    = "SIGINT"
kill_timeout   = "5s"

[deploy]
  release_command = "/bin/sh -c 'python -m app.scripts.run_migrations && python -m app.scripts.provision_tenant'"

[env]
  ENVIRONMENT      = "managed"
  LOG_LEVEL        = "info"
  PORT             = "8000"
  # Managed mode is multi-tenant in code, but each Fly stack hosts exactly
  # one customer org. We tag every request with the canonical tenant slug
  # so cross-stack telemetry stays attributable.
  AISOC_TENANT_SLUG = "${TENANT_SLUG}"
  AISOC_DISPLAY_NAME = "${TENANT_DISPLAY_NAME}"
  # Inter-service URLs over Fly's internal 6PN DNS.
  CORE_API_URL   = "http://localhost:8000"
  AGENTS_API_URL = "http://aisoc-${TENANT_SLUG}-agents.internal:8084"
  REALTIME_BASE_URL = "http://aisoc-${TENANT_SLUG}-realtime.internal:4000"
  CORS_ORIGINS   = "https://${BASE_DOMAIN},https://api.${BASE_DOMAIN},https://ws.${BASE_DOMAIN}"
  PASSKEY_RP_ID      = "${BASE_DOMAIN}"
  PASSKEY_RP_NAME    = "${TENANT_DISPLAY_NAME}"
  PASSKEY_RP_ORIGINS = "https://${BASE_DOMAIN}"
  # All optional integrations are enabled by default in managed mode (the
  # operator can flip them off via a per-app `flyctl secrets set
  # AISOC_DISABLE_<X>=true` after provision).

[http_service]
  internal_port       = 8000
  force_https         = true
  auto_stop_machines  = "off"
  auto_start_machines = true
  min_machines_running = 1
  processes           = ["app"]

  [[http_service.checks]]
    grace_period = "20s"
    interval     = "15s"
    method       = "GET"
    timeout      = "5s"
    path         = "/readyz"

[[vm]]
  size      = "${API_VM_SIZE}"
  memory_mb = 1024
