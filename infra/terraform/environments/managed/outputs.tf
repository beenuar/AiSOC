# AiSOC — Managed Instance Outputs (T6.1)
# =============================================================================
# Everything an operator needs to wire the managed instance into the rest of
# the AiSOC ecosystem after a successful `terraform apply`:
#
#   • App identity and Fly hostname for `fly deploy`.
#   • Postgres + Redis connection metadata so the operator can pipe them
#     into `fly secrets set` (we don't materialise the secrets in state).
#   • Public hostname + Cloudflare record id for downstream automation
#     (status pages, monitoring, certificate-aware health checks).
#
# Sensitive outputs are marked `sensitive = true` so they don't leak into
# CI logs by accident. The operator can read them with
# `terraform output -raw <name>`.
# =============================================================================

# -----------------------------------------------------------------------------
# Application
# -----------------------------------------------------------------------------

output "fly_app_name" {
  description = "The provisioned Fly.io app name. Use this with `fly deploy --app <name>`."
  value       = fly_app.control_plane.name
}

output "fly_app_hostname" {
  description = "Fly-issued hostname for the app (target of the Cloudflare CNAME)."
  value       = "${fly_app.control_plane.name}.fly.dev"
}

output "fly_app_ipv4" {
  description = "The dedicated IPv4 attached to the Fly app."
  value       = fly_ip.control_plane_v4.address
}

output "fly_app_ipv6" {
  description = "The dedicated IPv6 attached to the Fly app."
  value       = fly_ip.control_plane_v6.address
}

# -----------------------------------------------------------------------------
# Postgres
# -----------------------------------------------------------------------------

output "postgres_app_name" {
  description = "Fly app name backing the Postgres cluster. Run `fly attach <name>` from the control plane to bind it."
  value       = fly_postgres_cluster.primary.app_name
}

output "postgres_region" {
  description = "Fly region the Postgres primary lives in."
  value       = fly_postgres_cluster.primary.region
}

# -----------------------------------------------------------------------------
# Redis
# -----------------------------------------------------------------------------

output "redis_app_name" {
  description = "Fly app name for the Redis instance, or `null` if `redis_url_override` was supplied."
  value       = length(fly_redis.primary) > 0 ? fly_redis.primary[0].name : null
}

output "redis_url" {
  description = <<-EOT
    The Redis connection URL the control plane should consume. Pipe this
    into `fly secrets set REDIS_URL=...` rather than committing it.
  EOT
  value = (
    var.redis_url_override != null
    ? var.redis_url_override
    : (length(fly_redis.primary) > 0 ? fly_redis.primary[0].private_url : null)
  )
  sensitive = true
}

# -----------------------------------------------------------------------------
# DNS
# -----------------------------------------------------------------------------

output "public_app_url" {
  description = "Public HTTPS URL of the managed instance — what customers see."
  value       = "https://${var.app_hostname}"
}

output "cloudflare_record_id" {
  description = "Cloudflare record id for the app hostname. Useful for downstream automation."
  value       = cloudflare_record.app.id
}

# -----------------------------------------------------------------------------
# Wire-up checklist (for operators)
# -----------------------------------------------------------------------------
#
# A non-resource output that documents the post-apply checklist inline.
# `terraform output bootstrap_checklist` prints a human-readable summary.

output "bootstrap_checklist" {
  description = "Operator checklist printed after a successful apply."
  value       = <<-EOT
    AiSOC managed instance provisioned. Next steps:

      1. Attach Postgres to the control plane:
           fly attach -a ${fly_app.control_plane.name} ${fly_postgres_cluster.primary.app_name}

      2. Set the AiSOC credential-vault key (Fernet, 32 bytes urlsafe-b64):
           fly secrets set AISOC_CREDENTIAL_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())') -a ${fly_app.control_plane.name}

      3. Set the Slack sales-channel webhook used by /v1/waitlist/signup:
           fly secrets set AISOC_WAITLIST_SLACK_WEBHOOK=<your webhook> -a ${fly_app.control_plane.name}

      4. Set the shared realtime WS/SSE ticket secret (Issue #239). The API
         mints short-TTL tickets and the realtime process group verifies them,
         so both must read the SAME value. Generate one 32-byte secret and set
         it once — Fly fans it out to every process group in the app:
           fly secrets set AISOC_REALTIME_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))') -a ${fly_app.control_plane.name}

      5. Deploy the AiSOC images:
           fly deploy --app ${fly_app.control_plane.name}

      6. Verify the public URL responds:
           curl -sSf https://${var.app_hostname}/health

    The Redis URL is exposed as a `sensitive` output — surface it with
    `terraform output -raw redis_url` and feed it into `fly secrets set
    REDIS_URL=...` rather than committing it anywhere.
  EOT
}
