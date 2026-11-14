# AiSOC — Managed Instance Variables (T6.1)
# =============================================================================
# Every sensitive value is declared with `sensitive = true` and a `null`
# default so Terraform fails fast (`required value not provided`) if the
# operator forgets to export the matching `TF_VAR_*` env var.
#
# Naming rules (also documented in README.md):
#   • Fly.io app names are globally unique. The actual name is
#     `${app_name_prefix}-${random_suffix}` so the operator only needs
#     to pick the prefix.
#   • Hostnames must already have a Cloudflare zone configured.
#   • Region must be a Fly.io region code (e.g. `iad`, `lhr`, `sin`).
# =============================================================================

# -----------------------------------------------------------------------------
# Secrets — must be provided via TF_VAR_* env vars. Never commit.
# -----------------------------------------------------------------------------

variable "fly_api_token" {
  description = <<-EOT
    Fly.io API token with permissions to create apps + Postgres + Redis.
    Generate one with `fly auth token` and export it as
    `TF_VAR_fly_api_token` before running terraform.
  EOT
  type        = string
  sensitive   = true
  default     = null
}

variable "cloudflare_api_token" {
  description = <<-EOT
    Cloudflare API token with `Zone.DNS.Edit` permission on the zone
    that hosts `tryaisoc.com`. Export as `TF_VAR_cloudflare_api_token`.
  EOT
  type        = string
  sensitive   = true
  default     = null
}

variable "cloudflare_zone_id" {
  description = <<-EOT
    Cloudflare zone ID for the apex domain (e.g. `tryaisoc.com`). Find it
    on the Cloudflare dashboard → Overview → API → Zone ID.
  EOT
  type        = string
  default     = null
}

# -----------------------------------------------------------------------------
# Fly.io — application
# -----------------------------------------------------------------------------

variable "fly_org" {
  description = "Fly.io organisation slug that owns the managed deployment."
  type        = string
  default     = "aisoc"
}

variable "fly_region" {
  description = <<-EOT
    Primary Fly.io region (3-letter region code, see
    https://fly.io/docs/reference/regions/). Postgres + Redis primaries
    are pinned here; additional read replicas can be added later via the
    `fly volumes` / `fly postgres` CLIs.
  EOT
  type        = string
  default     = "iad"
}

variable "app_name_prefix" {
  description = <<-EOT
    Prefix for every Fly.io resource name created by this stack. A random
    4-char suffix is appended to avoid collisions when the same prefix is
    reused (e.g. spinning up a staging environment alongside production).
  EOT
  type        = string
  default     = "aisoc-managed"

  validation {
    # Fly.io requires app names to match `[a-z][a-z0-9-]{0,29}`. We
    # leave room for the random suffix (`-xxxx`, 5 chars).
    condition     = can(regex("^[a-z][a-z0-9-]{0,24}$", var.app_name_prefix))
    error_message = "app_name_prefix must be lowercase alphanumeric/hyphen, start with a letter, ≤25 chars."
  }
}

# -----------------------------------------------------------------------------
# Postgres
# -----------------------------------------------------------------------------

variable "postgres_vm_size" {
  description = "Fly Postgres VM preset. Sizes: `shared-cpu-1x`, `shared-cpu-2x`, `dedicated-cpu-2x`, etc."
  type        = string
  default     = "shared-cpu-2x"
}

variable "postgres_volume_gb" {
  description = "Per-node Postgres data volume size, in GiB."
  type        = number
  default     = 50

  validation {
    condition     = var.postgres_volume_gb >= 10 && var.postgres_volume_gb <= 500
    error_message = "postgres_volume_gb must be between 10 and 500."
  }
}

variable "postgres_node_count" {
  description = <<-EOT
    Number of Postgres nodes (1 = single-node, 2 = primary + standby,
    3+ = HA cluster with witness). For the managed beta we recommend 2
    so PITR + failover work without a witness node.
  EOT
  type        = number
  default     = 2

  validation {
    condition     = var.postgres_node_count >= 1 && var.postgres_node_count <= 5
    error_message = "postgres_node_count must be between 1 and 5."
  }
}

# -----------------------------------------------------------------------------
# Redis
# -----------------------------------------------------------------------------

variable "redis_plan" {
  description = "Fly/Upstash Redis plan id. `free` is enough for the beta cohort."
  type        = string
  default     = "free"
}

variable "redis_url_override" {
  description = <<-EOT
    If set, the stack will NOT provision a Fly-managed Redis and instead
    leaves the URL pass-through for the operator to consume in `fly secrets`.
    Use this when the operator wants to point at an external Redis
    (e.g. a self-hosted Upstash, ElastiCache, or DragonflyDB instance).
  EOT
  type        = string
  sensitive   = true
  default     = null
}

# -----------------------------------------------------------------------------
# DNS
# -----------------------------------------------------------------------------

variable "app_hostname" {
  description = "Public hostname for the console + API (e.g. `tryaisoc.com`)."
  type        = string
  default     = "tryaisoc.com"
}

variable "realtime_hostname" {
  description = <<-EOT
    Optional public hostname for the websocket / realtime stream
    (e.g. `realtime.tryaisoc.com`). Set to `null` to share the main
    hostname for WS traffic.
  EOT
  type        = string
  default     = "realtime.tryaisoc.com"
}
