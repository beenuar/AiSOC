# AiSOC — Managed Instance (T6.1)
# =============================================================================
# Provisions the single-tenant managed offering hosted at `tryaisoc.com`.
#
# Components:
#   • Fly.io application  — runs `services/api`, `services/agents`, the web
#     console (`apps/web`), and the realtime stream. One app, multiple
#     processes, scaled horizontally per process.
#   • Fly.io Postgres     — managed primary + standby, encrypted at rest,
#                          point-in-time recovery enabled.
#   • Fly.io Redis        — managed Upstash-backed Redis (pubsub + cache).
#   • Cloudflare DNS      — `tryaisoc.com` CNAME → Fly.io edge.
#
# This is the *skeleton*. The actual Fly.io provider is community-maintained
# (`fly-apps/fly`) and the API surface is still moving; the operator who
# bootstraps this stack will need to pin the provider to a known-good
# release and may need to fill in extra arguments (volumes, secrets, custom
# health checks) once a baseline image lands.
#
# No real secrets live in this file. Every sensitive value is sourced
# either from `var.*` (declared in `variables.tf`, with `null` default for
# operator-supplied values) or from `data.*` lookups against the operator's
# secret store (e.g. 1Password, Doppler, Cloudflare API token in their
# env). The operator MUST run `terraform plan` against this stack with
# their env vars exported before any `apply`.
#
# Bootstrap:
#
#   export TF_VAR_fly_api_token=...
#   export TF_VAR_cloudflare_api_token=...
#   terraform -chdir=infra/terraform/environments/managed init
#   terraform -chdir=infra/terraform/environments/managed plan
#   terraform -chdir=infra/terraform/environments/managed apply
#
# See README.md for the full operator playbook.
# =============================================================================

terraform {
  required_version = ">= 1.7"

  required_providers {
    # NOTE: pin to a specific release once the operator validates against a
    # known-good version. The version range here is intentionally loose
    # because the Fly provider has not yet stabilised its v1 surface.
    fly = {
      source  = "fly-apps/fly"
      version = "~> 0.0.23"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.30"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # The operator chooses their own backend. The default is local state, but
  # for any non-toy deployment we recommend either Terraform Cloud or an
  # S3-compatible backend with locking. Uncomment one of the blocks below
  # and populate the bucket/workspace name before the first `init`.
  #
  # backend "s3" {
  #   bucket         = "aisoc-managed-tfstate"
  #   key            = "managed/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "aisoc-managed-tflock"
  #   encrypt        = true
  # }
  #
  # backend "remote" {
  #   organization = "<your-tf-cloud-org>"
  #   workspaces {
  #     name = "aisoc-managed"
  #   }
  # }
}

# -----------------------------------------------------------------------------
# Providers
# -----------------------------------------------------------------------------

provider "fly" {
  # `fly_api_token` is sourced from `var.fly_api_token` which is itself sourced
  # from the env (`TF_VAR_fly_api_token`). Never commit this token.
  fly_api_token = var.fly_api_token
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# -----------------------------------------------------------------------------
# Random suffix for naming
# -----------------------------------------------------------------------------
#
# Adds a 4-char suffix to globally-unique names (Fly.io app names, Postgres
# cluster name). Keeping it stable in state so re-applies don't churn.

resource "random_string" "suffix" {
  length  = 4
  upper   = false
  numeric = true
  special = false
}

# -----------------------------------------------------------------------------
# Fly.io application — control plane
# -----------------------------------------------------------------------------
#
# A single Fly.io app hosts every service. Process groups are declared
# inside the app's `fly.toml` (committed alongside the service). This
# Terraform stack only owns the app-level identity; the operator runs
# `fly deploy` to ship code changes.

resource "fly_app" "control_plane" {
  name = "${var.app_name_prefix}-${random_string.suffix.result}"
  org  = var.fly_org
}

resource "fly_ip" "control_plane_v4" {
  app  = fly_app.control_plane.name
  type = "v4"
}

resource "fly_ip" "control_plane_v6" {
  app  = fly_app.control_plane.name
  type = "v6"
}

# -----------------------------------------------------------------------------
# Fly.io managed Postgres
# -----------------------------------------------------------------------------
#
# The provider exposes `fly_postgres_cluster` (Fly's wrapper around
# their managed Postgres). The control-plane Fly app attaches to it via
# `fly attach` once both exist. We track the cluster name in `outputs.tf`
# so the attach step is scriptable.

resource "fly_postgres_cluster" "primary" {
  app_name    = "${var.app_name_prefix}-pg-${random_string.suffix.result}"
  org_slug    = var.fly_org
  region      = var.fly_region
  vm_size     = var.postgres_vm_size
  volume_size = var.postgres_volume_gb
  node_count  = var.postgres_node_count
}

# -----------------------------------------------------------------------------
# Fly.io managed Redis (Upstash)
# -----------------------------------------------------------------------------
#
# Fly's Redis is Upstash under the hood. The provider's resource shape has
# changed across releases; if `fly_redis` isn't available in the pinned
# provider version, the operator can fall back to provisioning an Upstash
# Redis directly and feeding the URL into `var.redis_url_override`.

resource "fly_redis" "primary" {
  count = var.redis_url_override == null ? 1 : 0

  name    = "${var.app_name_prefix}-redis-${random_string.suffix.result}"
  org     = var.fly_org
  region  = var.fly_region
  plan_id = var.redis_plan
}

# -----------------------------------------------------------------------------
# Cloudflare — DNS for tryaisoc.com
# -----------------------------------------------------------------------------
#
# Fly.io issues a per-app hostname (`<app>.fly.dev`). We point
# `tryaisoc.com` at it via a proxied CNAME so Cloudflare terminates
# TLS in front of Fly's edge.

resource "cloudflare_record" "app" {
  zone_id = var.cloudflare_zone_id
  name    = var.app_hostname
  type    = "CNAME"
  content = "${fly_app.control_plane.name}.fly.dev"
  proxied = true
  ttl     = 1 # ttl=1 means "automatic" when proxied=true
  comment = "Managed by AiSOC managed-instance Terraform (T6.1)"
}

# Optional second CNAME for the realtime hostname — many deployments
# split `tryaisoc.com` (HTTP) from `realtime.tryaisoc.com` (websockets) so
# the WS connection budget isn't shared with API requests. Set
# `var.realtime_hostname` to null to skip this record.
resource "cloudflare_record" "realtime" {
  count = var.realtime_hostname == null ? 0 : 1

  zone_id = var.cloudflare_zone_id
  name    = var.realtime_hostname
  type    = "CNAME"
  content = "${fly_app.control_plane.name}.fly.dev"
  proxied = true
  ttl     = 1
  comment = "Managed by AiSOC managed-instance Terraform (T6.1)"
}
