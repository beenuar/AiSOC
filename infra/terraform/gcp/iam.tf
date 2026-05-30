/**
 * AiSOC — GCP serverless skeleton
 *
 * Per-service runtime identities. Cloud Run services run as dedicated SAs so
 * IAM bindings stay scoped to one service at a time. The compute default SA
 * is intentionally not used.
 */

# ─── Service accounts ───────────────────────────────────────────────────────

resource "google_service_account" "api" {
  account_id   = "${var.name_prefix}-api"
  display_name = "AiSOC API runtime"
  description  = "Runtime identity for the AiSOC FastAPI Cloud Run service."
}

resource "google_service_account" "web" {
  account_id   = "${var.name_prefix}-web"
  display_name = "AiSOC web runtime"
  description  = "Runtime identity for the AiSOC Next.js Cloud Run service."
}

resource "google_service_account" "ingest" {
  account_id   = "${var.name_prefix}-ingest"
  display_name = "AiSOC ingest runtime"
  description  = "Runtime identity for the AiSOC ingest Cloud Run service."
}

# ─── Common bindings ─────────────────────────────────────────────────────────
#
# Every runtime SA needs to:
#   - pull images from Artifact Registry
#   - read/write logs and metrics
#   - connect to Cloud SQL via the connector

locals {
  runtime_service_accounts = {
    api    = google_service_account.api.email
    web    = google_service_account.web.email
    ingest = google_service_account.ingest.email
  }

  # role => description (kept inline for readability)
  shared_runtime_roles = [
    "roles/artifactregistry.reader",
    "roles/cloudsql.client",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudtrace.agent",
  ]

  # Flatten {sa, role} pairs for for_each.
  runtime_role_bindings = {
    for pair in setproduct(keys(local.runtime_service_accounts), local.shared_runtime_roles) :
    "${pair[0]}-${replace(pair[1], "/", "_")}" => {
      service_account = local.runtime_service_accounts[pair[0]]
      role            = pair[1]
    }
  }
}

resource "google_project_iam_member" "runtime_shared" {
  for_each = local.runtime_role_bindings

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${each.value.service_account}"
}

# ─── Secret Manager access ───────────────────────────────────────────────────
#
# Only API and ingest read secrets at runtime. The web service is a Next.js
# bundle that talks to the API over HTTP — it doesn't need DB or vault keys.

locals {
  api_secrets = concat(
    [
      google_secret_manager_secret.postgres_password.id,
      google_secret_manager_secret.secret_key.id,
      google_secret_manager_secret.credential_key.id,
      google_secret_manager_secret.redis_auth.id,
    ],
    google_secret_manager_secret.openai_api_key[*].id,
  )

  ingest_secrets = [
    google_secret_manager_secret.postgres_password.id,
    google_secret_manager_secret.secret_key.id,
    google_secret_manager_secret.redis_auth.id,
  ]
}

resource "google_secret_manager_secret_iam_member" "api" {
  for_each = toset(local.api_secrets)

  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.api.email}"
}

resource "google_secret_manager_secret_iam_member" "ingest" {
  for_each = toset(local.ingest_secrets)

  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.ingest.email}"
}

# ─── Public invoker bindings ─────────────────────────────────────────────────
#
# Optional. When var.allow_unauthenticated is true (the default for a demo
# stack), Cloud Run services are reachable from the public internet. Flip the
# variable to false for a private deployment fronted by IAP or Cloud Load
# Balancer.

resource "google_cloud_run_v2_service_iam_member" "api_invoker" {
  count = var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "web_invoker" {
  count = var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.web.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "ingest_invoker" {
  count = var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.ingest.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
