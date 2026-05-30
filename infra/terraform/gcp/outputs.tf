/**
 * AiSOC — GCP serverless skeleton
 *
 * Outputs are scoped to what an operator needs immediately after
 * `terraform apply`: the public service URLs, the connection strings the API
 * will dial, and the IDs needed by the matching CI workflow that pushes
 * container images.
 */

# ─── Cloud Run URLs ──────────────────────────────────────────────────────────

output "api_url" {
  description = "Public Cloud Run URL for the AiSOC API."
  value       = google_cloud_run_v2_service.api.uri
}

output "web_url" {
  description = "Public Cloud Run URL for the AiSOC web console."
  value       = google_cloud_run_v2_service.web.uri
}

output "ingest_url" {
  description = "Public Cloud Run URL for the AiSOC ingest endpoint."
  value       = google_cloud_run_v2_service.ingest.uri
}

# ─── Cloud SQL ───────────────────────────────────────────────────────────────

output "sql_instance_name" {
  description = "Cloud SQL instance name (use with gcloud sql connect)."
  value       = google_sql_database_instance.main.name
}

output "sql_connection_name" {
  description = "Cloud SQL connection name (project:region:instance) for the Cloud SQL Auth Proxy."
  value       = google_sql_database_instance.main.connection_name
}

output "sql_private_ip" {
  description = "Private IP of the Cloud SQL instance."
  value       = google_sql_database_instance.main.private_ip_address
}

output "sql_database" {
  description = "Application database name inside the Cloud SQL instance."
  value       = google_sql_database.aisoc.name
}

# ─── Memorystore ─────────────────────────────────────────────────────────────

output "redis_host" {
  description = "Private IP of the Memorystore Redis instance."
  value       = google_redis_instance.main.host
}

output "redis_port" {
  description = "Port of the Memorystore Redis instance."
  value       = google_redis_instance.main.port
}

# ─── Artifact Registry ───────────────────────────────────────────────────────

output "artifact_registry_repo" {
  description = "Fully-qualified Artifact Registry repo (region-docker.pkg.dev/project/repo) for CI image pushes."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.containers.repository_id}"
}

# ─── Service accounts ────────────────────────────────────────────────────────

output "service_account_api" {
  description = "Email of the API runtime service account."
  value       = google_service_account.api.email
}

output "service_account_web" {
  description = "Email of the web runtime service account."
  value       = google_service_account.web.email
}

output "service_account_ingest" {
  description = "Email of the ingest runtime service account."
  value       = google_service_account.ingest.email
}

# ─── Secret IDs ──────────────────────────────────────────────────────────────
#
# These are the resource IDs (not the secret values). Useful for ad-hoc
# `gcloud secrets versions access latest --secret=<id>` after apply.

output "secret_postgres_password_id" {
  description = "Secret Manager ID for the Postgres application password."
  value       = google_secret_manager_secret.postgres_password.secret_id
}

output "secret_secret_key_id" {
  description = "Secret Manager ID for the AiSOC SECRET_KEY."
  value       = google_secret_manager_secret.secret_key.secret_id
}

output "secret_credential_key_id" {
  description = "Secret Manager ID for the CredentialVault Fernet key."
  value       = google_secret_manager_secret.credential_key.secret_id
}

output "secret_redis_auth_id" {
  description = "Secret Manager ID for the Memorystore Redis auth string."
  value       = google_secret_manager_secret.redis_auth.secret_id
}

output "secret_openai_api_key_id" {
  description = "Secret Manager ID for the OpenAI API key (null when not provisioned)."
  value = nonsensitive(
    length(google_secret_manager_secret.openai_api_key) == 0
    ? null
    : google_secret_manager_secret.openai_api_key[0].secret_id
  )
}
