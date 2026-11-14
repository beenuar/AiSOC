/**
 * AiSOC — GCP serverless skeleton
 *
 * Secret Manager entries that Cloud Run mounts as environment variables.
 *
 * The runtime SAs are granted secretAccessor in iam.tf so we don't have to
 * inline that role here.
 */

# ─── Generated secrets ───────────────────────────────────────────────────────
# These never appear in tfvars or state diffs; they are produced by random_*
# resources and only their secret IDs cross the trust boundary.

resource "random_password" "secret_key" {
  length  = 64
  special = false
}

resource "random_password" "credential_key" {
  # CredentialVault uses Fernet which expects a 32-byte url-safe base64 key.
  # 32 random bytes -> base64 is a valid Fernet key; we generate it here so a
  # `terraform destroy` followed by `terraform apply` rotates the vault key
  # cleanly. Operators who need rotation-without-rewrap should set this via
  # AISOC_CREDENTIAL_KEY_ROTATION_FROM in app config.
  length      = 32
  special     = false
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
}

resource "random_password" "realtime_jwt_secret" {
  # Shared HS256 secret for short-lived realtime WS/SSE tickets (Issue #239).
  # The API mints tickets at POST /api/v1/realtime/ticket; the Node realtime
  # service verifies them on every upgrade. Kept separate from secret_key so the
  # realtime edge rotates independently and a leaked ticket can't forge a full
  # API session.
  length  = 64
  special = false
}

# ─── Secret Manager secrets ──────────────────────────────────────────────────

resource "google_secret_manager_secret" "postgres_password" {
  secret_id = "${var.name_prefix}-postgres-password"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "postgres_password" {
  secret      = google_secret_manager_secret.postgres_password.id
  secret_data = random_password.postgres_user.result
}

resource "google_secret_manager_secret" "secret_key" {
  secret_id = "${var.name_prefix}-secret-key"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "secret_key" {
  secret      = google_secret_manager_secret.secret_key.id
  secret_data = random_password.secret_key.result
}

resource "google_secret_manager_secret" "credential_key" {
  secret_id = "${var.name_prefix}-credential-key"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "credential_key" {
  secret      = google_secret_manager_secret.credential_key.id
  secret_data = base64encode(random_password.credential_key.result)
}

resource "google_secret_manager_secret" "realtime_jwt_secret" {
  secret_id = "${var.name_prefix}-realtime-jwt-secret"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "realtime_jwt_secret" {
  secret      = google_secret_manager_secret.realtime_jwt_secret.id
  secret_data = random_password.realtime_jwt_secret.result
}

resource "google_secret_manager_secret" "redis_auth" {
  secret_id = "${var.name_prefix}-redis-auth"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "redis_auth" {
  secret      = google_secret_manager_secret.redis_auth.id
  secret_data = google_redis_instance.main.auth_string
}

# ─── Optional: OpenAI key ────────────────────────────────────────────────────
# Only created when var.openai_api_key is non-empty so an air-gapped install
# (Ollama / LiteLLM overlay) doesn't have to invent a placeholder secret.

resource "google_secret_manager_secret" "openai_api_key" {
  count = var.openai_api_key == "" ? 0 : 1

  secret_id = "${var.name_prefix}-openai-api-key"
  labels    = var.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "openai_api_key" {
  count = var.openai_api_key == "" ? 0 : 1

  secret      = google_secret_manager_secret.openai_api_key[0].id
  secret_data = var.openai_api_key
}
