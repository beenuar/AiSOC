/**
 * AiSOC — GCP serverless skeleton
 *
 * Cloud Run v2 services for the three customer-visible workloads:
 *
 *   - api    — FastAPI control plane
 *   - web    — Next.js console
 *   - ingest — Go fan-in service that accepts /v1/ingest/batch
 *
 * Long-running workloads (agents, alert-fusion, realtime, threatintel,
 * connectors, fusion, ocsf) intentionally aren't on Cloud Run — they belong
 * on a managed instance group or GKE Autopilot in a follow-up plan because
 * Cloud Run's request lifecycle doesn't fit websocket fan-out or scheduler
 * loops. The skeleton here ships the surface that customers see first.
 */

# ─── Shared env / wiring ─────────────────────────────────────────────────────

locals {
  # Cloud SQL connection name format: project:region:instance.
  sql_connection_name = google_sql_database_instance.main.connection_name

  # We construct DATABASE_URL from the per-service env injection rather than
  # storing the whole URL in Secret Manager so the password rotates cleanly
  # via random_password.postgres_user without rewriting the URL.
  database_url_template = "postgresql+asyncpg://${var.postgres_user}:%s@/%s?host=/cloudsql/${local.sql_connection_name}"

  # Memorystore exposes a private IP; the auth string is held in Secret Manager.
  redis_host = google_redis_instance.main.host
  redis_port = google_redis_instance.main.port
}

# ─── API ─────────────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "api" {
  name     = "${var.name_prefix}-api"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  labels   = var.labels

  template {
    service_account = google_service_account.api.email

    scaling {
      min_instance_count = var.api_min_instances
      max_instance_count = var.api_max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [local.sql_connection_name]
      }
    }

    containers {
      image = var.api_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "1Gi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      # ── Static config ──────────────────────────────────────────────────────
      env {
        name  = "AISOC_DEPLOYMENT"
        value = "gcp-cloudrun"
      }
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db_name
      }
      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_HOST"
        value = "/cloudsql/${local.sql_connection_name}"
      }
      env {
        name  = "REDIS_HOST"
        value = local.redis_host
      }
      env {
        name  = "REDIS_PORT"
        value = tostring(local.redis_port)
      }
      env {
        name  = "CORS_ORIGINS"
        value = var.cors_origins
      }

      # ── Secret-backed env ──────────────────────────────────────────────────
      env {
        name = "POSTGRES_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.postgres_password.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AISOC_CREDENTIAL_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.credential_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "REDIS_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_auth.secret_id
            version = "latest"
          }
        }
      }

      dynamic "env" {
        for_each = var.openai_api_key == "" ? [] : [1]
        content {
          name = "OPENAI_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.openai_api_key[0].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.enabled,
    google_secret_manager_secret_iam_member.api,
    google_sql_user.aisoc,
  ]
}

# ─── Web ─────────────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "web" {
  name     = "${var.name_prefix}-web"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  labels   = var.labels

  template {
    service_account = google_service_account.web.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.web_max_instances
    }

    containers {
      image = var.web_image

      ports {
        container_port = 3000
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "AISOC_DEPLOYMENT"
        value = "gcp-cloudrun"
      }
      env {
        name  = "NEXT_PUBLIC_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }
      env {
        name  = "NODE_ENV"
        value = "production"
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [google_project_service.enabled]
}

# ─── Ingest ──────────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "ingest" {
  name     = "${var.name_prefix}-ingest"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  labels   = var.labels

  template {
    service_account = google_service_account.ingest.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.ingest_max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [local.sql_connection_name]
      }
    }

    containers {
      image = var.ingest_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "AISOC_DEPLOYMENT"
        value = "gcp-cloudrun"
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db_name
      }
      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_HOST"
        value = "/cloudsql/${local.sql_connection_name}"
      }
      env {
        name  = "REDIS_HOST"
        value = local.redis_host
      }
      env {
        name  = "REDIS_PORT"
        value = tostring(local.redis_port)
      }

      env {
        name = "POSTGRES_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.postgres_password.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "REDIS_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_auth.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.enabled,
    google_secret_manager_secret_iam_member.ingest,
    google_sql_user.aisoc,
  ]
}
