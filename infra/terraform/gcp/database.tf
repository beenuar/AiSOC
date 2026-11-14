/**
 * AiSOC — GCP serverless skeleton
 *
 * Cloud SQL for Postgres, private-IP only, peered to the VPC defined in
 * main.tf. The application user password is randomly generated and stored
 * in Secret Manager (see secrets.tf) so it never lands in tfvars.
 */

resource "random_password" "postgres_user" {
  length           = 32
  special          = true
  override_special = "!@#%^&*()-_=+[]{}<>"
}

resource "google_sql_database_instance" "main" {
  name                = "${var.name_prefix}-pg"
  database_version    = var.postgres_version
  region              = var.region
  deletion_protection = var.deletion_protection

  depends_on = [google_service_networking_connection.private_service]

  settings {
    tier              = var.postgres_tier
    availability_type = var.redis_tier == "STANDARD_HA" ? "REGIONAL" : "ZONAL"
    disk_size         = var.postgres_disk_size_gb
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    user_labels = var.labels

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = false
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }
  }
}

resource "google_sql_database" "aisoc" {
  name     = var.postgres_db_name
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "aisoc" {
  name     = var.postgres_user
  instance = google_sql_database_instance.main.name
  password = random_password.postgres_user.result
}
