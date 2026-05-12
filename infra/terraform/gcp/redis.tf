/**
 * AiSOC — GCP serverless skeleton
 *
 * Memorystore for Redis, private to the VPC. Used for Celery / queue
 * coordination, FastAPI rate limiting, and websocket fan-out.
 */

resource "google_redis_instance" "main" {
  name           = "${var.name_prefix}-redis"
  tier           = var.redis_tier
  memory_size_gb = var.redis_memory_size_gb
  region         = var.region

  authorized_network      = google_compute_network.vpc.id
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  redis_version           = var.redis_version
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled            = true

  labels = var.labels

  depends_on = [google_service_networking_connection.private_service]
}
