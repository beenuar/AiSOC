/**
 * AiSOC — GCP serverless skeleton
 *
 * Input variables. Defaults aim for "smallest viable AiSOC" so a `terraform
 * apply` against a fresh project produces a working stack inside the GCP
 * always-free / startup-credit envelope, not a five-figure surprise.
 */

# ─── Project / region ────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID that will own every resource in this stack."
  type        = string
}

variable "region" {
  description = "Primary GCP region for Cloud Run, Cloud SQL, and Memorystore."
  type        = string
  default     = "us-central1"
}

variable "name_prefix" {
  description = "Prefix used for resource names (Cloud Run services, SQL instance, etc.)."
  type        = string
  default     = "aisoc"
}

variable "labels" {
  description = "Common labels applied to every label-supporting resource."
  type        = map(string)
  default = {
    project    = "aisoc"
    managed_by = "terraform"
  }
}

# ─── Networking ──────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "Primary subnet CIDR for the Cloud Run egress / Cloud SQL VPC."
  type        = string
  default     = "10.20.0.0/24"
}

variable "vpc_connector_cidr" {
  description = "/28 CIDR carved out for the Serverless VPC Access connector."
  type        = string
  default     = "10.20.1.0/28"
}

# ─── Cloud SQL (Postgres) ────────────────────────────────────────────────────

variable "postgres_tier" {
  description = "Cloud SQL machine tier. db-f1-micro is the cheapest dev tier; use db-custom-* for prod."
  type        = string
  default     = "db-custom-2-7680"
}

variable "postgres_version" {
  description = "Cloud SQL Postgres version."
  type        = string
  default     = "POSTGRES_16"
}

variable "postgres_disk_size_gb" {
  description = "Initial Cloud SQL disk size in GB. Auto-resize is enabled regardless."
  type        = number
  default     = 20
}

variable "postgres_db_name" {
  description = "Logical Postgres database name created inside the instance."
  type        = string
  default     = "aisoc"
}

variable "postgres_user" {
  description = "Application Postgres user."
  type        = string
  default     = "aisoc"
}

variable "deletion_protection" {
  description = "When true, prevents `terraform destroy` from deleting Cloud SQL. Set false for dev."
  type        = bool
  default     = true
}

# ─── Memorystore (Redis) ─────────────────────────────────────────────────────

variable "redis_tier" {
  description = "Memorystore tier — BASIC for dev (no HA), STANDARD_HA for prod."
  type        = string
  default     = "BASIC"
}

variable "redis_memory_size_gb" {
  description = "Memorystore memory size in GB."
  type        = number
  default     = 1
}

variable "redis_version" {
  description = "Memorystore Redis version."
  type        = string
  default     = "REDIS_7_2"
}

# ─── Cloud Run services ──────────────────────────────────────────────────────

variable "api_image" {
  description = "Container image for the API service (FastAPI). Defaults to the GHCR demo image."
  type        = string
  default     = "ghcr.io/beenuar/aisoc-api:latest"
}

variable "web_image" {
  description = "Container image for the web service (Next.js)."
  type        = string
  default     = "ghcr.io/beenuar/aisoc-web:latest"
}

variable "ingest_image" {
  description = "Container image for the ingest service (Go)."
  type        = string
  default     = "ghcr.io/beenuar/aisoc-ingest:latest"
}

variable "api_min_instances" {
  description = "Minimum Cloud Run instances for the API. Set >0 to avoid cold starts."
  type        = number
  default     = 0
}

variable "api_max_instances" {
  description = "Maximum Cloud Run instances for the API."
  type        = number
  default     = 10
}

variable "web_max_instances" {
  description = "Maximum Cloud Run instances for the web app."
  type        = number
  default     = 5
}

variable "ingest_max_instances" {
  description = "Maximum Cloud Run instances for the ingest service."
  type        = number
  default     = 5
}

variable "allow_unauthenticated" {
  description = "When true, exposes Cloud Run services to the public internet (allUsers)."
  type        = bool
  default     = true
}

variable "cors_origins" {
  description = "Comma-separated CORS allow-list passed to the API service."
  type        = string
  default     = ""
}

# ─── OpenAI / agents ─────────────────────────────────────────────────────────

variable "openai_api_key" {
  description = "Optional OpenAI API key persisted to Secret Manager. Leave blank to skip."
  type        = string
  default     = ""
  sensitive   = true
}
