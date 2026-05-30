/**
 * AiSOC — Azure serverless skeleton
 *
 * Input variables. Defaults aim for "smallest viable AiSOC" so a `terraform
 * apply` against a fresh subscription produces a working stack inside an
 * Azure free-trial / startup-credit envelope, not a five-figure surprise.
 */

# ─── Subscription / location ─────────────────────────────────────────────────

variable "subscription_id" {
  description = "Azure subscription ID that will own every resource. Leave blank to use the ARM_SUBSCRIPTION_ID / az-cli default."
  type        = string
  default     = ""
}

variable "location" {
  description = "Primary Azure region for the resource group, Container Apps, Postgres, and Redis."
  type        = string
  default     = "eastus"
}

variable "name_prefix" {
  description = "Prefix used for resource names (Container Apps, Postgres server, etc.). Must be lowercase; 3-12 chars keeps globally-unique names (ACR, Key Vault) under their length caps."
  type        = string
  default     = "aisoc"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,11}$", var.name_prefix))
    error_message = "name_prefix must be 3-12 chars, lowercase letters/digits, starting with a letter (keeps ACR + Key Vault names valid)."
  }
}

variable "tags" {
  description = "Common tags applied to every resource."
  type        = map(string)
  default = {
    project    = "aisoc"
    managed_by = "terraform"
  }
}

# ─── Networking ──────────────────────────────────────────────────────────────

variable "vnet_cidr" {
  description = "CIDR for the VNet that hosts the Container Apps environment and the data-tier private endpoints."
  type        = string
  default     = "10.20.0.0/16"
}

variable "aca_subnet_cidr" {
  description = "Subnet for the Container Apps environment. Must be at least /23 for a Consumption-only environment."
  type        = string
  default     = "10.20.0.0/23"
}

variable "postgres_subnet_cidr" {
  description = "Delegated subnet for the Postgres Flexible Server VNet integration."
  type        = string
  default     = "10.20.2.0/27"
}

variable "privatelink_subnet_cidr" {
  description = "Subnet that holds the Redis (and any future) private endpoints."
  type        = string
  default     = "10.20.3.0/27"
}

# ─── PostgreSQL Flexible Server ──────────────────────────────────────────────

variable "postgres_sku" {
  description = "Flexible Server SKU. B_Standard_B1ms is the cheapest burstable dev tier; GP_Standard_D2s_v3 is the smallest sensible production tier."
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "postgres_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "postgres_storage_mb" {
  description = "Initial storage in MB (must be a supported Flexible Server size, e.g. 32768, 65536)."
  type        = number
  default     = 32768
}

variable "postgres_db_name" {
  description = "Logical database name created inside the server."
  type        = string
  default     = "aisoc"
}

variable "postgres_user" {
  description = "Administrator login for the Flexible Server."
  type        = string
  default     = "aisoc"
}

variable "postgres_zone" {
  description = "Availability zone for the primary Flexible Server node."
  type        = string
  default     = "1"
}

# ─── Azure Cache for Redis ───────────────────────────────────────────────────

variable "redis_sku" {
  description = "Redis SKU — Basic for dev (no SLA, no HA), Standard for prod, Premium for VNet injection / clustering."
  type        = string
  default     = "Standard"
}

variable "redis_family" {
  description = "Redis SKU family — C for Basic/Standard, P for Premium."
  type        = string
  default     = "C"
}

variable "redis_capacity" {
  description = "Redis size unit (0=250MB, 1=1GB, 2=2.5GB for the C family)."
  type        = number
  default     = 1
}

# ─── Container Apps ──────────────────────────────────────────────────────────

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

variable "api_min_replicas" {
  description = "Minimum Container App replicas for the API. Set >0 to avoid cold starts."
  type        = number
  default     = 0
}

variable "api_max_replicas" {
  description = "Maximum Container App replicas for the API."
  type        = number
  default     = 10
}

variable "web_max_replicas" {
  description = "Maximum Container App replicas for the web app."
  type        = number
  default     = 5
}

variable "ingest_max_replicas" {
  description = "Maximum Container App replicas for the ingest service."
  type        = number
  default     = 5
}

variable "cors_origins" {
  description = "Comma-separated CORS allow-list passed to the API service."
  type        = string
  default     = ""
}

# ─── OpenAI / agents ─────────────────────────────────────────────────────────

variable "openai_api_key" {
  description = "Optional OpenAI API key persisted to Key Vault. Leave blank to skip (air-gapped Ollama / LiteLLM config)."
  type        = string
  default     = ""
  sensitive   = true
}
