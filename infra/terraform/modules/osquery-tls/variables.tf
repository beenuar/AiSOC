variable "namespace" {
  description = "Kubernetes namespace to deploy into"
  type        = string
  default     = "aisoc"
}

variable "create_namespace" {
  description = "Whether to create the namespace (set false if it already exists)"
  type        = bool
  default     = false
}

variable "image_repository" {
  description = "Container image repository for aisoc-osquery-tls"
  type        = string
  default     = "ghcr.io/aisoc-community/osquery-tls"
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 2
}

variable "enroll_secret" {
  description = "Shared secret that osqueryd agents must present during enrollment"
  type        = string
  sensitive   = true
}

variable "database_url" {
  description = "PostgreSQL connection URL (asyncpg driver)"
  type        = string
  sensitive   = true
}

variable "ingest_base_url" {
  description = "Base URL for the AiSOC ingest service"
  type        = string
  default     = "http://aisoc-ingest:8080"
}

variable "resources" {
  description = "CPU and memory resource requests/limits"
  type = object({
    requests = object({
      cpu    = string
      memory = string
    })
    limits = object({
      cpu    = string
      memory = string
    })
  })
  default = {
    requests = {
      cpu    = "100m"
      memory = "128Mi"
    }
    limits = {
      cpu    = "500m"
      memory = "512Mi"
    }
  }
}

variable "autoscaling" {
  description = "Horizontal Pod Autoscaler settings"
  type = object({
    enabled                = bool
    min_replicas           = number
    max_replicas           = number
    target_cpu_utilization = number
  })
  default = {
    enabled                = true
    min_replicas           = 2
    max_replicas           = 10
    target_cpu_utilization = 70
  }
}
