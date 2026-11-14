/**
 * AiSOC Terraform Variables
 */

variable "aws_region" {
  description = "AWS region to deploy infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnets_cidr" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnets_cidr" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "db_subnets_cidr" {
  description = "Database subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

variable "eks_cluster_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"
}

variable "rds_instance_class" {
  description = "RDS PostgreSQL instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_username" {
  description = "PostgreSQL master username. Owns the schema and applies migrations; no service connects as it."
  type        = string
  default     = "aisoc_admin"
  sensitive   = true
}

variable "db_app_username" {
  description = <<-EOT
    The DML-only role every service connects as. Created by
    services/api/migrations/061_runtime_app_role.sql, which also constrains it to
    NOSUPERUSER NOBYPASSRLS so the row-level-security policies actually apply.
    Change this only if you also change the migration.
  EOT
  type        = string
  default     = "aisoc_app"
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "kafka_instance_type" {
  description = "MSK Kafka broker instance type"
  type        = string
  default     = "kafka.m5.large"
}

variable "osquery_tls_image_tag" {
  description = "Container image tag for aisoc-osquery-tls"
  type        = string
  default     = "latest"
}

variable "osquery_tls_replicas" {
  description = "Baseline pod replica count for aisoc-osquery-tls"
  type        = number
  default     = 2
}

variable "osquery_tls_enroll_secret" {
  description = "Shared enroll secret for osqueryd agent authentication"
  type        = string
  sensitive   = true
}
