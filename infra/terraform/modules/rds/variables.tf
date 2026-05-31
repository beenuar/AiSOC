variable "name_prefix" {
  description = "Prefix applied to all RDS resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC the database is deployed into"
  type        = string
}

variable "db_subnet_ids" {
  description = "Subnet IDs used for the database subnet group"
  type        = list(string)
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  default     = "aisoc"
}

variable "db_username" {
  description = "Master username"
  type        = string
  default     = "aisoc_admin"
  sensitive   = true
}

variable "engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "16.4"
}

variable "allocated_storage" {
  description = "Initial allocated storage in GiB"
  type        = number
  default     = 100
}

variable "max_allocated_storage" {
  description = "Upper bound for storage autoscaling in GiB"
  type        = number
  default     = 1000
}

variable "backup_retention_period" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 7
}

variable "multi_az" {
  description = "Deploy the database across multiple availability zones"
  type        = bool
  default     = true
}

variable "allowed_security_groups" {
  description = "Security group IDs permitted to reach the database on port 5432"
  type        = list(string)
  default     = []
}
