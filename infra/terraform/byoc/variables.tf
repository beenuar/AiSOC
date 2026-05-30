variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "EKS cluster / resource name prefix"
  type        = string
  default     = "aisoc-byoc"
}

variable "kubernetes_version" {
  type    = string
  default = "1.29"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "azs" {
  type    = list(string)
  default = ["us-west-2a", "us-west-2b"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.large"
}

variable "db_password" {
  description = "Master password for RDS (store in a secret manager in production)"
  type        = string
  sensitive   = true
}

variable "redis_node_type" {
  type    = string
  default = "cache.t3.medium"
}

variable "tags" {
  type = map(string)
  default = {
    Project     = "AiSOC"
    Environment = "byoc"
    ManagedBy   = "Terraform"
  }
}