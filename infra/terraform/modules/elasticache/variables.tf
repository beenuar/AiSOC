variable "name_prefix" {
  description = "Prefix applied to all ElastiCache resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC the cache is deployed into"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs used for the cache subnet group"
  type        = list(string)
}

variable "node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "7.1"
}

variable "num_shards" {
  description = "Number of node groups (shards) in the cluster"
  type        = number
  default     = 2
}

variable "replicas_per_shard" {
  description = "Number of read replicas per shard"
  type        = number
  default     = 1
}

variable "allowed_security_groups" {
  description = "Security group IDs permitted to reach Redis on port 6379"
  type        = list(string)
  default     = []
}
