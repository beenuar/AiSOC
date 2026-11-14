variable "name_prefix" {
  description = "Prefix applied to all MSK resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC the Kafka cluster is deployed into"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs the broker nodes are placed in"
  type        = list(string)
}

variable "instance_type" {
  description = "MSK broker instance type"
  type        = string
  default     = "kafka.m5.large"
}

variable "broker_count" {
  description = "Number of broker nodes (must be a multiple of the number of subnets)"
  type        = number
  default     = 3
}

variable "kafka_version" {
  description = "Apache Kafka version"
  type        = string
  default     = "3.6.0"
}

variable "ebs_volume_size" {
  description = "EBS volume size per broker in GiB"
  type        = number
  default     = 100
}

variable "allowed_security_groups" {
  description = "Security group IDs permitted to reach the brokers"
  type        = list(string)
  default     = []
}
