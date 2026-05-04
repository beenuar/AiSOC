/**
 * AiSOC - AI Security Operations Center
 * Terraform Infrastructure - Main Configuration
 * AiSOC — open-source under MIT License
 */

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    bucket         = "aisoc-terraform-state"
    key            = "infra/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aisoc-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AiSOC"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "AiSOC"
    }
  }
}

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# ─── Locals ───────────────────────────────────────────────────────────────────

locals {
  name_prefix = "aisoc-${var.environment}"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)
  account_id  = data.aws_caller_identity.current.account_id
}

# ─── Modules ──────────────────────────────────────────────────────────────────

module "vpc" {
  source = "./modules/vpc"

  name_prefix         = local.name_prefix
  vpc_cidr            = var.vpc_cidr
  availability_zones  = local.azs
  public_subnets_cidr = var.public_subnets_cidr
  private_subnets_cidr = var.private_subnets_cidr
  db_subnets_cidr     = var.db_subnets_cidr
}

module "eks" {
  source = "./modules/eks"

  name_prefix        = local.name_prefix
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  cluster_version    = var.eks_cluster_version

  node_groups = {
    general = {
      instance_types = ["m6i.xlarge"]
      min_size       = 2
      max_size       = 10
      desired_size   = 3
      disk_size      = 50
    }
    compute = {
      instance_types = ["c6i.2xlarge"]
      min_size       = 0
      max_size       = 5
      desired_size   = 1
      disk_size      = 100
      taints = [{
        key    = "workload"
        value  = "compute"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

module "rds" {
  source = "./modules/rds"

  name_prefix    = local.name_prefix
  vpc_id         = module.vpc.vpc_id
  db_subnet_ids  = module.vpc.db_subnet_ids
  instance_class = var.rds_instance_class
  db_name        = "aisoc"
  db_username    = var.db_username

  allowed_security_groups = [module.eks.node_security_group_id]
}

module "elasticache" {
  source = "./modules/elasticache"

  name_prefix   = local.name_prefix
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  node_type     = var.redis_node_type
  num_shards    = 2
  replicas_per_shard = 1

  allowed_security_groups = [module.eks.node_security_group_id]
}

module "kafka" {
  source = "./modules/kafka"

  name_prefix    = local.name_prefix
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.private_subnet_ids
  instance_type  = var.kafka_instance_type
  broker_count   = 3

  allowed_security_groups = [module.eks.node_security_group_id]
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
  sensitive   = true
}

output "rds_endpoint" {
  description = "PostgreSQL RDS endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.elasticache.endpoint
  sensitive   = true
}

output "kafka_bootstrap_servers" {
  description = "Kafka bootstrap servers"
  value       = module.kafka.bootstrap_brokers
  sensitive   = true
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}
