# AiSOC Bring-Your-Own-Cloud (BYOC) — minimal production starter
# Deploys the core control plane (API + Agents) on a single-region EKS cluster
# with managed PostgreSQL, Redis, and object storage.

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }
}

provider "aws" {
  region = var.region
}

# VPC, subnets, EKS cluster, node groups, RDS (Postgres), ElastiCache (Redis)
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr

  azs             = var.azs
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = var.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    default = {
      min_size       = 2
      max_size       = 6
      desired_size   = 3
      instance_types = ["m6i.large"]
    }
  }

  tags = var.tags
}

# RDS PostgreSQL (multi-AZ for prod)
resource "aws_db_subnet_group" "db" {
  name       = "${var.cluster_name}-db-subnet"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "postgres" {
  identifier        = "${var.cluster_name}-postgres"
  engine            = "postgres"
  engine_version    = "16.2"
  instance_class    = var.db_instance_class
  allocated_storage = 100
  storage_encrypted = true
  multi_az          = true

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [module.eks.cluster_security_group_id]

  username = "aisoc"
  password = var.db_password

  skip_final_snapshot = true
  tags                = var.tags
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.cluster_name}-redis"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.cluster_name}-redis"
  description                = "AiSOC Redis"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  engine                     = "redis"
  engine_version             = "7.1"
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [module.eks.cluster_security_group_id]
  tags                       = var.tags
}

output "postgres_endpoint" {
  value = aws_db_instance.postgres.endpoint
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}