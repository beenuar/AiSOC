/**
 * AiSOC — GCP serverless skeleton
 *
 * Provider pinning. Tested against Terraform 1.5+ and the 5.x google
 * providers. Bump in lockstep when google releases new resource types we
 * need (Cloud SQL Postgres 16, Memorystore for Redis 7.2, Cloud Run v2).
 */

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State backend left intentionally unconfigured. Pick one of:
  #
  #   backend "gcs"   { bucket = "aisoc-tfstate-<project-id>"  prefix = "gcp" }
  #   backend "local" {}
  #
  # …and bootstrap the bucket once per project before `terraform init`.
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}
