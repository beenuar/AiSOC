/**
 * AiSOC — GCP serverless skeleton
 *
 * Bootstraps shared resources required by every other file in this stack:
 *   - the GCP APIs the rest of the stack needs
 *   - a private VPC + Serverless VPC Access connector for Cloud Run egress
 *   - a regional Artifact Registry repo for AiSOC container images
 *
 * Service-specific resources live in:
 *   database.tf   — Cloud SQL (Postgres)
 *   redis.tf      — Memorystore (Redis)
 *   secrets.tf    — Secret Manager entries
 *   iam.tf        — runtime service accounts
 *   cloud_run.tf  — api / web / ingest services
 */

# ─── Required APIs ───────────────────────────────────────────────────────────

locals {
  required_apis = [
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "enabled" {
  for_each = toset(local.required_apis)

  project                    = var.project_id
  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ─── Network ─────────────────────────────────────────────────────────────────
#
# A small dedicated VPC keeps Cloud SQL on private IP and lets Cloud Run reach
# both Postgres and Memorystore over the connector below. Public IP egress is
# unchanged for the services themselves.

resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.enabled]
}

resource "google_compute_subnetwork" "primary" {
  name                     = "${var.name_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.vpc_cidr
  private_ip_google_access = true
}

# Reserved IP range used by service networking (Cloud SQL private IP, Memorystore).
resource "google_compute_global_address" "private_service" {
  name          = "${var.name_prefix}-psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_service" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service.name]

  depends_on = [google_project_service.enabled]
}

# Serverless VPC Access connector — Cloud Run uses this to reach Cloud SQL
# (private IP) and Memorystore.
resource "google_vpc_access_connector" "main" {
  name          = "${var.name_prefix}-vpcconn"
  region        = var.region
  network       = google_compute_network.vpc.name
  ip_cidr_range = var.vpc_connector_cidr
  min_instances = 2
  max_instances = 3
  machine_type  = "e2-micro"

  depends_on = [google_project_service.enabled]
}

# ─── Artifact Registry ───────────────────────────────────────────────────────
#
# Optional but recommended. CI can push images here instead of GHCR; Cloud Run
# pulls them with the runtime SA's roles/artifactregistry.reader binding (set
# in iam.tf).

resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  repository_id = "${var.name_prefix}-containers"
  description   = "Container images for AiSOC services."
  format        = "DOCKER"
  labels        = var.labels

  depends_on = [google_project_service.enabled]
}
