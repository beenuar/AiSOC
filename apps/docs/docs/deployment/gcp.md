---
sidebar_position: 3
---

# GCP (Cloud Run + Cloud SQL)

A serverless-first Terraform skeleton lives at
[`infra/terraform/gcp/`](https://github.com/beenuar/AiSOC/tree/main/infra/terraform/gcp).
It targets Google Cloud Run for the customer-visible services (API, web,
ingest), Cloud SQL for PostgreSQL 16, and Memorystore for Redis 7.2 — all
private-IP, peered through a dedicated VPC.

## What you get

| Component                    | Resource                              |
|------------------------------|---------------------------------------|
| API (FastAPI)                | Cloud Run v2 service                  |
| Web console (Next.js)        | Cloud Run v2 service                  |
| Ingest gateway (Go)          | Cloud Run v2 service                  |
| Application database         | Cloud SQL for PostgreSQL 16, private  |
| Queues / rate limit / fan-out| Memorystore Redis 7.2, private        |
| Secrets                      | Secret Manager (auto-generated)       |
| Container registry           | Artifact Registry (Docker)            |
| Networking                   | Dedicated VPC + Serverless VPC Access |
| Identity                     | One service account per Cloud Run svc |

## Prerequisites

1. A GCP project with billing attached.
2. `gcloud` authenticated as a principal that can create Cloud Run services,
   Cloud SQL instances, Secret Manager entries, and service accounts in that
   project. Project Owner is the simplest grant; the
   least-privilege bundle is `roles/run.admin` + `roles/iam.serviceAccountAdmin`
   + `roles/secretmanager.admin` + `roles/cloudsql.admin` +
   `roles/compute.networkAdmin`.
3. Terraform 1.5+ and the [Google provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
   5.40+ (the lockfile pins exact versions on first init).

## Quick start

```bash
cd infra/terraform/gcp
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars            # at minimum set project_id

terraform init
terraform plan -out tfplan          # review the proposed plan
terraform apply tfplan
```

A full apply against an empty project takes ~12 minutes — most of that is the
Cloud SQL instance and the service-networking peering. After the apply
finishes, the `api_url`, `web_url`, and `ingest_url` outputs are reachable
immediately if `allow_unauthenticated` is `true` (the default).

```bash
$ terraform output
api_url     = "https://aisoc-api-xxxxxxxxxx-uc.a.run.app"
web_url     = "https://aisoc-web-xxxxxxxxxx-uc.a.run.app"
ingest_url  = "https://aisoc-ingest-xxxxxxxxxx-uc.a.run.app"
```

## Container images

The defaults point at the public GHCR demo images
(`ghcr.io/beenuar/aisoc-{api,web,ingest}:latest`) so the skeleton runs with
zero CI work. For a real deployment, push your own images to the Artifact
Registry repo this stack provisions:

```bash
gcloud auth configure-docker us-central1-docker.pkg.dev

REPO=$(terraform output -raw artifact_registry_repo)

docker build -t $REPO/api:$(git rev-parse --short HEAD)    services/api
docker push     $REPO/api:$(git rev-parse --short HEAD)
# repeat for web + ingest

terraform apply \
  -var "api_image=$REPO/api:<sha>" \
  -var "web_image=$REPO/web:<sha>" \
  -var "ingest_image=$REPO/ingest:<sha>"
```

## Connecting to Cloud SQL from your laptop

The instance has no public IP. Use the
[Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy):

```bash
INSTANCE=$(terraform output -raw sql_connection_name)
PASSWORD=$(gcloud secrets versions access latest \
  --secret=$(terraform output -raw secret_postgres_password_id))

cloud-sql-proxy --port 5432 "$INSTANCE" &
PGPASSWORD="$PASSWORD" psql -h 127.0.0.1 -U aisoc aisoc
```

## Secrets

Five secrets are managed automatically:

| Secret ID                     | Source                | Consumed by         |
|-------------------------------|-----------------------|---------------------|
| `aisoc-postgres-password`     | random_password       | api, ingest         |
| `aisoc-secret-key`            | random_password (64c) | api, ingest         |
| `aisoc-credential-key`        | random (Fernet key)   | api (CredentialVault) |
| `aisoc-redis-auth`            | Memorystore auth      | api, ingest         |
| `aisoc-openai-api-key`        | `var.openai_api_key`  | api (optional)      |

Cloud Run mounts each as an environment variable via
`secret_key_ref { version = "latest" }`, so rotating a secret value (without
deleting the secret) is picked up on the next revision deploy.

## Costs

Defaults are chosen so a fresh apply against a project that's never run a
demo before fits inside the 90-day GCP startup-credit envelope:

| Resource              | Default            | ~Monthly cost (us-central1) |
| --------------------- | ------------------ | --------------------------- |
| Cloud SQL Postgres    | `db-custom-2-7680` | ~$95                        |
| Memorystore Redis     | `BASIC` 1 GB       | ~$30                        |
| VPC Access connector  | 2× e2-micro        | ~$10                        |
| Cloud Run (idle)      | 0–10 instances     | ~$0 (scale-to-zero)         |
| Artifact Registry     | empty repo         | ~$0                         |

Tune `postgres_tier` and `redis_memory_size_gb` in `terraform.tfvars` for a
cheaper sandbox; the smallest sensible production tier is `db-custom-2-7680`
plus a `STANDARD_HA` Redis.

## Limitations

This is a **skeleton**, not the full GCP migration:

- **No long-running services.** `services/agents`, `services/realtime`,
  `services/connectors`, `services/alert-fusion`, `services/threatintel`, and
  `services/fusion` need persistent compute. The websocket fan-out and the
  APScheduler-driven connector polling don't fit Cloud Run's request lifecycle
  cleanly. The recommended follow-up is GKE Autopilot for those workloads,
  sharing the VPC and Cloud SQL provisioned here.
- **No HTTPS load balancer.** Cloud Run gives every service a `*.run.app`
  certificate that's fine for the skeleton. Wire a Global External HTTPS Load
  Balancer + Cloud Armor in front of the API for a custom domain and WAF.
- **No Kafka.** The buyer-value demo runs on Redis Streams alone. For higher
  throughput, swap in Confluent Cloud or run Kafka on GKE.
- **No CMEK.** Secret Manager is the secret store; customer-managed encryption
  keys on Cloud SQL / Memorystore / Artifact Registry are a one-line addition
  (`encryption_key_name = ...`) and intentionally left out of the skeleton to
  keep the trust boundary small.
- **Demo image source.** `ghcr.io/beenuar/aisoc-*` is the default for the
  zero-config experience; don't ship that to production.

## Tear-down

```bash
terraform destroy
```

Cloud SQL refuses to delete unless `deletion_protection=false`. Either flip
the variable and re-apply first, or destroy in two steps:

```bash
terraform apply -var deletion_protection=false
terraform destroy
```

## See also

- [`infra/terraform/gcp/README.md`](https://github.com/beenuar/AiSOC/blob/main/infra/terraform/gcp/README.md) — operator runbook
- [Environment variables reference](./env-vars) — what each Cloud Run service
  consumes
- [AWS BYOC module](https://github.com/beenuar/AiSOC/tree/main/infra/terraform/byoc)
  — equivalent skeleton for AWS (EKS + RDS + ElastiCache)
