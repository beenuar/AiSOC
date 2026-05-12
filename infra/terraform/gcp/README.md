# AiSOC on Google Cloud — Terraform skeleton

A serverless-first deployment of the AiSOC stack on Google Cloud Platform:

- **Cloud Run v2** for the API (FastAPI), web console (Next.js), and ingest gateway
- **Cloud SQL for PostgreSQL 16** for the application database (private IP)
- **Memorystore for Redis 7.2** for queues, rate limits, and websocket fan-out
- **Secret Manager** for the application secrets (DB password, `SECRET_KEY`,
  `AISOC_CREDENTIAL_KEY`, Redis auth, optional `OPENAI_API_KEY`)
- **Artifact Registry** as the container registry CI pushes to
- **Serverless VPC Access connector** so Cloud Run can reach Cloud SQL and
  Memorystore over private IPs

> This is the **skeleton** — a buyer-friendly starting point that runs the
> three customer-visible services. Long-running workloads (`agents`,
> `realtime`, `connectors`, `threatintel`, `alert-fusion`) need a managed
> instance group or GKE Autopilot and are deferred to a follow-up plan.
> See [Limitations](#limitations) below.

## Layout

```
infra/terraform/gcp/
├── README.md                ← you are here
├── versions.tf              ← terraform + provider pinning
├── variables.tf             ← input variables (defaults targeting startup credit)
├── main.tf                  ← APIs, VPC, VPC connector, Artifact Registry
├── database.tf              ← Cloud SQL + database + user
├── redis.tf                 ← Memorystore for Redis
├── secrets.tf               ← Secret Manager entries (generated + optional)
├── iam.tf                   ← per-service runtime service accounts + bindings
├── cloud_run.tf             ← api / web / ingest Cloud Run v2 services
├── outputs.tf               ← URLs, connection strings, secret IDs
└── terraform.tfvars.example ← copy → terraform.tfvars and fill in
```

Files are split by concern, not by module, to keep the skeleton legible. Lift
into modules when you start running multiple environments off the same code.

## Prerequisites

1. **A GCP project** with billing attached. The skeleton enables every API it
   needs, but billing must already be linked.
2. **`gcloud` authenticated** as a principal that can create service accounts,
   secrets, and Cloud Run services in that project (project Owner is the
   simplest grant; principle-of-least-privilege bundles like
   `roles/run.admin` + `roles/iam.serviceAccountAdmin` +
   `roles/secretmanager.admin` + `roles/cloudsql.admin` work too).
3. **Terraform 1.7+** and the Google provider 5.40+ (the lockfile pins the
   exact versions on first init).
4. (Optional) **A GCS bucket for remote state.** Highly recommended for
   anything beyond a personal sandbox; see *State backend* below.

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

## State backend

Terraform state is **not configured** by default so you can pick what fits.
For anything shared across operators, use GCS:

1. Create the state bucket once (outside Terraform), versioning enabled:
   ```bash
   gcloud storage buckets create gs://aisoc-tfstate-<project-id> \
     --project=<project-id> \
     --location=us-central1 \
     --uniform-bucket-level-access
   gcloud storage buckets update gs://aisoc-tfstate-<project-id> \
     --versioning
   ```
2. Uncomment the `backend "gcs"` block at the top of `versions.tf`:
   ```hcl
   backend "gcs" {
     bucket = "aisoc-tfstate-<project-id>"
     prefix = "gcp"
   }
   ```
3. Re-run `terraform init -migrate-state`.

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

# Then point Cloud Run at the new tags:
terraform apply \
  -var "api_image=$REPO/api:<sha>" \
  -var "web_image=$REPO/web:<sha>" \
  -var "ingest_image=$REPO/ingest:<sha>"
```

## Connecting to Cloud SQL from your laptop

The instance has no public IP. Use the [Cloud SQL Auth
Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy):

```bash
INSTANCE=$(terraform output -raw sql_connection_name)
PASSWORD=$(gcloud secrets versions access latest \
  --secret=$(terraform output -raw secret_postgres_password_id))

cloud-sql-proxy --port 5432 "$INSTANCE" &
PGPASSWORD="$PASSWORD" psql -h 127.0.0.1 -U aisoc aisoc
```

## Costs

Defaults are chosen so a fresh apply against a project that's never run a
demo before fits inside the 90-day startup credit envelope:

| Resource              | Default            | ~Monthly cost (us-central1) |
| --------------------- | ------------------ | --------------------------- |
| Cloud SQL Postgres    | `db-custom-2-7680` | ~$95                        |
| Memorystore Redis     | `BASIC` 1 GB       | ~$30                        |
| VPC Access connector  | 2× e2-micro        | ~$10                        |
| Cloud Run (idle)      | 0–10 instances     | ~$0 (scale-to-zero)         |
| Artifact Registry     | empty repo         | ~$0                         |

Tune `postgres_tier` and `redis_memory_size_gb` in `terraform.tfvars` for a
cheaper sandbox; the smallest sensible production is `db-custom-2-7680` +
`STANDARD_HA` Redis.

## Limitations

This is the **skeleton**, not the full migration. Known gaps:

- **No long-running services.** `services/agents`, `services/realtime`,
  `services/connectors`, `services/alert-fusion`, `services/threatintel`, and
  `services/fusion` need persistent compute. Cloud Run v2 *does* support sidecar
  workloads up to 60 minutes per request, but the websocket fan-out and the
  APScheduler-driven connector polling don't fit cleanly. The recommended
  follow-up is GKE Autopilot for those workloads, sharing the VPC and Cloud
  SQL provisioned here.
- **No HTTPS load balancer.** Cloud Run gives every service a `*.run.app`
  certificate that's fine for the skeleton. Wire a Global External
  HTTPS Load Balancer + Cloud Armor in front of the API for a custom domain
  and WAF.
- **No Kafka / message bus.** The AiSOC ingest path can run on Redis Streams
  alone for the buyer-value demo. For higher throughput, swap in
  Confluent Cloud or run Kafka on GKE.
- **No BYOK envelope encryption.** Secret Manager is the secret store;
  customer-managed encryption keys (CMEK) on Cloud SQL / Memorystore /
  Artifact Registry are a one-line addition (`encryption_key_name = ...`)
  and intentionally left out of the skeleton to keep the trust boundary
  small.
- **Demo image source.** `ghcr.io/beenuar/aisoc-*` is the default for the
  zero-config experience; don't ship that to production. See *Container
  images* above.

For the full GCP migration plan (multi-tenant, Kafka, GKE Autopilot,
observability, CMEK), see the v1.1 roadmap in the project's planning docs.

## Tear-down

```bash
terraform destroy
```

Cloud SQL will refuse to delete unless `deletion_protection=false`. Either
flip the variable and re-apply first, or destroy via:

```bash
terraform apply -var deletion_protection=false
terraform destroy
```

The Secret Manager secrets and the Artifact Registry repo are deleted with
the rest of the stack; back up anything you want to keep first.
