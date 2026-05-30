# AiSOC Terraform — AWS infrastructure

This directory provisions the AWS infrastructure that the AiSOC Helm chart
(`infra/helm/aisoc/`) deploys onto. It is the path the production deployment
docs (`apps/docs/docs/deployment/kubernetes.md`) reference.

```
infra/terraform/
├── main.tf            # Wires the modules together + outputs
├── variables.tf       # Inputs (region, env, instance sizes, CIDRs)
└── modules/
    ├── vpc/             # 3-AZ VPC: public, private, db subnets
    ├── eks/             # EKS cluster + general & compute node groups
    ├── rds/             # PostgreSQL RDS
    ├── elasticache/     # Redis (sharded)
    ├── kafka/           # MSK
    ├── opensearch/      # OpenSearch (optional)
    ├── clickhouse/      # Self-managed ClickHouse on EC2 (optional)
    ├── databases/       # Helper module that wires DSNs into k8s secrets
    ├── kubernetes/      # In-cluster bootstrap (CRDs, namespaces, addons)
    ├── network/         # Extra security groups + private endpoints
    └── vault/           # HashiCorp Vault (optional)
```

`main.tf` deploys the **core** stack: `vpc`, `eks`, `rds`, `elasticache`,
`kafka`. The other modules under `modules/` are optional add-ons — wire them
in by extending `main.tf` if you need OpenSearch, ClickHouse, or Vault.

## What you get

A 3-AZ deployment in a single AWS region with:

- VPC: 10.0.0.0/16 by default (public, private, db subnet tiers per AZ).
- EKS 1.28 with two managed node groups:
  - `general` — `m6i.xlarge`, 2–10 nodes, runs the bulk of AiSOC services.
  - `compute` — `c6i.2xlarge`, 0–5 nodes, taint `workload=compute:NO_SCHEDULE`
    for ML/agent workloads.
- RDS PostgreSQL on `db.r6g.large` (override via `rds_instance_class`).
- ElastiCache Redis with 2 shards × 1 replica on `cache.r6g.large`.
- MSK Kafka with 3 brokers on `kafka.m5.large`.

All data services restrict ingress to the EKS node security group.

## Backend state

State is stored in S3 with DynamoDB locking. Before the first `terraform init`
you must create:

```hcl
# main.tf:29
backend "s3" {
  bucket         = "aisoc-terraform-state"
  key            = "infra/terraform.tfstate"
  region         = "us-east-1"
  encrypt        = true
  dynamodb_table = "aisoc-terraform-locks"
}
```

Bootstrap once per AWS account:

```bash
aws s3 mb s3://aisoc-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket aisoc-terraform-state \
  --versioning-configuration Status=Enabled

aws dynamodb create-table \
  --table-name aisoc-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

If you want a different bucket/table/region, edit the `backend "s3"` block
**before** the first `terraform init` — moving state after the fact is
operationally painful.

## Deploy

```bash
cd infra/terraform

# 1. Provider plugins + module init
terraform init

# 2. Plan against an environment
terraform plan \
  -var="environment=prod" \
  -var="aws_region=us-east-1" \
  -out=tfplan

# 3. Apply (15–25 min on a clean account; EKS + MSK dominate)
terraform apply tfplan

# 4. Wire kubectl up to the new cluster
aws eks update-kubeconfig \
  --name "$(terraform output -raw eks_cluster_name)" \
  --region us-east-1
```

The endpoints needed by the Helm chart are emitted as outputs:

```bash
terraform output -raw rds_endpoint
terraform output -raw redis_endpoint
terraform output -raw kafka_bootstrap_servers   # canonical name; matches KAFKA_BOOTSTRAP_SERVERS
terraform output -raw eks_cluster_endpoint
```

Feed these into a Kubernetes `Secret` consumed by the AiSOC chart — see
`apps/docs/docs/deployment/env-vars.md` for the canonical environment-variable
contract.

## Common overrides

| Variable | Default | Notes |
|---|---|---|
| `aws_region` | `us-east-1` | Single-region deployment. |
| `environment` | `prod` | One of `dev`, `staging`, `prod`. Drives the `aisoc-${environment}` name prefix. |
| `vpc_cidr` | `10.0.0.0/16` | Pick something that doesn't collide with your peering. |
| `eks_cluster_version` | `1.28` | Bump in lockstep with addon compatibility. |
| `rds_instance_class` | `db.r6g.large` | Down-size to `db.t4g.medium` for dev. |
| `redis_node_type` | `cache.r6g.large` | `cache.t4g.medium` for dev. |
| `kafka_instance_type` | `kafka.m5.large` | `kafka.t3.small` for dev (3 brokers minimum). |
| `db_username` | `aisoc_admin` | Marked `sensitive`; the password is generated and stored in Secrets Manager by the `rds` module. |

For a dev/eval install, drop the instance sizes and consider not provisioning
MSK at all (run the in-cluster Kafka from the Helm bundle instead).

## Destroy

```bash
terraform destroy -var="environment=prod"
```

RDS and OpenSearch take a final snapshot before deletion (set explicitly in
the modules). The S3 state bucket and DynamoDB lock table are **not** managed
by this configuration and survive `destroy`.

## Alternate cloud skeletons

This directory is the AWS/EKS reference. Two serverless-container skeletons
exist for teams that don't want to run Kubernetes:

- `infra/terraform/gcp/` — Cloud Run + Cloud SQL Postgres + Memorystore Redis +
  Secret Manager + Artifact Registry, fronted by Serverless VPC Access.
- `infra/terraform/azure/` — Container Apps + PostgreSQL Flexible Server +
  Azure Cache for Redis + Key Vault + Container Registry, on a private VNet
  with user-assigned managed identities. Mirrors the GCP layout file-for-file.

Both deploy the `api`, `web`, and `ingest` services directly as managed
containers (no cluster), and emit the same env-var contract documented in
`apps/docs/docs/deployment/env-vars.md`.

## Related docs

- `apps/docs/docs/deployment/kubernetes.md` — production deployment guide.
- `apps/docs/docs/deployment/env-vars.md` — env-var contract; note that
  `KAFKA_BOOTSTRAP_SERVERS` is canonical (`KAFKA_BROKERS` is honored as a
  back-compat alias).
- `infra/helm/README.md` — the chart that runs on top of this infra.
