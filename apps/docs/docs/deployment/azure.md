---
sidebar_position: 4
---

# Azure (Container Apps + Postgres Flexible Server)

A serverless-first Terraform skeleton lives at
[`infra/terraform/azure/`](https://github.com/beenuar/AiSOC/tree/main/infra/terraform/azure).
It mirrors the [GCP skeleton](./gcp) file-for-file on Azure: Container Apps for
the customer-visible services (API, web, ingest), Azure Database for
PostgreSQL Flexible Server 16, and Azure Cache for Redis — all on private
endpoints inside a dedicated VNet.

## What you get

| Component                    | Resource                                         |
|------------------------------|--------------------------------------------------|
| API (FastAPI)                | Azure Container App                              |
| Web console (Next.js)        | Azure Container App                              |
| Ingest gateway (Go)          | Azure Container App                              |
| Application database         | Postgres Flexible Server 16, VNet-integrated     |
| Queues / rate limit / fan-out| Azure Cache for Redis, private endpoint, TLS-only|
| Secrets                      | Azure Key Vault (auto-generated)                 |
| Container registry           | Azure Container Registry                         |
| Networking                   | Dedicated VNet + private DNS zones               |
| Identity                     | One user-assigned managed identity per app       |

## Prerequisites

1. An Azure subscription with credits or billing attached.
2. `az` authenticated (`az login`) as a principal that can create resource
   groups, Container Apps, Postgres, Key Vault, and **role assignments**.
   Granting role assignments needs `Owner` or `User Access Administrator` on
   the subscription (the apply wires `AcrPull` + `Key Vault Secrets User`
   itself).
3. Terraform 1.5+ and the [`azurerm`](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
   3.116 provider (the lockfile pins exact versions on first `init`).

## Quick start

```bash
cd infra/terraform/azure
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars            # optional — defaults already work

az login
az account set --subscription <subscription-id>

terraform init
terraform plan -out tfplan          # review the proposed plan
terraform apply tfplan
```

A full apply against an empty subscription takes ~15 minutes — most of that is
the Postgres Flexible Server and the Redis private endpoint. After the apply
finishes, the `api_url`, `web_url`, and `ingest_url` outputs are publicly
reachable immediately (Container Apps ingress issues a managed TLS cert per
service).

```bash
$ terraform output
api_url     = "https://aisoc-api.<env-id>.eastus.azurecontainerapps.io"
web_url     = "https://aisoc-web.<env-id>.eastus.azurecontainerapps.io"
ingest_url  = "https://aisoc-ingest.<env-id>.eastus.azurecontainerapps.io"
```

## Container images

The defaults point at the public GHCR demo images
(`ghcr.io/beenuar/aisoc-{api,web,ingest}:latest`) so the skeleton runs with
zero CI work. For a real deployment, push your own images to the ACR this
stack provisions:

```bash
ACR=$(terraform output -raw container_registry_login_server)
az acr login --name "${ACR%%.*}"

docker build -t $ACR/api:$(git rev-parse --short HEAD)    services/api
docker push     $ACR/api:$(git rev-parse --short HEAD)
# repeat for web + ingest

terraform apply \
  -var "api_image=$ACR/api:<sha>" \
  -var "web_image=$ACR/web:<sha>" \
  -var "ingest_image=$ACR/ingest:<sha>"
```

The managed identities already hold `AcrPull`, so no registry admin user or
password is needed.

## Connecting to Postgres from your laptop

The Flexible Server has no public endpoint — it's only resolvable inside the
VNet via the `privatelink.postgres.database.azure.com` zone. Reach it through
a jump host in the VNet, a point-to-site VPN, or temporarily enable a public
firewall rule. The admin password lives in Key Vault:

```bash
VAULT=$(terraform output -raw key_vault_name)
az keyvault secret show --vault-name "$VAULT" --name postgres-password \
  --query value -o tsv
```

## Secrets

Five secrets are managed automatically:

| Secret name                | Source                | Consumed by         |
|----------------------------|-----------------------|---------------------|
| `postgres-password`        | random_password       | api, ingest         |
| `secret-key`               | random_password (64c) | api, ingest         |
| `credential-key`           | random (Fernet key)   | api (CredentialVault) |
| `redis-auth`               | Azure Cache primary   | api, ingest         |
| `openai-api-key`           | `var.openai_api_key`  | api (optional)      |

Container Apps mount each as an environment variable via a
`secretRef → keyVaultRef` pointer, so rotating a secret value in Key Vault is
picked up on the next revision deploy.

## Costs

Defaults are chosen so a fresh apply fits inside an Azure free-trial / startup
envelope:

| Resource                  | Default               | ~Monthly cost (East US) |
| ------------------------- | --------------------- | ----------------------- |
| Postgres Flexible Server  | `GP_Standard_D2s_v3`  | ~$135                   |
| Azure Cache for Redis     | `Standard C1` (1 GB)  | ~$55                    |
| Container Apps (idle)     | 0–10 replicas         | ~$0 (scale-to-zero)     |
| Container Registry        | `Standard`            | ~$20                    |
| Key Vault + Log Analytics | low volume            | ~$5                     |

For the cheapest sandbox set `postgres_sku = "B_Standard_B1ms"` and
`redis_sku = "Basic"` in `terraform.tfvars`.

## Limitations

This is a **skeleton**, not the full Azure migration:

- **No long-running services.** `services/agents`, `services/realtime`,
  `services/connectors`, `services/alert-fusion`, `services/threatintel`, and
  `services/fusion` need always-on compute. Run them as dedicated Container
  Apps with `min_replicas > 0` (KEDA can still scale on queue depth) or move
  them to AKS sharing this VNet, Postgres, and Redis.
- **Redis is TLS-only.** The non-SSL port is disabled, so the apps connect on
  `6380` with `REDIS_SSL=true`. Confirm the AiSOC Redis client honours that
  before pointing production traffic at it.
- **No Azure Front Door / WAF.** Container Apps ingress gives every service a
  managed `*.azurecontainerapps.io` certificate, fine for the skeleton. Put
  Azure Front Door + WAF in front of the API for a custom domain and edge
  filtering.
- **No customer-managed keys.** Key Vault is the secret store; CMEK on
  Postgres / Redis / ACR is a small addition deferred to keep the trust
  boundary tight.
- **Key Vault public access stays on** to keep first-run secret population
  simple (it mirrors GCP Secret Manager's API-plane reachability). Lock it
  down with a private endpoint + `network_acls` for a hardened install.
- **Demo image source.** `ghcr.io/beenuar/aisoc-*` is the zero-config default;
  don't ship that to production.

## Tear-down

```bash
terraform destroy
```

Key Vault is created with soft-delete on but **purge-on-destroy enabled**, so
a destroy fully removes it — back up any secrets you want to keep first. The
Postgres server and Redis cache are deleted with the rest of the stack.

## See also

- [`infra/terraform/azure/README.md`](https://github.com/beenuar/AiSOC/blob/main/infra/terraform/azure/README.md) — operator runbook
- [Environment variables reference](./env-vars) — what each Container App
  consumes
- [GCP skeleton](./gcp) — equivalent skeleton on Google Cloud (Cloud Run +
  Cloud SQL + Memorystore)
- [AWS BYOC module](https://github.com/beenuar/AiSOC/tree/main/infra/terraform/byoc)
  — equivalent skeleton for AWS (EKS + RDS + ElastiCache)
