# AiSOC on Azure — Terraform skeleton

A serverless-first deployment of the AiSOC stack on Microsoft Azure, mirroring
the [GCP skeleton](../gcp/README.md):

- **Azure Container Apps** for the API (FastAPI), web console (Next.js), and
  ingest gateway
- **Azure Database for PostgreSQL Flexible Server 16** for the application
  database (VNet-integrated private access, no public endpoint)
- **Azure Cache for Redis** for queues, rate limits, and websocket fan-out
  (private endpoint, TLS-only)
- **Azure Key Vault** for the application secrets (DB password, `SECRET_KEY`,
  `AISOC_CREDENTIAL_KEY`, Redis auth, optional `OPENAI_API_KEY`)
- **Azure Container Registry** as the registry CI pushes to
- **User-assigned managed identities** so each Container App pulls its own
  image and reads only the secrets it needs — no registry passwords or
  connection strings on disk

> This is the **skeleton** — a buyer-friendly starting point that runs the
> three customer-visible services. Long-running workloads (`agents`,
> `realtime`, `connectors`, `threatintel`, `alert-fusion`, `fusion`) need
> always-on compute and are deferred to a follow-up plan. See
> [Limitations](#limitations).

## Layout

```
infra/terraform/azure/
├── README.md                ← you are here
├── versions.tf              ← terraform + provider pinning, provider features
├── variables.tf             ← input variables (defaults targeting startup credit)
├── main.tf                  ← resource group, VNet + subnets, Log Analytics,
│                              Container Apps environment, ACR
├── database.tf              ← Postgres Flexible Server + DB + private DNS
├── redis.tf                 ← Azure Cache for Redis + private endpoint
├── secrets.tf               ← Key Vault + generated/optional secret values
├── iam.tf                   ← per-service managed identities + role assignments
├── container_apps.tf        ← api / web / ingest Container Apps
├── outputs.tf               ← URLs, connection targets, identity + vault IDs
└── terraform.tfvars.example ← copy → terraform.tfvars and override
```

Files are split by concern, not by module, to keep the skeleton legible. Lift
into modules when you start running multiple environments off the same code.

## Prerequisites

1. **An Azure subscription** with credits or billing attached.
2. **`az` authenticated** (`az login`) as a principal that can create resource
   groups, Container Apps, Postgres, Key Vault, and **role assignments**.
   Granting role assignments needs `Owner` or `User Access Administrator` on
   the subscription (the apply wires AcrPull + Key Vault Secrets User itself).
3. **Terraform 1.5+** and the `azurerm` 3.116 provider (the lockfile pins the
   exact versions on first `init`).
4. (Optional) **A storage account for remote state** — recommended for anything
   beyond a personal sandbox; see *State backend* below.

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
the Postgres Flexible Server and the Redis private endpoint. After apply, the
`api_url`, `web_url`, and `ingest_url` outputs are publicly reachable
immediately (Container Apps ingress issues a managed TLS cert per service).

## State backend

Terraform state is **not configured** by default so you can pick what fits.
For anything shared across operators, use an Azure Storage backend:

1. Create the state container once (outside Terraform):
   ```bash
   az group create -n aisoc-tfstate -l eastus
   az storage account create -g aisoc-tfstate -n aisoctfstate$RANDOM \
     --sku Standard_LRS --encryption-services blob
   az storage container create -n tfstate --account-name <account-name>
   ```
2. Add a `backend "azurerm"` block to `versions.tf`:
   ```hcl
   backend "azurerm" {
     resource_group_name  = "aisoc-tfstate"
     storage_account_name = "<account-name>"
     container_name       = "tfstate"
     key                  = "azure.tfstate"
   }
   ```
3. Re-run `terraform init -migrate-state`.

## Container images

The defaults point at the public GHCR demo images
(`ghcr.io/beenuar/aisoc-{api,web,ingest}:latest`) so the skeleton runs with
zero CI work. For a real deployment, push your own images to the ACR this stack
provisions:

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
VNet via the `privatelink.postgres.database.azure.com` zone. Reach it through a
jump host in the VNet, a point-to-site VPN, or temporarily enable a public
firewall rule. The admin password lives in Key Vault:

```bash
VAULT=$(terraform output -raw key_vault_name)
az keyvault secret show --vault-name "$VAULT" --name postgres-password \
  --query value -o tsv
```

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

This is the **skeleton**, not the full migration. Known gaps:

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
  simple (it mirrors GCP Secret Manager's API-plane reachability). Lock it down
  with a private endpoint + `network_acls` for a hardened install.
- **Demo image source.** `ghcr.io/beenuar/aisoc-*` is the zero-config default;
  don't ship that to production. See *Container images* above.

## Tear-down

```bash
terraform destroy
```

Key Vault is created with soft-delete on but **purge-on-destroy enabled**
(`versions.tf`), so a destroy fully removes it — back up any secrets you want
to keep first. The Postgres server and Redis cache are deleted with the rest of
the stack.
