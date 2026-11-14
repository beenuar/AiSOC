/**
 * AiSOC — Azure serverless skeleton
 *
 * Container Apps for the three customer-visible workloads:
 *
 *   - api    — FastAPI control plane (port 8000)
 *   - web    — Next.js console (port 3000)
 *   - ingest — Go fan-in service that accepts /v1/ingest/batch (port 8080)
 *
 * Long-running workloads (agents, alert-fusion, realtime, threatintel,
 * connectors, fusion, ocsf) intentionally aren't here — they belong on a
 * dedicated always-on Container App (min_replicas > 0) or AKS in a follow-up
 * plan because scale-to-zero doesn't fit websocket fan-out or scheduler loops.
 * This skeleton ships the surface customers see first, mirroring the GCP stack.
 *
 * Secrets flow: Key Vault entry -> `secret { key_vault_secret_id, identity }`
 * -> `env { secret_name }`. The managed identity reads Key Vault at revision
 * activation time, so the apps depend on the "Key Vault Secrets User" role
 * assignment (iam.tf) existing first.
 */

locals {
  # Azure Postgres Flexible Server is reached by FQDN over the private DNS zone;
  # unlike Cloud SQL there's no unix socket, so the app dials host:5432 w/ TLS.
  postgres_host = azurerm_postgresql_flexible_server.main.fqdn

  # Azure Cache for Redis with the non-SSL port disabled is TLS-only on 6380.
  redis_host = azurerm_redis_cache.main.hostname
  redis_port = azurerm_redis_cache.main.ssl_port
}

# ─── API ─────────────────────────────────────────────────────────────────────

resource "azurerm_container_app" "api" {
  name                         = "${var.name_prefix}-api"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.api.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.api.id
  }

  # ── Key Vault-backed secrets ───────────────────────────────────────────────
  secret {
    name                = "postgres-password"
    identity            = azurerm_user_assigned_identity.api.id
    key_vault_secret_id = azurerm_key_vault_secret.postgres_password.id
  }
  secret {
    name                = "secret-key"
    identity            = azurerm_user_assigned_identity.api.id
    key_vault_secret_id = azurerm_key_vault_secret.secret_key.id
  }
  secret {
    name                = "credential-key"
    identity            = azurerm_user_assigned_identity.api.id
    key_vault_secret_id = azurerm_key_vault_secret.credential_key.id
  }
  # Shared HS256 secret the API uses to mint realtime WS/SSE tickets (Issue
  # #239). The Node realtime workload (an always-on Container App / AKS in the
  # follow-up plan) reads the same Key Vault entry to verify them.
  secret {
    name                = "realtime-jwt-secret"
    identity            = azurerm_user_assigned_identity.api.id
    key_vault_secret_id = azurerm_key_vault_secret.realtime_jwt_secret.id
  }
  secret {
    name                = "redis-auth"
    identity            = azurerm_user_assigned_identity.api.id
    key_vault_secret_id = azurerm_key_vault_secret.redis_auth.id
  }
  dynamic "secret" {
    for_each = toset(var.openai_api_key == "" ? [] : ["openai"])
    content {
      name                = "openai-api-key"
      identity            = azurerm_user_assigned_identity.api.id
      key_vault_secret_id = azurerm_key_vault_secret.openai_api_key[0].id
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto" # HTTP/1.1 + HTTP/2 + websockets (for realtime later)

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas

    container {
      name   = "api"
      image  = var.api_image
      cpu    = 1.0
      memory = "2Gi"

      # ── Static config ────────────────────────────────────────────────────────
      env {
        name  = "AISOC_DEPLOYMENT"
        value = "azure-containerapps"
      }
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db_name
      }
      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_HOST"
        value = local.postgres_host
      }
      env {
        name  = "POSTGRES_PORT"
        value = "5432"
      }
      env {
        name  = "POSTGRES_SSLMODE"
        value = "require"
      }
      env {
        name  = "REDIS_HOST"
        value = local.redis_host
      }
      env {
        name  = "REDIS_PORT"
        value = tostring(local.redis_port)
      }
      env {
        name  = "REDIS_SSL"
        value = "true"
      }
      env {
        name  = "CORS_ORIGINS"
        value = var.cors_origins
      }

      # ── Secret-backed env ────────────────────────────────────────────────────
      env {
        name        = "POSTGRES_PASSWORD"
        secret_name = "postgres-password"
      }
      env {
        name        = "SECRET_KEY"
        secret_name = "secret-key"
      }
      env {
        name        = "AISOC_CREDENTIAL_KEY"
        secret_name = "credential-key"
      }
      env {
        name        = "AISOC_REALTIME_JWT_SECRET"
        secret_name = "realtime-jwt-secret"
      }
      env {
        name        = "REDIS_PASSWORD"
        secret_name = "redis-auth"
      }
      dynamic "env" {
        for_each = toset(var.openai_api_key == "" ? [] : ["openai"])
        content {
          name        = "OPENAI_API_KEY"
          secret_name = "openai-api-key"
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.kv_secrets_user,
    azurerm_postgresql_flexible_server_database.aisoc,
  ]
}

# ─── Web ─────────────────────────────────────────────────────────────────────

resource "azurerm_container_app" "web" {
  name                         = "${var.name_prefix}-web"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.web.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.web.id
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 0
    max_replicas = var.web_max_replicas

    container {
      name   = "web"
      image  = var.web_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "AISOC_DEPLOYMENT"
        value = "azure-containerapps"
      }
      env {
        name  = "NEXT_PUBLIC_API_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }
      env {
        name  = "NODE_ENV"
        value = "production"
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# ─── Ingest ──────────────────────────────────────────────────────────────────

resource "azurerm_container_app" "ingest" {
  name                         = "${var.name_prefix}-ingest"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ingest.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.ingest.id
  }

  secret {
    name                = "postgres-password"
    identity            = azurerm_user_assigned_identity.ingest.id
    key_vault_secret_id = azurerm_key_vault_secret.postgres_password.id
  }
  secret {
    name                = "secret-key"
    identity            = azurerm_user_assigned_identity.ingest.id
    key_vault_secret_id = azurerm_key_vault_secret.secret_key.id
  }
  secret {
    name                = "redis-auth"
    identity            = azurerm_user_assigned_identity.ingest.id
    key_vault_secret_id = azurerm_key_vault_secret.redis_auth.id
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 0
    max_replicas = var.ingest_max_replicas

    container {
      name   = "ingest"
      image  = var.ingest_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "AISOC_DEPLOYMENT"
        value = "azure-containerapps"
      }
      env {
        name  = "POSTGRES_DB"
        value = var.postgres_db_name
      }
      env {
        name  = "POSTGRES_USER"
        value = var.postgres_user
      }
      env {
        name  = "POSTGRES_HOST"
        value = local.postgres_host
      }
      env {
        name  = "POSTGRES_PORT"
        value = "5432"
      }
      env {
        name  = "POSTGRES_SSLMODE"
        value = "require"
      }
      env {
        name  = "REDIS_HOST"
        value = local.redis_host
      }
      env {
        name  = "REDIS_PORT"
        value = tostring(local.redis_port)
      }
      env {
        name  = "REDIS_SSL"
        value = "true"
      }

      env {
        name        = "POSTGRES_PASSWORD"
        secret_name = "postgres-password"
      }
      env {
        name        = "SECRET_KEY"
        secret_name = "secret-key"
      }
      env {
        name        = "REDIS_PASSWORD"
        secret_name = "redis-auth"
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.kv_secrets_user,
    azurerm_postgresql_flexible_server_database.aisoc,
  ]
}
