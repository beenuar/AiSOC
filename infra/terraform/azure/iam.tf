/**
 * AiSOC — Azure serverless skeleton
 *
 * Per-service runtime identities. Each Container App runs as a dedicated
 * user-assigned managed identity so role assignments stay scoped to one
 * workload at a time (the GCP stack uses one service account per service for
 * the same reason).
 *
 * Bindings:
 *   - every identity gets AcrPull on the registry (pull its own image)
 *   - api + ingest get "Key Vault Secrets User" (read DB / vault / redis creds)
 *   - web is a Next.js bundle that only talks to the API over HTTP, so it gets
 *     no Key Vault access
 */

# ─── User-assigned managed identities ────────────────────────────────────────

resource "azurerm_user_assigned_identity" "api" {
  name                = "${var.name_prefix}-api-id"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "web" {
  name                = "${var.name_prefix}-web-id"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "ingest" {
  name                = "${var.name_prefix}-ingest-id"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

# ─── ACR pull (all three) ────────────────────────────────────────────────────

locals {
  acr_pull_identities = {
    api    = azurerm_user_assigned_identity.api.principal_id
    web    = azurerm_user_assigned_identity.web.principal_id
    ingest = azurerm_user_assigned_identity.ingest.principal_id
  }
}

resource "azurerm_role_assignment" "acr_pull" {
  for_each = local.acr_pull_identities

  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = each.value
}

# ─── Key Vault Secrets User (api + ingest) ───────────────────────────────────

locals {
  kv_reader_identities = {
    api    = azurerm_user_assigned_identity.api.principal_id
    ingest = azurerm_user_assigned_identity.ingest.principal_id
  }
}

resource "azurerm_role_assignment" "kv_secrets_user" {
  for_each = local.kv_reader_identities

  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
}
