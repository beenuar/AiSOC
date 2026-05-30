/**
 * AiSOC — Azure serverless skeleton
 *
 * Outputs scoped to what an operator needs right after `terraform apply`: the
 * public Container App URLs, the connection targets the API dials, and the IDs
 * the matching CI workflow needs to push container images. Mirrors the GCP
 * stack's outputs.tf.
 */

# ─── Container App URLs ──────────────────────────────────────────────────────

output "api_url" {
  description = "Public Container App URL for the AiSOC API."
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "web_url" {
  description = "Public Container App URL for the AiSOC web console."
  value       = "https://${azurerm_container_app.web.ingress[0].fqdn}"
}

output "ingest_url" {
  description = "Public Container App URL for the AiSOC ingest endpoint."
  value       = "https://${azurerm_container_app.ingest.ingress[0].fqdn}"
}

# ─── PostgreSQL Flexible Server ──────────────────────────────────────────────

output "postgres_fqdn" {
  description = "Private FQDN of the PostgreSQL Flexible Server (resolves inside the VNet)."
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "postgres_database" {
  description = "Application database name inside the Flexible Server."
  value       = azurerm_postgresql_flexible_server_database.aisoc.name
}

output "postgres_admin_user" {
  description = "Administrator login for the Flexible Server."
  value       = var.postgres_user
}

# ─── Azure Cache for Redis ───────────────────────────────────────────────────

output "redis_hostname" {
  description = "Private hostname of the Azure Cache for Redis instance."
  value       = azurerm_redis_cache.main.hostname
}

output "redis_ssl_port" {
  description = "TLS port of the Azure Cache for Redis instance (non-SSL port is disabled)."
  value       = azurerm_redis_cache.main.ssl_port
}

# ─── Container Registry ──────────────────────────────────────────────────────

output "container_registry_login_server" {
  description = "ACR login server (push target for CI image builds)."
  value       = azurerm_container_registry.main.login_server
}

# ─── Managed identities ──────────────────────────────────────────────────────

output "identity_api_client_id" {
  description = "Client ID of the API runtime managed identity."
  value       = azurerm_user_assigned_identity.api.client_id
}

output "identity_web_client_id" {
  description = "Client ID of the web runtime managed identity."
  value       = azurerm_user_assigned_identity.web.client_id
}

output "identity_ingest_client_id" {
  description = "Client ID of the ingest runtime managed identity."
  value       = azurerm_user_assigned_identity.ingest.client_id
}

# ─── Key Vault ───────────────────────────────────────────────────────────────

output "key_vault_name" {
  description = "Name of the Key Vault holding the runtime secrets."
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "Vault URI for ad-hoc `az keyvault secret show` after apply."
  value       = azurerm_key_vault.main.vault_uri
}
