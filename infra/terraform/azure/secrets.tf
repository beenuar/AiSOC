/**
 * AiSOC — Azure serverless skeleton
 *
 * Key Vault entries that the Container Apps read back as secret-backed env
 * vars (container_apps.tf). The runtime managed identities are granted
 * "Key Vault Secrets User" in iam.tf so we don't inline that here.
 *
 * Generated values (SECRET_KEY, CredentialVault key) are produced by random_*
 * resources and only their Key Vault references cross the trust boundary — the
 * plaintext never lands in tfvars.
 */

# ─── Generated secrets ───────────────────────────────────────────────────────

resource "random_password" "secret_key" {
  length  = 64
  special = false
}

resource "random_password" "credential_key" {
  # CredentialVault uses Fernet which expects a 32-byte url-safe base64 key.
  # 32 random bytes -> base64 is a valid Fernet key; generating it here means a
  # `terraform destroy` + `apply` rotates the vault key cleanly. Operators who
  # need rotation-without-rewrap should set AISOC_CREDENTIAL_KEY_ROTATION_FROM
  # in app config.
  length      = 32
  special     = false
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
}

# ─── Key Vault ───────────────────────────────────────────────────────────────
#
# RBAC-authorization mode (no access policies). The deploying principal gets
# "Key Vault Secrets Officer" so this apply can write the secret values; the
# Container App identities get read-only "Key Vault Secrets User" in iam.tf.
#
# Public network access stays enabled to keep first-run secret population simple
# (mirrors GCP's Secret Manager, which is reachable over the Google API plane).
# Lock it down with a private endpoint + network_acls for a hardened install.

resource "azurerm_key_vault" "main" {
  name                = "${var.name_prefix}-kv-${random_string.kv_suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name                      = "standard"
  enable_rbac_authorization     = true
  purge_protection_enabled      = false
  soft_delete_retention_days    = 7
  public_network_access_enabled = true

  tags = var.tags
}

# Key Vault names are globally unique (3-24 chars). A short random suffix keeps
# re-applies and forks from colliding without forcing a unique name_prefix.
resource "random_string" "kv_suffix" {
  length  = 6
  special = false
  upper   = false
  numeric = true
}

# Let this apply's identity write secret values. Without this, the
# azurerm_key_vault_secret resources below 403 on a fresh RBAC vault.
resource "azurerm_role_assignment" "deployer_secrets_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ─── Secret values ───────────────────────────────────────────────────────────

resource "azurerm_key_vault_secret" "postgres_password" {
  name         = "postgres-password"
  value        = random_password.postgres.result
  key_vault_id = azurerm_key_vault.main.id
  tags         = var.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}

resource "azurerm_key_vault_secret" "secret_key" {
  name         = "secret-key"
  value        = random_password.secret_key.result
  key_vault_id = azurerm_key_vault.main.id
  tags         = var.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}

resource "azurerm_key_vault_secret" "credential_key" {
  name         = "credential-key"
  value        = base64encode(random_password.credential_key.result)
  key_vault_id = azurerm_key_vault.main.id
  tags         = var.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}

resource "azurerm_key_vault_secret" "redis_auth" {
  name         = "redis-auth"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id
  tags         = var.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}

# ─── Optional: OpenAI key ────────────────────────────────────────────────────
# Only created when var.openai_api_key is non-empty so an air-gapped install
# (Ollama / LiteLLM overlay) doesn't have to invent a placeholder secret.

resource "azurerm_key_vault_secret" "openai_api_key" {
  count = var.openai_api_key == "" ? 0 : 1

  name         = "openai-api-key"
  value        = var.openai_api_key
  key_vault_id = azurerm_key_vault.main.id
  tags         = var.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}
