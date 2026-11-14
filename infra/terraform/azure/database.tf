/**
 * AiSOC — Azure serverless skeleton
 *
 * PostgreSQL Flexible Server with VNet-integrated private access (no public
 * endpoint). The password is generated here and stored in Key Vault
 * (secrets.tf); the Container Apps read it back as a secret-backed env var.
 */

# ─── Generated admin password ────────────────────────────────────────────────

resource "random_password" "postgres" {
  length  = 32
  special = true
  # Flexible Server rejects a handful of characters in the admin password.
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ─── Private DNS for VNet integration ────────────────────────────────────────
#
# Flexible Server with VNet integration requires a private DNS zone named
# *.postgres.database.azure.com linked to the VNet so the apps resolve the
# server's private IP.

resource "azurerm_private_dns_zone" "postgres" {
  name                = "${var.name_prefix}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "${var.name_prefix}-pg-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
  tags                  = var.tags
}

# ─── Flexible Server ─────────────────────────────────────────────────────────

resource "azurerm_postgresql_flexible_server" "main" {
  name                = "${var.name_prefix}-pg"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  version  = var.postgres_version
  sku_name = var.postgres_sku
  zone     = var.postgres_zone

  storage_mb            = var.postgres_storage_mb
  auto_grow_enabled     = true
  backup_retention_days = 7

  administrator_login    = var.postgres_user
  administrator_password = random_password.postgres.result

  # VNet integration → private only. public_network_access is implicitly
  # disabled when delegated_subnet_id is set.
  delegated_subnet_id = azurerm_subnet.postgres.id
  private_dns_zone_id = azurerm_private_dns_zone.postgres.id

  tags = var.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]

  lifecycle {
    # Zone changes after creation force a replacement; ignore drift on these
    # so an apply doesn't try to rebuild the server under load.
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "aisoc" {
  name      = var.postgres_db_name
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# Require TLS for all connections (matches the app's sslmode=require default).
resource "azurerm_postgresql_flexible_server_configuration" "require_ssl" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "ON"
}
