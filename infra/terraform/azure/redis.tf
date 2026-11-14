/**
 * AiSOC — Azure serverless skeleton
 *
 * Azure Cache for Redis reached over a private endpoint. Public network access
 * is disabled; the Container Apps resolve the cache's private IP via the
 * privatelink.redis.cache.windows.net DNS zone linked to the VNet.
 *
 * The primary access key is read back into Key Vault (secrets.tf) so the apps
 * inject it as REDIS_PASSWORD the same way every other secret flows.
 */

resource "azurerm_redis_cache" "main" {
  name                = "${var.name_prefix}-redis"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  sku_name = var.redis_sku
  family   = var.redis_family
  capacity = var.redis_capacity

  # Lock down to TLS 1.2 over the private endpoint only.
  non_ssl_port_enabled          = false
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false

  tags = var.tags
}

# ─── Private endpoint + DNS ──────────────────────────────────────────────────

resource "azurerm_private_dns_zone" "redis" {
  name                = "privatelink.redis.cache.windows.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "redis" {
  name                  = "${var.name_prefix}-redis-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.redis.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_endpoint" "redis" {
  name                = "${var.name_prefix}-redis-pe"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  subnet_id           = azurerm_subnet.privatelink.id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.name_prefix}-redis-psc"
    private_connection_resource_id = azurerm_redis_cache.main.id
    subresource_names              = ["redisCache"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "redis"
    private_dns_zone_ids = [azurerm_private_dns_zone.redis.id]
  }
}
