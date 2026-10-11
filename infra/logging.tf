# Log Analytics + Sentinel + the pipe the honeypot writes through:
#   VM (managed identity) -> Data Collection Endpoint -> Data Collection Rule -> HoneypotEvents_CL

locals {
  table_name  = "HoneypotEvents_CL"
  stream_name = "Custom-HoneypotEvents_CL"

  columns = [
    { name = "TimeGenerated", type = "datetime" },
    { name = "EventId", type = "string" },
    { name = "Sensor", type = "string" },
    { name = "Kind", type = "string" },
    { name = "SrcIp", type = "string" },
    { name = "SrcPort", type = "int" },
    { name = "DstPort", type = "int" },
    { name = "Username", type = "string" },
    { name = "Password", type = "string" },
    { name = "Client", type = "string" },
    { name = "Method", type = "string" },
    { name = "Path", type = "string" },
    { name = "Country", type = "string" },
    { name = "CountryCode", type = "string" },
    { name = "City", type = "string" },
    { name = "Latitude", type = "real" },
    { name = "Longitude", type = "real" },
    { name = "Asn", type = "string" },
    { name = "Honeypot", type = "string" },
  ]
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}

# azurerm has no resource for custom table schemas, so we use azapi.
resource "azapi_resource" "table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = local.table_name
  parent_id = azurerm_log_analytics_workspace.main.id

  body = {
    properties = {
      retentionInDays = var.retention_days
      plan            = "Analytics"
      schema = {
        name    = local.table_name
        columns = local.columns
      }
    }
  }
}

resource "azurerm_monitor_data_collection_endpoint" "main" {
  name                          = "dce-${var.prefix}"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_monitor_data_collection_rule" "main" {
  name                        = "dcr-${var.prefix}"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.main.id
  tags                        = local.tags

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
    }
  }

  data_flow {
    streams       = [local.stream_name]
    destinations  = ["law"]
    output_stream = local.stream_name
    transform_kql = "source"
  }

  stream_declaration {
    stream_name = local.stream_name
    dynamic "column" {
      for_each = local.columns
      content {
        name = column.value.name
        type = column.value.type
      }
    }
  }

  depends_on = [azapi_resource.table]
}

# Least privilege: the VM may only publish to this one rule.
resource "azurerm_role_assignment" "vm_publish" {
  scope                = azurerm_monitor_data_collection_rule.main.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_linux_virtual_machine.main.identity[0].principal_id
}
