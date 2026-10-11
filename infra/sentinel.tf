# Sentinel analytics rules. The KQL lives in ../kql/rules so it can be
# read, tested, and reused outside Terraform.

locals {
  rules = {
    brute-force = {
      display_name = "Snare: brute force from a single IP"
      description  = "One IP made 20 or more login attempts against the honeypot in 15 minutes."
      severity     = "Medium"
      frequency    = "PT15M"
      period       = "PT15M"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
    }
    password-spray = {
      display_name = "Snare: password spray"
      description  = "One IP tried 10 or more usernames with 3 or fewer passwords in an hour."
      severity     = "Medium"
      frequency    = "PT1H"
      period       = "PT1H"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
    }
    multi-protocol-recon = {
      display_name = "Snare: one IP probed SSH, Telnet, and HTTP"
      description  = "The same source touched every honeypot sensor within an hour."
      severity     = "Low"
      frequency    = "PT1H"
      period       = "PT1H"
      tactics      = ["Reconnaissance"]
      techniques   = ["T1595"]
    }
    web-exploit-probe = {
      display_name = "Snare: web exploit or secret file probe"
      description  = "Requests for paths tied to known exploits or leaked config files."
      severity     = "Informational"
      frequency    = "PT1H"
      period       = "PT1H"
      tactics      = ["InitialAccess"]
      techniques   = ["T1190"]
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "rules" {
  for_each = local.rules

  name                       = "snare-${each.key}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = each.value.display_name
  description                = each.value.description
  severity                   = each.value.severity
  query                      = file("${path.module}/../kql/rules/${each.key}.kql")
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SrcIp"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT6H"
      entity_matching_method  = "Selected"
      by_entities             = ["IP"]
      reopen_closed_incidents = false
    }
  }

  depends_on = [azapi_resource.table]
}

# A Sentinel workbook with a world map, the same idea as the live map but
# backed by the full history in Log Analytics.
resource "random_uuid" "workbook" {}

resource "azurerm_application_insights_workbook" "map" {
  name                = random_uuid.workbook.result
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "Snare Threat Map"
  source_id           = lower(azurerm_log_analytics_workspace.main.id)
  category            = "sentinel"
  tags                = local.tags

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 9
        name = "params"
        content = {
          version = "KqlParameterItem/1.0"
          parameters = [{
            id    = "0b2d6f6c-0000-4000-8000-000000000001"
            name  = "TimeRange"
            type  = 4
            value = { durationMs = 86400000 }
            typeSettings = {
              selectableValues = [
                { durationMs = 3600000 }, { durationMs = 86400000 },
                { durationMs = 604800000 }, { durationMs = 2592000000 }
              ]
            }
          }]
        }
      },
      {
        type = 3
        name = "map"
        content = {
          version                  = "KqlItem/1.0"
          title                    = "Attacks by location"
          query                    = file("${path.module}/../kql/hunting/attack-map.kql")
          size                     = 0
          timeContextFromParameter = "TimeRange"
          queryType                = 0
          resourceType             = "microsoft.operationalinsights/workspaces"
          visualization            = "map"
          mapSettings = {
            locInfo           = "LatLong"
            latitude          = "Latitude"
            longitude         = "Longitude"
            sizeSettings      = "Events"
            sizeAggregation   = "Sum"
            labelSettings     = "Country"
            legendMetric      = "Events"
            legendAggregation = "Sum"
            itemColorSettings = {
              nodeColorField   = "Events"
              colorAggregation = "Sum"
              type             = "heatmap"
              heatmapPalette   = "greenRed"
            }
          }
        }
      },
      {
        type = 3
        name = "creds"
        content = {
          version                  = "KqlItem/1.0"
          title                    = "Top credentials"
          query                    = file("${path.module}/../kql/hunting/top-credentials.kql")
          size                     = 0
          timeContextFromParameter = "TimeRange"
          queryType                = 0
          resourceType             = "microsoft.operationalinsights/workspaces"
          visualization            = "table"
        }
        customWidth = "50"
      },
      {
        type = 3
        name = "countries"
        content = {
          version                  = "KqlItem/1.0"
          title                    = "Attacks by country"
          query                    = file("${path.module}/../kql/hunting/attacks-by-country.kql")
          size                     = 0
          timeContextFromParameter = "TimeRange"
          queryType                = 0
          resourceType             = "microsoft.operationalinsights/workspaces"
          visualization            = "barchart"
        }
        customWidth = "50"
      },
    ]
    fallbackResourceIds = [azurerm_log_analytics_workspace.main.id]
  })
}
