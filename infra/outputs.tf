output "public_ip" {
  description = "The honeypot's public IP. Attackers will find it on their own within minutes."
  value       = azurerm_public_ip.main.ip_address
}

output "admin_ssh" {
  description = "How to reach the real shell."
  value       = "ssh -p ${var.admin_ssh_port} azureuser@${azurerm_public_ip.main.ip_address}"
}

output "map_url" {
  description = "Live threat map (includes the access token)."
  value       = "http://${azurerm_public_ip.main.ip_address}:8080/?token=${random_password.map_token.result}"
  sensitive   = true
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.main.workspace_id
}

output "dce_endpoint" {
  value = azurerm_monitor_data_collection_endpoint.main.logs_ingestion_endpoint
}

output "dcr_immutable_id" {
  value = azurerm_monitor_data_collection_rule.main.immutable_id
}
