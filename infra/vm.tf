resource "random_password" "map_token" {
  length  = 32
  special = false
}

resource "azurerm_linux_virtual_machine" "main" {
  name                            = "vm-${var.prefix}"
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
  size                            = var.vm_size
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.main.id]
  tags                            = local.tags

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 30
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_ssh_port      = var.admin_ssh_port
    repo_url            = var.repo_url
    maxmind_license_key = var.maxmind_license_key
    dce_endpoint        = azurerm_monitor_data_collection_endpoint.main.logs_ingestion_endpoint
    dcr_id              = azurerm_monitor_data_collection_rule.main.immutable_id
    stream_name         = local.stream_name
    map_token           = random_password.map_token.result
    home_lat            = var.home_lat
    home_lon            = var.home_lon
    location            = var.location
  }))
}

resource "azurerm_consumption_budget_resource_group" "main" {
  count             = var.budget_email == "" ? 0 : 1
  name              = "budget-${var.prefix}"
  resource_group_id = azurerm_resource_group.main.id
  amount            = var.monthly_budget
  time_grain        = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = [var.budget_email]
  }

  notification {
    enabled        = true
    threshold      = 100
    threshold_type = "Forecasted"
    operator       = "GreaterThan"
    contact_emails = [var.budget_email]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
