variable "subscription_id" {
  description = "Azure subscription to deploy into."
  type        = string
}

variable "prefix" {
  description = "Short name used in every resource name."
  type        = string
  default     = "snare"
}

variable "location" {
  description = "Azure region for the honeypot."
  type        = string
  default     = "canadacentral"
}

variable "admin_cidr" {
  description = "Your own public IP in CIDR form (for example 203.0.113.7/32). Only this range can reach the real SSH port and the map."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && var.admin_cidr != "0.0.0.0/0"
    error_message = "admin_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "admin_ssh_public_key" {
  description = "Public key for the real admin login (contents of ~/.ssh/id_ed25519.pub)."
  type        = string
}

variable "admin_ssh_port" {
  description = "Port the real sshd moves to, so the honeypot can own port 22."
  type        = number
  default     = 22022
}

variable "map_public" {
  description = "Set true to let anyone with the token view the live map. False keeps it to admin_cidr only."
  type        = bool
  default     = false
}

variable "vm_size" {
  description = "VM size. B1s is enough for the honeypot."
  type        = string
  default     = "Standard_B1s"
}

variable "repo_url" {
  description = "Git URL the VM installs Snare from."
  type        = string
  default     = "https://github.com/PrimelPJ/snare.git"
}

variable "maxmind_license_key" {
  description = "Optional free MaxMind key for offline GeoLite2 lookups. Empty uses ip-api.com instead."
  type        = string
  default     = ""
  sensitive   = true
}

variable "home_lat" {
  description = "Where the honeypot sits on the map (defaults to Toronto, close to canadacentral)."
  type        = number
  default     = 43.65
}

variable "home_lon" {
  type    = number
  default = -79.38
}

variable "retention_days" {
  type    = number
  default = 30
}

variable "daily_quota_gb" {
  description = "Hard cap on Log Analytics ingestion per day, to protect your bill."
  type        = number
  default     = 1
}

variable "budget_email" {
  description = "Email for the monthly budget alert. Empty skips the budget."
  type        = string
  default     = ""
}

variable "monthly_budget" {
  description = "Monthly budget in your billing currency."
  type        = number
  default     = 25
}
