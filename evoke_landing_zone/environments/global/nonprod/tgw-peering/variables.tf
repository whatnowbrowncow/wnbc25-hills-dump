# ==================================================
# Global TGW Peering Variables
# ==================================================
# Variables for global Transit Gateway peering configuration
# ==================================================

# ==================================================
# NETWORK CONFIGURATION
# ==================================================

variable "local_cidr_block" {
  description = "EU West 1 region supernet CIDR block"
  type        = string
  default     = "100.104.0.0/14"
  
  validation {
    condition     = can(cidrhost(var.local_cidr_block, 0))
    error_message = "Local CIDR block must be a valid CIDR notation."
  }
}

variable "peer_cidr_block" {
  description = "US East 1 region supernet CIDR block"
  type        = string
  default     = "100.120.0.0/14"
  
  validation {
    condition     = can(cidrhost(var.peer_cidr_block, 0))
    error_message = "Peer CIDR block must be a valid CIDR notation."
  }
}
variable "local_region" {
  description = "Local AWS region (EU West 1)"
  type        = string
  default     = "eu-west-1"
}

variable "peer_region" {
  description = "Peer AWS region (US East 1)"
  type        = string
  default     = "us-east-1"
}