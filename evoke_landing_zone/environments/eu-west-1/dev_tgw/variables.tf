# variables.tf - Development Environment Configuration
# Environment-specific variable overrides for dev in eu-west-1
# These values override module defaults and configure development-specific settings

# ==================================================
# CORE ENVIRONMENT CONFIGURATION
# ==================================================

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "region" {
  description = "AWS region for development deployment"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "network-hub"
}

variable "availability_zones" {
  description = "Availability zones for multi-AZ deployment in eu-west-1"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

variable "common_tags" {
  description = "Common tags applied to all development resources"
  type        = map(string)
  default = {
    Environment    = "dev"
    Project        = "network-hub"
    ManagedBy      = "OpenTofu"
    Product        = "network-hub"
    Classification = "nonpublic"
    CardData       = "no"
    Migrated       = "no"
    Tier           = "internal"
    GitURL         = "https://gitlab.com/williamhillplc/technical-services/networks/channels-team.git"
  }
}

# ==================================================
# NETWORK ARCHITECTURE CONFIGURATION
# ==================================================

# ------------------------------------------------------
# Supernet CIDR Blocks
# ------------------------------------------------------

variable "local_supernet_cidr" {
  description = "Development region supernet CIDR block"
  type        = string
  default     = "100.96.0.0/14"
}

variable "peer_supernet_cidr" {
  description = "Peer region supernet CIDR block for cross-region connectivity"
  type        = string
  default     = "100.112.0.0/14"
}

variable "evoke_supernet" {
  description = "Complete Evoke supernet CIDR block for blackhole routing"
  type        = string
  default     = "100.96.0.0/11"
}

# ------------------------------------------------------
# Environment-Specific Supernet CIDRs
# ------------------------------------------------------

variable "dev_supernet_cidr" {
  description = "Development environment supernet CIDR block"
  type        = string
  default     = "100.96.0.0/14"
}

variable "nonprod_supernet_cidr" {
  description = "Non-production environment supernet CIDR block"
  type        = string
  default     = "100.104.0.0/14"
}

variable "prod_supernet_cidr" {
  description = "Production environment supernet CIDR block"
  type        = string
  default     = "100.108.0.0/14"
}

# ==================================================
# VPC CIDR CONFIGURATION
# ==================================================

variable "transit_gateway_vpc_cidr" {
  description = "CIDR block for Transit Gateway VPC (management and access)"
  type        = string
  default     = "100.96.0.0/24"
}

variable "firewall_vpc_cidr" {
  description = "CIDR block for Firewall VPC (security inspection)"
  type        = string
  default     = "100.96.1.0/24"
}

variable "central_egress_vpc_cidr" {
  description = "CIDR block for Central Egress VPC (internet gateway)"
  type        = string
  default     = "100.96.2.0/24"
}

variable "client_vpc_cidr" {
  description = "CIDR block for Client VPC (application workloads)"
  type        = string
  default     = "100.96.32.0/19"
}

# ==================================================
# SUBNET CONFIGURATION
# ==================================================
# Auto-calculated subnet CIDRs - override only if custom layouts needed

variable "transit_gateway_subnets" {
  description = "Transit Gateway VPC subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "firewall_endpoint_subnets" {
  description = "Firewall VPC endpoint subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "firewall_tgw_subnets" {
  description = "Firewall VPC TGW attachment subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_public_subnets" {
  description = "Central Egress VPC public subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_private_subnets" {
  description = "Central Egress VPC private subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_firewall_endpoint_subnets" {
  description = "Central Egress VPC firewall endpoint subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "client_tgw_subnets" {
  description = "Client VPC Transit Gateway attachment subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

# ==================================================
# SECURITY CONFIGURATION
# ==================================================

variable "environment_ip_rules" {
  description = "Development-specific IP-based firewall rules"
  type = list(object({
    name        = string
    action      = string # "PASS" or "DROP"
    protocol    = string # "TCP", "UDP", "ICMP", "IP"
    source      = string
    destination = string
    port        = string
    description = string
  }))
  default = []
}

variable "environment_domain_rules" {
  description = "Development-specific domain allowlist rules"
  type = object({
    allowed_domains = list(string)
  })
  default = {
    allowed_domains = []
  }
}

# ==================================================
# ORGANIZATIONAL CONFIGURATION
# ==================================================

variable "organization_id" {
  description = "AWS Organization ID for RAM sharing and cross-account access"
  type        = string
  default     = "o-kv10f7crlv"
}

# ==================================================
# TRANSIT GATEWAY PEERING CONFIGURATION
# ==================================================
# Development initiates peering to both nonprod and prod

variable "enable_peering" {
  description = "Enable Transit Gateway peering (dev initiates connections)"
  type        = bool
  default     = true
}

variable "is_peering_initiator" {
  description = "Whether this environment initiates peering (true for dev)"
  type        = bool
  default     = true
}

# ------------------------------------------------------
# Production Environment Peering
# ------------------------------------------------------

#variable "prod_account_id" {
#  description = "Production account ID for peering target"
#  type        = string
#  default     = "492597629650"
#}

#variable "prod_tgw_id" {
#  description = "Production Transit Gateway ID for peering target"
#  type        = string
#  default     = "tgw-02c5191990d7b5c7e"
#}

#variable "prod_route_table_id" {
#  description = "Production Transit Gateway route table ID"
#  type        = string
#  default     = "tgw-rtb-033bf73a679c656a3"
#}

variable "enable_dev_prod_peering" {
  description = "Enable peering between dev and prod environments"
  type        = bool
  default     = true
}

# ------------------------------------------------------
# Non-Production Environment Peering
# ------------------------------------------------------

#variable "nonprod_account_id" {
#  description = "Non-production account ID for peering target"
#  type        = string
#  default     = "052127203460"
#}

#variable "nonprod_tgw_id" {
#  description = "Non-production Transit Gateway ID for peering target"
#  type        = string
#  default     = "tgw-0807d14a2e1a987fb"
#}

#variable "nonprod_route_table_id" {
#  description = "Non-production Transit Gateway route table ID"
#  type        = string
#  default     = "tgw-rtb-0fe9e5edcf51d6aeb"
#}

variable "enable_dev_nonprod_peering" {
  description = "Enable peering between dev and non-prod environments"
  type        = bool
  default     = true
}

# ------------------------------------------------------
# Peering Feature Flags (Not Used by Dev Directly)
# ------------------------------------------------------

variable "enable_nonprod_prod_peering" {
  description = "Enable nonprod to prod peering (not used by dev, but module may expect it)"
  type        = bool
  default     = false
}