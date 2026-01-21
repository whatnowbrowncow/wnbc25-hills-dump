# variables.tf - Non-Production Environment Configuration
# Environment-specific variable overrides for nonprod in eu-west-1
# These values override module defaults and configure non-production-specific settings

# ==================================================
# CORE ENVIRONMENT CONFIGURATION
# ==================================================

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "nonprod"
}

variable "region" {
  description = "AWS region for non-production deployment"
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
  description = "Common tags applied to all non-production resources"
  type        = map(string)
  default = {
    Environment    = "nonprod"
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
  description = "Non-production region supernet CIDR block"
  type        = string
  default     = "100.104.0.0/14"
}

variable "peer_supernet_cidr" {
  description = "Peer region supernet CIDR block for cross-region connectivity"
  type        = string
  default     = "100.120.0.0/14"
}

variable "evoke_supernet" {
  description = "Complete Evoke supernet CIDR block for blackhole routing"
  type        = string
  default     = "100.96.0.0/11"
}

# ------------------------------------------------------
# Environment-Specific Supernet CIDRs
# ------------------------------------------------------

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

variable "dev_supernet_cidr" {
  description = "Development environment supernet CIDR block"
  type        = string
  default     = "100.96.0.0/14"
}

# ==================================================
# VPC CIDR CONFIGURATION
# ==================================================

variable "transit_gateway_vpc_cidr" {
  description = "CIDR block for Transit Gateway VPC (management and access)"
  type        = string
  default     = "100.104.0.0/24"
}

variable "firewall_vpc_cidr" {
  description = "CIDR block for Firewall VPC (security inspection)"
  type        = string
  default     = "100.104.1.0/24"
}

variable "central_egress_vpc_cidr" {
  description = "CIDR block for Central Egress VPC (internet gateway)"
  type        = string
  default     = "100.104.2.0/24"
}

variable "client_vpc_cidr" {
  description = "CIDR block for Client VPC (application workloads)"
  type        = string
  default     = "100.104.32.0/19"
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
  description = "Non-production-specific IP-based firewall rules"
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
  description = "Non-production-specific domain allowlist rules"
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
# TESTING AND DEVELOPMENT CONFIGURATION
# ==================================================

variable "enable_test_instances" {
  description = "Deploy test instances for network validation in non-production"
  type        = bool
  default     = true
}

variable "test_instance_type" {
  description = "EC2 instance type for non-production test instances"
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "SSH key pair name for test instance access"
  type        = string
  default     = "eu_west_1_nonprod_tgw"
}

# ==================================================
# TRANSIT GATEWAY PEERING CONFIGURATION
# ==================================================
# Non-production can initiate peering to production

variable "enable_peering" {
  description = "Enable Transit Gateway peering (nonprod can initiate to prod)"
  type        = bool
  default     = true
}

variable "is_peering_initiator" {
  description = "Whether this environment initiates peering (true for nonprod to prod)"
  type        = bool
  default     = true
}

# ------------------------------------------------------
# Non-Production Environment Settings (Self-Reference)
# ------------------------------------------------------

#variable "nonprod_account_id" {
#  description = "Non-production account ID"
#  type        = string
#  default     = "052127203460"
#}

#variable "nonprod_tgw_id" {
#  description = "Non-production Transit Gateway ID"
#  type        = string
#  default     = "tgw-0807d14a2e1a987fb"
#}

# ------------------------------------------------------
# Production Environment Settings (For Peering Target)
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
