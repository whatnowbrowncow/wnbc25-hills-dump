# variables.tf
# Organized by logical groupings with consistent ordering and improved descriptions

# ==================================================
# CORE PROJECT VARIABLES
# ==================================================
# Foundational variables that define the deployment context

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, nonprod, prod)"
  type        = string
}

variable "region" {
  description = "AWS region for resource deployment"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones to use for multi-AZ deployments"
  type        = list(string)
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
}

# ==================================================
# AWS ORGANIZATION CONFIGURATION
# ==================================================
# AWS Organization settings for cross-account access

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
  default     = "o-kv10f7crlv"
}

variable "organization_management_account_id" {
  description = "AWS Organization management account ID"
  type        = string
  default     = "703671905140"
}

# ==================================================
# VPC NETWORK CONFIGURATION
# ==================================================
# Primary VPC CIDR blocks for the hub-and-spoke architecture

variable "firewall_vpc_cidr" {
  description = "CIDR block for Firewall VPC (centralized security inspection)"
  type        = string
}

variable "central_egress_vpc_cidr" {
  description = "CIDR block for Central Egress VPC (internet gateway hub)"
  type        = string
}

# ==================================================
# SUBNET CONFIGURATION
# ==================================================
# Subnet CIDR blocks organized by VPC and purpose

# ------------------------------------------------------
# Firewall VPC Subnets  
# ------------------------------------------------------
variable "firewall_endpoint_subnets" {
  description = "List of Firewall endpoint subnet CIDRs for Network Firewall"
  type        = list(string)
}

variable "firewall_tgw_subnets" {
  description = "List of Firewall TGW subnet CIDRs for Transit Gateway attachments"
  type        = list(string)
}

# ------------------------------------------------------
# Central Egress VPC Subnets
# ------------------------------------------------------
variable "egress_public_subnets" {
  description = "List of Egress public subnet CIDRs for internet-facing resources"
  type        = list(string)
}

variable "egress_private_subnets" {
  description = "List of Egress private subnet CIDRs for NAT Gateway traffic"
  type        = list(string)
}

variable "egress_firewall_endpoint_subnets" {
  description = "List of Central Egress VPC firewall endpoint subnet CIDRs (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

# ==================================================
# NETWORK ROUTING CONFIGURATION
# ==================================================
# Supernet CIDR blocks for routing and peering

variable "local_supernet_cidr" {
  description = "Local region supernet CIDR block (e.g., 100.104.0.0/14)"
  type        = string
}

variable "peer_supernet_cidr" {
  description = "Peer region supernet CIDR block (e.g., 100.120.0.0/14)" 
  type        = string
}

variable "evoke_supernet" {
  description = "Evoke supernet CIDR block for external connectivity"
  type        = string
}

# ==================================================
# SECURITY CONFIGURATION
# ==================================================
# Firewall rules and security policies

variable "environment_ip_rules" {
  description = "Environment-specific IP-based firewall rules (supplements global rules)"
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
  
  validation {
    condition = alltrue([
      for rule in var.environment_ip_rules : contains(["PASS", "DROP"], rule.action)
    ])
    error_message = "Rule action must be either 'PASS' or 'DROP'."
  }
}

variable "environment_domain_rules" {
  description = "Environment-specific domain-based firewall rules"
  type = object({
    allowed_domains = list(string)
    blocked_domains = optional(list(string), [])
  })
  default = {
    allowed_domains = []
    blocked_domains = []
  }
}

# ==================================================
# TRANSIT GATEWAY PEERING CONFIGURATION
# ==================================================
# Cross-environment and cross-account peering settings

# ------------------------------------------------------
# General Peering Settings
# ------------------------------------------------------
variable "enable_peering" {
  description = "Enable Transit Gateway peering functionality"
  type        = bool
  default     = false
}

variable "is_peering_initiator" {
  description = "Whether this environment initiates TGW peering connections"
  type        = bool
  default     = false
}

# ------------------------------------------------------
# Production Environment Peering
# ------------------------------------------------------
variable "prod_account_id" {
  description = "Production account ID for cross-account peering"
  type        = string
  default     = ""
}

variable "prod_tgw_id" {
  description = "Production Transit Gateway ID for peering attachment"
  type        = string
  default     = ""
}

variable "prod_supernet_cidr" {
  description = "Production environment supernet CIDR block"
  type        = string
  default     = ""
}

variable "prod_route_table_id" {
  description = "Production Transit Gateway route table ID"
  type        = string
  default     = ""
}

# ------------------------------------------------------
# Non-Production Environment Peering
# ------------------------------------------------------
variable "nonprod_account_id" {
  description = "Non-production account ID for cross-account peering"
  type        = string
  default     = ""
}

variable "nonprod_tgw_id" {
  description = "Non-production Transit Gateway ID for peering attachment"
  type        = string
  default     = ""
}

variable "nonprod_supernet_cidr" {
  description = "Non-production environment supernet CIDR block"
  type        = string
  default     = ""
}

variable "nonprod_route_table_id" {
  description = "Non-production Transit Gateway route table ID"
  type        = string
  default     = ""
}

# ------------------------------------------------------
# Development Environment Peering
# ------------------------------------------------------
variable "dev_supernet_cidr" {
  description = "Development environment supernet CIDR block"
  type        = string
  default     = ""
}

variable "dev_tgw_id" {
  description = "Non-production Transit Gateway ID for peering attachment"
  type        = string
  default     = ""
}

# ------------------------------------------------------
# Peering Feature Toggles
# ------------------------------------------------------
variable "enable_dev_nonprod_peering" {
  description = "Enable peering between dev and nonprod environments"
  type        = bool
  default     = false
}

variable "enable_dev_prod_peering" {
  description = "Enable peering between dev and prod environments"
  type        = bool
  default     = true
}

variable "enable_nonprod_prod_peering" {
  description = "Enable peering between nonprod and prod environments"
  type        = bool
  default     = false
}

variable "dev_to_prod_peering_attachment_id" {
  description = "Dev to Prod peering attachment ID (from remote state or manual)"
  type        = string
  default     = ""
}

# Variables to control whether dev/nonprod are active yet

variable "enable_dev_environment" {
  description = "Enable dev environment resources"
  type        = bool
  default     = false
}

variable "enable_nonprod_environment" {
  description = "Enable nonprod environment resources"
  type        = bool
  default     = false
}

variable "enable_prod_environment" {
  description = "Enable prod environment resources"
  type        = bool
  default     = true
}