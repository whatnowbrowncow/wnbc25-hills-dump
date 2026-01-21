# ==================================================
# Environment Variables Configuration
# ==================================================
# Variables for the nonprod environment in us-east-1
# These values override module defaults and configure environment-specific settings
# ==================================================

# ==================================================
# BASIC CONFIGURATION
# ==================================================

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "network-hub"
}

variable "availability_zones" {
  description = "List of availability zones for this region"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# ==================================================
# NETWORK SUPERNET CIDRS
# ==================================================

variable "local_supernet_cidr" {
  description = "Local region supernet CIDR block"
  type        = string
  default     = "100.124.0.0/14"
}

variable "peer_supernet_cidr" {
  description = "Peer region supernet CIDR block"
  type        = string
  default     = "100.108.0.0/14"
}

variable "evoke_supernet" {
  description = "CIDR block representing the entire supernet"
  type        = string
  default     = "100.96.0.0/11"
}

# REMOVED: global_supernet_cidr - not used by the module

# ==================================================
# VPC CIDR BLOCKS
# ==================================================

variable "transit_gateway_vpc_cidr" {
  description = "CIDR block for Transit Gateway VPC"
  type        = string
  default     = "100.124.0.0/24"
}

variable "firewall_vpc_cidr" {
  description = "CIDR block for Firewall VPC"
  type        = string
  default     = "100.124.1.0/24"
}

variable "central_egress_vpc_cidr" {
  description = "CIDR block for Central Egress VPC"
  type        = string
  default     = "100.124.2.0/24"
}

variable "client_vpc_cidr" {
  description = "CIDR block for Client VPC"
  type        = string
  default     = "100.124.32.0/19"
}

# ==================================================
# SUBNET CONFIGURATION
# ==================================================
# All subnet variables use auto-calculation from the module's locals.tf
# Override these only if you need custom subnet layouts

variable "transit_gateway_subnets" {
  description = "List of CIDR blocks for Transit Gateway VPC subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "firewall_endpoint_subnets" {
  description = "List of CIDR blocks for Firewall VPC endpoint subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "firewall_tgw_subnets" {
  description = "List of CIDR blocks for Firewall VPC TGW subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_private_subnets" {
  description = "List of CIDR blocks for Central Egress VPC private subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_public_subnets" {
  description = "List of CIDR blocks for Central Egress VPC public subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "egress_firewall_endpoint_subnets" {
  description = "List of CIDR blocks for Central Egress VPC firewall endpoint subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

variable "client_tgw_subnets" {
  description = "List of CIDR blocks for client VPC Transit Gateway attachment subnets (auto-calculated if empty)"
  type        = list(string)
  default     = []
}

# ==================================================
# TEST INSTANCE CONFIGURATION
# ==================================================

variable "enable_test_instances" {
  description = "Enable creation of test instances for network validation"
  type        = bool
  default     = true
}

variable "test_instance_type" {
  description = "EC2 instance type for test instances"
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair for test instances"
  type        = string
  default     = "do_us_test"
}

# ==================================================
# FIREWALL RULES CONFIGURATION
# ==================================================

variable "environment_ip_rules" {
  description = "Environment-specific IP-based firewall rules"
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
  description = "Environment-specific domain allowlist rules"
  type = object({
    allowed_domains = list(string)
  })
  default = {
    allowed_domains = []
  }
}

# ==================================================
# ORGANIZATION CONFIGURATION
# ==================================================

variable "organization_id" {
  description = "AWS Organization ID for RAM sharing"
  type        = string
  default     = "o-kv10f7crlv"
}

# ==================================================
# COMMON TAGS
# ==================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment    = "prod"
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