# main.tf - Development Environment
# Network Hub module deployment for dev in eu-west-1

# ==================================================
# DATA SOURCES
# ==================================================

data "aws_caller_identity" "current" {}

# ==================================================
# NETWORK HUB MODULE
# ==================================================

module "network_hub" {
  source = "../../../modules/network-hub"

  # =============================================================================
  # CORE CONFIGURATION
  # =============================================================================
  environment        = var.environment
  region            = var.region
  project_name      = var.project_name
  availability_zones = var.availability_zones
  common_tags       = var.common_tags

  # =============================================================================
  # NETWORK ARCHITECTURE
  # =============================================================================
  
  # ------------------------------------------------------
  # VPC CIDR Blocks
  # ------------------------------------------------------
  firewall_vpc_cidr       = var.firewall_vpc_cidr
  central_egress_vpc_cidr = var.central_egress_vpc_cidr

  # ------------------------------------------------------
  # Supernet CIDR Blocks
  # ------------------------------------------------------
  local_supernet_cidr    = var.local_supernet_cidr
  peer_supernet_cidr     = var.peer_supernet_cidr
  evoke_supernet         = var.evoke_supernet
  dev_supernet_cidr      = var.dev_supernet_cidr
  nonprod_supernet_cidr  = var.nonprod_supernet_cidr
  prod_supernet_cidr     = var.prod_supernet_cidr

  # =============================================================================
  # SUBNET CONFIGURATION
  # =============================================================================
  
  # ------------------------------------------------------
  # Firewall VPC Subnets
  # ------------------------------------------------------
  firewall_endpoint_subnets = var.firewall_endpoint_subnets
  firewall_tgw_subnets     = var.firewall_tgw_subnets

  # ------------------------------------------------------
  # Central Egress VPC Subnets
  # ------------------------------------------------------
  egress_public_subnets  = var.egress_public_subnets
  egress_private_subnets = var.egress_private_subnets

  # =============================================================================
  # SECURITY CONFIGURATION
  # =============================================================================
  environment_ip_rules     = local.environment_ip_rules
  environment_domain_rules = local.environment_domain_rules

  # =============================================================================
  # TRANSIT GATEWAY PEERING CONFIGURATION
  # =============================================================================
  # Development initiates peering to both nonprod and prod environments
  
  # ------------------------------------------------------
  # Peering Feature Flags
  # ------------------------------------------------------
  enable_dev_nonprod_peering  = var.enable_dev_nonprod_peering  # Dev → Nonprod
  enable_dev_prod_peering     = var.enable_dev_prod_peering     # Dev → Prod
  enable_nonprod_prod_peering = false                           # Not used by dev
}