# main.tf - Non-Production Environment
# Network Hub module deployment for nonprod in eu-west-1

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
  transit_gateway_vpc_cidr = var.transit_gateway_vpc_cidr
  firewall_vpc_cidr       = var.firewall_vpc_cidr
  central_egress_vpc_cidr = var.central_egress_vpc_cidr
  client_vpc_cidr         = var.client_vpc_cidr

  # ------------------------------------------------------
  # Supernet CIDR Blocks
  # ------------------------------------------------------
  local_supernet_cidr    = var.local_supernet_cidr
  peer_supernet_cidr     = var.peer_supernet_cidr
  evoke_supernet         = var.evoke_supernet
  nonprod_supernet_cidr  = var.nonprod_supernet_cidr
  prod_supernet_cidr     = var.prod_supernet_cidr
  dev_supernet_cidr      = var.dev_supernet_cidr

  # =============================================================================
  # SUBNET CONFIGURATION
  # =============================================================================
  
  # ------------------------------------------------------
  # Transit Gateway VPC Subnets
  # ------------------------------------------------------
  transit_gateway_subnets = var.transit_gateway_subnets

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

  # ------------------------------------------------------
  # Client VPC Subnets
  # ------------------------------------------------------
  client_tgw_subnets = var.client_tgw_subnets
  # Note: CDE and NCDE subnets are auto-calculated from client_vpc_cidr

  # =============================================================================
  # SECURITY CONFIGURATION
  # =============================================================================
  environment_ip_rules     = local.environment_ip_rules
  environment_domain_rules = local.environment_domain_rules

  # =============================================================================
  # TESTING CONFIGURATION
  # =============================================================================
  #enable_test_instances = var.enable_test_instances
  #test_instance_type    = var.test_instance_type
  #ssh_key_name         = var.ssh_key_name

  # =============================================================================
  # TRANSIT GATEWAY PEERING CONFIGURATION
  # =============================================================================
  # Non-production can initiate peering to production and accept from dev
  
  enable_peering       = var.enable_peering        # true - enable peering
  is_peering_initiator = var.is_peering_initiator  # true - nonprod initiates to prod
  
  # ------------------------------------------------------
  # Production Environment (Peering Target)
  # ------------------------------------------------------
  #prod_account_id = var.prod_account_id
  #prod_tgw_id     = var.prod_tgw_id
  
  # ------------------------------------------------------
  # Peering Feature Flags
  # ------------------------------------------------------
  enable_dev_nonprod_peering  = true  # Accept dev → nonprod
  enable_nonprod_prod_peering = true                            # Create nonprod → prod
  enable_dev_prod_peering     = false                           # Not used by nonprod
  enable_nonprod_environment = true
}