module "network_hub" {
  source = "../../../modules/network-hub"

  # =============================================================================
  # BASIC CONFIGURATION
  # =============================================================================
  environment        = var.environment
  region            = var.region
  project_name      = var.project_name
  availability_zones = var.availability_zones

  # =============================================================================
  # VPC CIDR BLOCKS
  # =============================================================================
  transit_gateway_vpc_cidr = var.transit_gateway_vpc_cidr
  firewall_vpc_cidr       = var.firewall_vpc_cidr
  central_egress_vpc_cidr = var.central_egress_vpc_cidr
  client_vpc_cidr         = var.client_vpc_cidr

  # =============================================================================
  # NETWORK SUPERNET CIDRS
  # =============================================================================
  local_supernet_cidr  = var.local_supernet_cidr
  peer_supernet_cidr   = var.peer_supernet_cidr
  evoke_supernet       = var.evoke_supernet

  # =============================================================================
  # TRANSIT GATEWAY VPC SUBNETS
  # =============================================================================
  transit_gateway_subnets = var.transit_gateway_subnets

  # =============================================================================
  # FIREWALL VPC SUBNETS
  # =============================================================================
  firewall_endpoint_subnets = var.firewall_endpoint_subnets
  firewall_tgw_subnets     = var.firewall_tgw_subnets

  # =============================================================================
  # CENTRAL EGRESS VPC SUBNETS
  # =============================================================================
  egress_private_subnets           = var.egress_private_subnets
  egress_public_subnets            = var.egress_public_subnets
  egress_firewall_endpoint_subnets = var.egress_firewall_endpoint_subnets

  # =============================================================================
  # CLIENT VPC SUBNETS
  # =============================================================================
  client_tgw_subnets = var.client_tgw_subnets
  # Note: CDE and NCDE subnets are auto-calculated from client_vpc_cidr

  # =============================================================================
  # FIREWALL CONFIGURATION
  # =============================================================================
  #vpc_cidr                 = var.firewall_vpc_cidr  # Legacy parameter
  environment_ip_rules     = local.environment_ip_rules
  environment_domain_rules = local.environment_domain_rules

  # =============================================================================
  # TEST INSTANCE CONFIGURATION
  # =============================================================================
  enable_test_instances = var.enable_test_instances
  test_instance_type    = var.test_instance_type
  ssh_key_name         = var.ssh_key_name

  # =============================================================================
  # COMMON TAGS
  # =============================================================================
  common_tags = var.common_tags
}