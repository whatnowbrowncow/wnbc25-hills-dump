# ==================================================
# main.tf
# ==================================================

# Get account information
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Get network hub information from remote state
data "terraform_remote_state" "network_hub" {
  backend = "local" # Change to your backend type
  config = {
    path = "../prod_tgw/terraform.tfstate" # Path to network-hub state
  }
}


# ==================================================
# CLIENT VPC MODULE
# ==================================================

module "client_vpc" {
  source = "../../../modules/client-vpc"
  
  # Basic configuration
  project_name    = var.project_name
  account_name    = var.account_name
  environment     = var.environment
  region          = var.region
  
  # Network configuration - from Infoblox allocation
  vpc_cidr = var.vpc_cidr
  
  # Subnet configuration - from Infoblox allocation
  cde_subnets  = var.cde_subnets
  ncde_subnets = var.ncde_subnets
  tgw_subnets  = var.tgw_subnets
  
  # Network hub integration
  transit_gateway_id = data.terraform_remote_state.network_hub.outputs.transit_gateway_id
  
  # Availability zones
  availability_zones = var.availability_zones
  
  # Test instance configuration
  enable_test_instance = var.enable_test_instance
  test_instance_type   = var.test_instance_type
  ssh_key_name         = var.ssh_key_name
  
  # Tags
  common_tags = var.common_tags
}
