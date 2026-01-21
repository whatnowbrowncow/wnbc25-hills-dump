# ==================================================
# DATA SOURCES
# ==================================================

# Get current AWS account information
data "aws_caller_identity" "current" {}

# Remote state from EU West 1 region
data "terraform_remote_state" "eu_west" {
  backend = "local"
  config = {
    path = "../../../eu-west-1/nonprod/terraform.tfstate"
  }
}

# Remote state from US East 1 region
data "terraform_remote_state" "us_east" {
  backend = "local"
  config = {
    path = "../../../us-east-1/nonprod/terraform.tfstate"
  }
}

# ==================================================
# LOCAL VALUES
# ==================================================

locals {
  # Project configuration
  project_name = "network-hub"  # Updated from "evoke" to match your network-hub module
  environment  = "nonprod"
  
  # Network configuration
  eu_west_supernet = var.local_cidr_block   # EU West 1 supernet
  us_east_supernet = var.peer_cidr_block    # US East 1 supernet
  
  # Common tags for all resources
  common_tags = {
    Environment = local.environment
    Project     = local.project_name
    ManagedBy   = "OpenTofu"
    Type        = "tgw-peering"
    Purpose     = "cross-region-connectivity"
  }
  
  # Remote state data validation
  eu_west_tgw_id = data.terraform_remote_state.eu_west.outputs.transit_gateway_id
  us_east_tgw_id = data.terraform_remote_state.us_east.outputs.transit_gateway_id
  
  eu_west_route_table_id = data.terraform_remote_state.eu_west.outputs.tgw_route_table_ids.main
  us_east_route_table_id = data.terraform_remote_state.us_east.outputs.tgw_route_table_ids.main
}

# ==================================================
# TRANSIT GATEWAY PEERING
# ==================================================

module "tgw_peering_eu_to_us" {
  source = "../../../../modules/tgw-peering"
  
  providers = {
    aws.local = aws.local  # EU West 1
    aws.peer  = aws.peer   # US East 1
  }
  
  # Basic configuration
  project_name = local.project_name
  environment  = local.environment
  common_tags  = local.common_tags
  
  # Transit Gateway configuration
  local_tgw_id         = local.eu_west_tgw_id
  peer_tgw_id          = local.us_east_tgw_id
  local_route_table_id = local.eu_west_route_table_id
  peer_route_table_id  = local.us_east_route_table_id
  
  # Regional configuration
  local_region    = "eu-west-1"
  peer_region     = "us-east-1"
  peer_account_id = data.aws_caller_identity.current.account_id
  
  # Network configuration
  local_cidr_block = local.eu_west_supernet
  peer_cidr_block  = local.us_east_supernet
}