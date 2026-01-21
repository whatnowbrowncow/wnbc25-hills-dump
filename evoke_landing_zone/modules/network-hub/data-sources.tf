# modules/network-hub/data-sources.tf

# Get current account ID
data "aws_caller_identity" "current" {}

# Get organization details for validation
data "aws_organizations_organization" "current" {}

# Discover TGWs by searching for each expected owner account
# Only lookup if we need to peer with that environment

data "aws_ec2_transit_gateway" "dev" {
  count = var.environment != "dev" && (
    var.enable_dev_nonprod_peering || 
    var.enable_dev_prod_peering
  ) ? 1 : 0
  
  filter {
    name   = "owner-id"
    values = [local.environment_to_account["dev"]]
  }
  
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ec2_transit_gateway" "nonprod" {
  count = var.environment != "nonprod" && (
    var.enable_dev_nonprod_peering || 
    var.enable_nonprod_prod_peering
  ) ? 1 : 0
  
  filter {
    name   = "owner-id"
    values = [local.environment_to_account["nonprod"]]
  }
  
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ec2_transit_gateway" "prod" {
  count = var.environment != "prod" && (
    var.enable_dev_prod_peering || 
    var.enable_nonprod_prod_peering
  ) ? 1 : 0
  
  filter {
    name   = "owner-id"
    values = [local.environment_to_account["prod"]]
  }
  
  filter {
    name   = "state"
    values = ["available"]
  }
}