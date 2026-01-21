# ==================================================
# Local Values Configuration
# ==================================================
# This file contains all local value definitions for the network-hub module
# Organized by functional area for better maintainability
# ==================================================

# ==================================================
# AVAILABILITY ZONES AND NAMING
# ==================================================

locals {
  # Use specified AZs or default to first 3 available AZs
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 3)
  
  # Helper for AZ short names (e.g., "us-east-1a" -> "1a")
  az_short_names = [
    for az in local.azs : substr(az, -2, 2)
  ]
}

# ==================================================
# VPC CONFIGURATION
# ==================================================

locals {
  # VPC configuration map for consistent settings
  vpc_configs = {
    firewall = {
      cidr_block = var.firewall_vpc_cidr
      name       = "${var.project_name}-${var.environment}-firewall-vpc"
      type       = "firewall"
      purpose    = "Network security and traffic inspection"
    }
    central_egress = {
      cidr_block = var.central_egress_vpc_cidr
      name       = "${var.project_name}-${var.environment}-egress-vpc"
      type       = "central-egress"
      purpose    = "Centralized internet connectivity"
    }
  }
  
  # Common VPC settings
  vpc_defaults = {
    enable_dns_hostnames = true
    enable_dns_support   = true
  }
}

locals {
  # FIREWALL VPC CALCULATION (/24 -> /28)
  # Create multiple /28 subnets from the /24 VPC CIDR
  all_firewall_subnets = cidrsubnets(
    var.firewall_vpc_cidr,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
  )
  # Positions 0-2 for firewall endpoints, 3-5 for TGW subnets
  firewall_endpoint_subnets = length(var.firewall_endpoint_subnets) > 0 ? var.firewall_endpoint_subnets : slice(local.all_firewall_subnets, 0, 3)
  firewall_tgw_subnets      = length(var.firewall_tgw_subnets) > 0 ? var.firewall_tgw_subnets : slice(local.all_firewall_subnets, 3, 6)
}

locals {
  # CENTRAL EGRESS VPC CALCULATION (/24 -> /28)
  # Create multiple /28 subnets from the /24 VPC CIDR
  all_egress_subnets = cidrsubnets(
    var.central_egress_vpc_cidr,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
  )
  # Positions 0-2 for private, 3-5 for public, 6-8 for firewall endpoints
  egress_private_subnets           = length(var.egress_private_subnets) > 0 ? var.egress_private_subnets : slice(local.all_egress_subnets, 0, 3)
  egress_public_subnets            = length(var.egress_public_subnets) > 0 ? var.egress_public_subnets : slice(local.all_egress_subnets, 3, 6)
  egress_firewall_endpoint_subnets = length(var.egress_firewall_endpoint_subnets) > 0 ? var.egress_firewall_endpoint_subnets : slice(local.all_egress_subnets, 6, 9)
}

# ==================================================
# FIREWALL CONFIGURATION
# ==================================================

locals {
  # Firewall naming
  firewall_policy_name = "${var.project_name}-${var.environment}-firewall-policy"
  firewall_name        = "${var.project_name}-${var.environment}-network-firewall"

  # Rule group references with priorities (lower numbers = higher precedence)
  rule_group_references = [
    {
      name        = "domain-allowlist"
      arn         = try(aws_networkfirewall_rule_group.domain_allowlist[0].arn, null)
      priority    = 100
      description = "Domain allowlist rules (highest priority)"
    },
    {
      name        = "ip-rules"
      arn         = try(aws_networkfirewall_rule_group.ip_rules[0].arn, null)
      priority    = 300
      description = "IP-based access control rules"
    }
  ]

  # Filter out null ARNs (rule groups that weren't created)
  active_rule_groups = [
    for rule_group in local.rule_group_references : rule_group
    if rule_group.arn != null
  ]

  # VPC endpoint mapping for egress firewall endpoints
  egress_vpce_by_az = { 
    for idx in range(length(toset(local.egress_firewall_endpoint_subnets))) : 
    var.availability_zones[idx] => data.aws_vpc_endpoint.firewall[tostring(idx)].id 
  }
}

# ==================================================
# INTERNET CONNECTIVITY
# ==================================================

locals {
  # Gateway naming conventions
  egress_igw_name = "${var.project_name}-${var.environment}-egress-igw"
  tgw_igw_name    = "${var.project_name}-${var.environment}-tgw-igw"
  
  # NAT Gateway configuration
  nat_gateway_count = length(local.azs)
}

# ==================================================
# TRANSIT GATEWAY CONFIGURATION
# ==================================================

locals {
  # Transit Gateway naming
  tgw_name              = "${var.project_name}-${var.environment}-tgw"
  main_route_table_name = "${var.project_name}-${var.environment}-tgw-rt-main"
  #gitlab_runner_rout_table_name = "${var.project_name}-${var.environment}-gitlab-runner-a-tgw-rt"
  
  # VPC attachment configurations
  vpc_attachments = {
    central_egress = {
      name        = "egress-vpc"
      vpc_id      = aws_vpc.central_egress.id
      subnet_ids  = aws_subnet.egress_private[*].id
      description = "Central Egress VPC attachment for internet connectivity"
    }
  }
}

# ==================================================
# RAM SHARING CONFIGURATION
# ==================================================

locals {
  # RAM share configuration
  share_name       = "${var.project_name}-${var.environment}-tgw-share"
  organization_arn = "arn:aws:organizations::${data.aws_caller_identity.current.account_id}:organization/${var.organization_id}"
  
  # Control whether to share with organization
  enable_organization_sharing = true
}


# Allows dynamic naming of TGWs across accounts

locals {
  # Static mapping - source of truth
  account_to_environment = {
    "776564762201" = "dev"
    "559413642457" = "nonprod"
    "131778591898" = "prod"
  }
  
  environment_to_account = {
    "dev"     = "776564762201"
    "nonprod" = "559413642457"
    "prod"    = "131778591898"
  }
  
  # TGW IDs - use the created resource for current account, lookup for others
  tgw_ids = {
    "dev" = var.environment == "dev" ? aws_ec2_transit_gateway.main.id : (
      var.enable_dev_nonprod_peering || var.enable_dev_prod_peering ? 
      try(data.aws_ec2_transit_gateway.dev[0].id, "") : ""
    )
    
    "nonprod" = var.environment == "nonprod" ? aws_ec2_transit_gateway.main.id : (
      var.enable_dev_nonprod_peering || var.enable_nonprod_prod_peering ? 
      try(data.aws_ec2_transit_gateway.nonprod[0].id, "") : ""
    )
    
    "prod" = var.environment == "prod" ? aws_ec2_transit_gateway.main.id : (
      var.enable_dev_prod_peering || var.enable_nonprod_prod_peering ? 
      try(data.aws_ec2_transit_gateway.prod[0].id, "") : ""
    )
  }
}
