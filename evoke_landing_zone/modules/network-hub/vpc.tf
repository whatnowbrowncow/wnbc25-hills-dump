# vpc.tf
# Organized by dependency order: Data Sources → VPCs → Default Resources

# ==================================================
# DATA SOURCES
# ==================================================
# Data sources first - no dependencies

data "aws_availability_zones" "available" {
  state = "available"
}

# ==================================================
# VPC RESOURCES
# ==================================================
# Core VPCs that form the hub-and-spoke network architecture

# ------------------------------------------------------
# Firewall VPC
# ------------------------------------------------------
# Dedicated VPC for AWS Network Firewall
# All inter-VPC traffic is inspected here for security

resource "aws_vpc" "firewall" {
  cidr_block           = local.vpc_configs.firewall.cidr_block
  enable_dns_hostnames = local.vpc_defaults.enable_dns_hostnames
  enable_dns_support   = local.vpc_defaults.enable_dns_support

  tags = merge(var.common_tags, {
    Name    = local.vpc_configs.firewall.name
    Type    = local.vpc_configs.firewall.type
    Purpose = local.vpc_configs.firewall.purpose
  })
}

# ------------------------------------------------------
# Central Egress VPC
# ------------------------------------------------------
# Centralized internet egress and ingress point
# Hosts NAT Gateways and internet-facing load balancers

resource "aws_vpc" "central_egress" {
  cidr_block           = local.vpc_configs.central_egress.cidr_block
  enable_dns_hostnames = local.vpc_defaults.enable_dns_hostnames
  enable_dns_support   = local.vpc_defaults.enable_dns_support

  tags = merge(var.common_tags, {
    Name    = local.vpc_configs.central_egress.name
    Type    = local.vpc_configs.central_egress.type
    Purpose = local.vpc_configs.central_egress.purpose
  })
}

# ==================================================
# DEFAULT ROUTE TABLES
# ==================================================
# Tag default route tables for better identification and management
# These are automatically created by AWS but we name them for clarity

resource "aws_default_route_table" "firewall_main" {
  default_route_table_id = aws_vpc.firewall.default_route_table_id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-firewall-vpc-main-rt"
    Type = "main-route-table"
    VPC  = "firewall"
  })
}

resource "aws_default_route_table" "central_egress_main" {
  default_route_table_id = aws_vpc.central_egress.default_route_table_id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-vpc-main-rt"
    Type = "main-route-table"
    VPC  = "central-egress"
  })
}