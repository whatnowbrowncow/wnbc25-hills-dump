# ==================================================
# FIREWALL VPC SUBNETS
# ==================================================
# Subnets for AWS Network Firewall components

# ------------------------------------------------------
# Firewall Endpoint Subnets
# ------------------------------------------------------
# Host the Network Firewall endpoints that inspect traffic

resource "aws_subnet" "firewall_endpoint" {
  count = length(local.firewall_endpoint_subnets)

  # Basic configuration
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = local.firewall_endpoint_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-fw-endpoint-subnet-${local.az_short_names[count.index]}"
    Type = "firewall-endpoint"
    AZ   = local.azs[count.index]
    VPC  = "firewall"
  })
}

# ------------------------------------------------------
# Firewall Transit Gateway Subnets
# ------------------------------------------------------
# Connect the Firewall VPC to Transit Gateway for traffic routing

resource "aws_subnet" "firewall_tgw" {
  count = length(local.firewall_tgw_subnets)

  # Basic configuration
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = local.firewall_tgw_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-fw-tgw-subnet-${local.az_short_names[count.index]}"
    Type = "firewall-tgw"
    AZ   = local.azs[count.index]
    VPC  = "firewall"
  })
}

# ==================================================
# CENTRAL EGRESS VPC SUBNETS
# ==================================================
# Subnets for centralized internet egress and ingress

# ------------------------------------------------------
# Private Subnets
# ------------------------------------------------------
# Host private resources that need internet access via NAT Gateway

resource "aws_subnet" "egress_private" {
  count = length(local.egress_private_subnets)

  # Basic configuration
  vpc_id            = aws_vpc.central_egress.id
  cidr_block        = local.egress_private_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-private-subnet-${local.az_short_names[count.index]}"
    Type = "egress-private"
    AZ   = local.azs[count.index]
    VPC  = "central-egress"
  })
}

# ------------------------------------------------------
# Public Subnets
# ------------------------------------------------------
# Host public resources like NAT Gateways and Load Balancers
# Resources in these subnets get public IP addresses automatically

resource "aws_subnet" "egress_public" {
  count = length(local.egress_public_subnets)

  # Basic configuration
  vpc_id                  = aws_vpc.central_egress.id
  cidr_block              = local.egress_public_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-public-subnet-${local.az_short_names[count.index]}"
    Type = "egress-public"
    AZ   = local.azs[count.index]
    VPC  = "central-egress"
  })
}

# ------------------------------------------------------
# Firewall Endpoint Subnets
# ------------------------------------------------------
# Host firewall VPC endpoints in the Central Egress VPC
# These subnets route traffic through the firewall for inspection

resource "aws_subnet" "egress_firewall_endpoint" {
  count = length(local.egress_firewall_endpoint_subnets)

  # Basic configuration
  vpc_id            = aws_vpc.central_egress.id
  cidr_block        = local.egress_firewall_endpoint_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-fw-endpoint-subnet-${local.az_short_names[count.index]}"
    Type = "egress-firewall-endpoint"
    AZ   = local.azs[count.index]
    VPC  = "central-egress"
  })
}