# routes.tf

data "aws_vpc_endpoint" "firewall" {
  for_each = { for idx, subnet in aws_subnet.egress_firewall_endpoint : idx => subnet }
  vpc_id = aws_vpc.central_egress.id
  tags = {
    VPCEndpointAssociation = "arn:aws:network-firewall:${var.region}:${data.aws_caller_identity.current.account_id}:vpc-endpoint-association/*"
    Name = "network-hub-${var.environment}-network-firewall (${each.value.availability_zone})"
  }
  
  # Add this depends_on to ensure VPC endpoint associations are created first
  depends_on = [
    awscc_networkfirewall_vpc_endpoint_association.egress
  ]
}

# =============================================================================
# VPC DEFAULT ROUTE TABLE ROUTES
# =============================================================================

# Central Egress VPC main route table: Route network traffic via TGW
resource "aws_route" "egress_vpc_to_tgw" {
  route_table_id         = aws_default_route_table.central_egress_main.id
  destination_cidr_block = var.local_supernet_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
  depends_on = [
    aws_ec2_transit_gateway.main,
    #aws_ec2_transit_gateway_vpc_attachment.transit_gateway_vpc
  ]
}

# Central Egress VPC main route table: Route internet traffic via IGW
resource "aws_route" "egress_vpc_to_igw" {
  route_table_id         = aws_default_route_table.central_egress_main.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.central_egress.id
}

# =============================================================================
# CENTRAL EGRESS VPC ROUTE TABLES
# =============================================================================

# Central Egress Private Route Tables
resource "aws_route_table" "egress_private" {
  count  = length(local.azs)
  vpc_id = aws_vpc.central_egress.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-private-rt-${substr(local.azs[count.index], -2, 2)}"
    Type = "private-route-table"
    AZ   = local.azs[count.index]
  })
}

# Central Egress Public Route Tables
resource "aws_route_table" "egress_public" {
  count  = length(local.azs)
  vpc_id = aws_vpc.central_egress.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-public-rt-${substr(local.azs[count.index], -2, 2)}"
    Type = "public-route-table"
    AZ   = local.azs[count.index]
  })
}

# =============================================================================
# CENTRAL EGRESS VPC ROUTE TABLE ASSOCIATIONS
# =============================================================================

# Associate private subnets with their respective route tables
resource "aws_route_table_association" "egress_private" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.egress_private[count.index].id
  route_table_id = aws_route_table.egress_private[count.index].id
}

# Associate public subnets with their respective route tables
resource "aws_route_table_association" "egress_public" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.egress_public[count.index].id
  route_table_id = aws_route_table.egress_public[count.index].id
}

# =============================================================================
# CENTRAL EGRESS VPC ROUTES
# =============================================================================

# Egress Private Route Table Routes
# Network traffic via TGW
resource "aws_route" "egress_private_to_tgw" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.egress_private[count.index].id
  destination_cidr_block = var.local_supernet_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
}

# Egress traffic via FW
resource "aws_route" "egress_private_to_nat" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.egress_private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.egress_vpce_by_az[local.azs[count.index]]
  
  depends_on = [
    awscc_networkfirewall_vpc_endpoint_association.egress
  ]
}

# Egress Public Route Table Routes
# Internet traffic via IGW
resource "aws_route" "egress_public_to_igw" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.egress_public[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.central_egress.id
}

resource "aws_route" "egress_public_to_tgw" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.egress_public[count.index].id
  destination_cidr_block = var.local_supernet_cidr
  vpc_endpoint_id        = local.egress_vpce_by_az[local.azs[count.index]]
  
  depends_on = [
    awscc_networkfirewall_vpc_endpoint_association.egress
  ]
}

# =============================================================================
# CENTRAL EGRESS FIREWALL ENDPOINT ROUTE TABLES
# =============================================================================

# Route tables for egress firewall endpoint subnets (one per AZ)
resource "aws_route_table" "egress_firewall_endpoint" {
  count  = length(aws_subnet.egress_firewall_endpoint)
  vpc_id = aws_vpc.central_egress.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-egress-fw-endpoint-rt-${substr(local.azs[count.index], -2, 2)}"
    Type = "egress-firewall-endpoint-route-table"
    AZ   = local.azs[count.index]
  })
}

# Associate egress firewall endpoint subnets with their route tables
resource "aws_route_table_association" "egress_firewall_endpoint" {
  count          = length(aws_subnet.egress_firewall_endpoint)
  subnet_id      = aws_subnet.egress_firewall_endpoint[count.index].id
  route_table_id = aws_route_table.egress_firewall_endpoint[count.index].id
}

# =============================================================================
# CENTRAL EGRESS FIREWALL ENDPOINT ROUTES
# =============================================================================

# Route internet traffic (0.0.0.0/0) via NAT Gateway
resource "aws_route" "egress_firewall_endpoint_to_nat" {
  count                  = length(aws_route_table.egress_firewall_endpoint)
  route_table_id         = aws_route_table.egress_firewall_endpoint[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.central_egress[count.index].id
}

# Route supernet traffic via TGW
resource "aws_route" "egress_firewall_endpoint_to_tgw" {
  count                  = length(aws_route_table.egress_firewall_endpoint)
  route_table_id         = aws_route_table.egress_firewall_endpoint[count.index].id
  destination_cidr_block = var.local_supernet_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
}