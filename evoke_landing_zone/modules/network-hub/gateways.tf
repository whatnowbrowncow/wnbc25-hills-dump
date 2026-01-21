# ------------------------------------------------------
# Internet Gateways
# ------------------------------------------------------
# Internet Gateways provide direct internet access for public subnets
# Each VPC can have only one IGW attached

resource "aws_internet_gateway" "central_egress" {
  vpc_id = aws_vpc.central_egress.id

  tags = merge(var.common_tags, {
    Name = local.egress_igw_name
    Type = "internet-gateway"
    VPC  = "central-egress"
  })
}

# ------------------------------------------------------
# Elastic IPs for NAT Gateways
# ------------------------------------------------------
# Each NAT Gateway requires a static Elastic IP address
# Creating one EIP per availability zone for high availability

resource "aws_eip" "nat_gateway" {
  count = local.nat_gateway_count

  # Specify VPC domain for modern AWS regions
  domain = "vpc"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-nat-eip-${local.az_short_names[count.index]}"
    Type = "elastic-ip"
    AZ   = local.azs[count.index]
    Purpose = "nat-gateway"
  })

  # Ensure IGW exists before creating EIPs
  depends_on = [aws_internet_gateway.central_egress]
}

# ------------------------------------------------------
# NAT Gateways
# ------------------------------------------------------
# NAT Gateways provide internet access for private subnets
# Deployed in public subnets across multiple AZs for high availability
# Traffic from private subnets is routed through these for internet access

resource "aws_nat_gateway" "central_egress" {
  count = local.nat_gateway_count

  # Basic configuration
  allocation_id     = aws_eip.nat_gateway[count.index].id
  subnet_id         = aws_subnet.egress_public[count.index].id
  connectivity_type = "public"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-nat-gw-${local.az_short_names[count.index]}"
    Type = "nat-gateway"
    AZ   = local.azs[count.index]
    Subnet = aws_subnet.egress_public[count.index].id
  })

  # Ensure IGW and public subnet route table exists before creating NAT Gateway
  depends_on = [
    aws_internet_gateway.central_egress,
    aws_subnet.egress_public
  ]
}