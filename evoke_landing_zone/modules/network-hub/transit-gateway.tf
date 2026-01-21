# transit-gateway.tf
# Organized by dependency order: TGW → Attachments → Route Tables → Associations → Routes

# ==================================================
# TRANSIT GATEWAY
# ==================================================
# Main Transit Gateway that connects all VPCs in the hub-and-spoke architecture

resource "aws_ec2_transit_gateway" "main" {
  description = "Main Transit Gateway for ${var.project_name}-${var.environment}"
  
  # Enable auto-acceptance and disable default routing for custom control
  auto_accept_shared_attachments     = "disable"
  default_route_table_association    = "disable"
  default_route_table_propagation    = "disable"
  
  # Enable DNS resolution across VPCs
  dns_support = "enable"
  
  # Enable ECMP for VPN connections (load balancing across multiple tunnels)
  vpn_ecmp_support = "enable"

  tags = merge(var.common_tags, {
    Name = local.tgw_name
    Type = "transit-gateway"
  })
}

# ==================================================
# VPC ATTACHMENTS
# ==================================================
# Connect each VPC to the Transit Gateway for inter-VPC communication
# Order by architectural importance: Transit Gateway → Firewall → Egress → Client

# ------------------------------------------------------
# Central Egress VPC Attachment
# ------------------------------------------------------
# Centralized internet egress and ingress point

resource "aws_ec2_transit_gateway_vpc_attachment" "central_egress_vpc" {
  subnet_ids         = local.vpc_attachments.central_egress.subnet_ids
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = local.vpc_attachments.central_egress.vpc_id
  
  # Enable default routing association
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  appliance_mode_support = "enable"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-tgw-attachment-${local.vpc_attachments.central_egress.name}"
    Type = "tgw-attachment"
    VPC  = "central-egress"
  })
}

# ==================================================
# TRANSIT GATEWAY ROUTE TABLES
# ==================================================
# Custom route tables for granular traffic control

# ------------------------------------------------------
# Main Route Table
# ------------------------------------------------------
# Primary route table for standard VPC-to-VPC communication
# All traffic flows through firewall for inspection

resource "aws_ec2_transit_gateway_route_table" "main" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name    = local.main_route_table_name
    Type    = "tgw-route-table"
    Purpose = "main-routing"
  })
}

# ------------------------------------------------------
# GitLab Runner Route Table
# ------------------------------------------------------
# Dedicated route table for GitLab runner instances in prod

#resource "aws_ec2_transit_gateway_route_table" "gitlab_runner_a" {
#  count              = var.environment == "prod" ? 1 : 0
#  transit_gateway_id = aws_ec2_transit_gateway.main.id
#
#  tags = merge(var.common_tags, {
#    Name    = local.gitlab_runner_rout_table_name
#    Type    = "tgw-route-table"
#    Purpose = "routes gitlab runner a instances"
#  })
#}

# ==================================================
# DEFAULT ROUTE TABLE CONFIGURATION
# ==================================================
# Configure the default route table association

#resource "aws_ec2_transit_gateway_default_route_table_association" "main" {
#  transit_gateway_id             = aws_ec2_transit_gateway.main.id
#  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
#}

# ==================================================
# ROUTE TABLE ASSOCIATIONS
# ==================================================
# Associate VPC attachments with appropriate route tables
# Currently using default associations (commented out for reference)

resource "aws_ec2_transit_gateway_route_table_association" "main_egress_vpc" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.central_egress_vpc.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# ==================================================
# STATIC ROUTES
# ==================================================
# Define explicit routing rules for traffic flow control

# ------------------------------------------------------
# Internet-bound Traffic Routes
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_route" "main_default_to_egress" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.central_egress_vpc.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# ------------------------------------------------------
# Security Routes
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_route" "blackhole_evoke_supernet" {
  destination_cidr_block         = var.evoke_supernet
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  blackhole                      = true
}