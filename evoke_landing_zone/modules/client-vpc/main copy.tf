# ==================================================
# CLIENT VPC MODULE - Main Configuration
# ==================================================

locals {
  # Generate consistent naming
  name_prefix = "${var.project_name}-${var.environment}"
  
  # Common tags merged with custom tags
  common_tags = merge(
    var.common_tags,
    {
      Name        = "${local.name_prefix}-vpc"
      AccountName = var.account_name
      ManagedBy   = "Terraform"
    }
  )
}

# ==================================================
# VPC
# ==================================================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-vpc"
    }
  )
}

# ==================================================
# WORKLOAD SUBNETS
# ==================================================
resource "aws_subnet" "workload" {
  count             = length(var.workload_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.workload_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-workload-${var.availability_zones[count.index]}"
      Type = "workload"
      Tier = var.common_tags["Tier"]
    }
  )
}

# ==================================================
# TRANSIT GATEWAY ATTACHMENT SUBNETS
# ==================================================
resource "aws_subnet" "tgw" {
  count             = length(var.tgw_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.tgw_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-tgw-attach-${var.availability_zones[count.index]}"
      Type = "transit-gateway"
    }
  )
}

# ==================================================
# TRANSIT GATEWAY ATTACHMENT
# ==================================================
resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  subnet_ids         = aws_subnet.tgw[*].id
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.main.id

  # Best practices for TGW attachments
  dns_support                                     = "enable"
  ipv6_support                                    = "disable"
  # appliance_mode_support                          = var.appliance_mode_support ? "enable" : "disable"
  transit_gateway_default_route_table_association = false # var.tgw_default_route_table_association
  transit_gateway_default_route_table_propagation = false # var.tgw_default_route_table_propagation

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-tgw-attachment"
    }
  )
}

# ==================================================
# ROUTE TABLES
# ==================================================

# Workload Route Table
resource "aws_route_table" "workload" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-workload-rt"
      Type = "workload"
    }
  )
}

# TGW Route Table
resource "aws_route_table" "tgw" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-tgw-rt"
      Type = "transit-gateway"
    }
  )
}

# ==================================================
# ROUTE TABLE ASSOCIATIONS
# ==================================================

# Associate workload subnets with workload route table
resource "aws_route_table_association" "workload" {
  count          = length(aws_subnet.workload)
  subnet_id      = aws_subnet.workload[count.index].id
  route_table_id = aws_route_table.workload.id
}

# Associate TGW subnets with TGW route table
resource "aws_route_table_association" "tgw" {
  count          = length(aws_subnet.tgw)
  subnet_id      = aws_subnet.tgw[count.index].id
  route_table_id = aws_route_table.tgw.id
}

# ==================================================
# DEFAULT ROUTES TO TRANSIT GATEWAY
# ==================================================

# Route all traffic from workload subnets to TGW
resource "aws_route" "workload_to_tgw" {
  count                  = var.create_default_tgw_route ? 1 : 0
  route_table_id         = aws_route_table.workload.id
  destination_cidr_block = var.default_route_cidr
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

# ==================================================
# ADDITIONAL ROUTES (OPTIONAL)
# ==================================================
#resource "aws_route" "additional_workload_routes" {
#  for_each = var.additional_workload_routes
#
#  route_table_id         = aws_route_table.workload.id
#  destination_cidr_block = each.key
#  transit_gateway_id     = var.transit_gateway_id
#
#  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
#}

# ==================================================
# TEST INSTANCE (OPTIONAL)
# ==================================================
data "aws_ami" "amazon_linux_2023" {
  count = var.enable_test_instance ? 1 : 0

  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "test_instance" {
  count = var.enable_test_instance ? 1 : 0

  name_prefix = "${local.name_prefix}-test-instance-"
  description = "Security group for test instance"
  vpc_id      = aws_vpc.main.id

  # Allow SSH from specified CIDR blocks
  dynamic "ingress" {
    for_each = var.test_instance_ssh_cidrs
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "SSH access"
    }
  }

  # Allow ICMP for testing
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "ICMP for testing"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-test-instance-sg"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "test" {
  count = var.enable_test_instance ? 1 : 0

  ami                    = data.aws_ami.amazon_linux_2023[0].id
  instance_type          = var.test_instance_type
  subnet_id              = aws_subnet.workload[0].id
  vpc_security_group_ids = [aws_security_group.test_instance[0].id]
  key_name               = var.ssh_key_name

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              echo "Test instance for ${var.account_name}" > /etc/motd
              EOF

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-test-instance"
    }
  )
}
