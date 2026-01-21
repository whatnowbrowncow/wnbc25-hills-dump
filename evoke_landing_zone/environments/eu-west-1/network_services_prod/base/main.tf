# ==================================================
# Client VPC Module - modules/client-vpc/main.tf
# ==================================================

# ==================================================
# DATA SOURCES
# ==================================================

data "aws_availability_zones" "available" {
  state = "available"
}

# ==================================================
# LOCAL VALUES
# ==================================================

locals {
  # Use specified AZs or default to first 3 available
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 3)
  
  # VPC naming
  vpc_name = "${var.project_name}-${var.environment}-vpc"
}

# ==================================================
# VPC
# ==================================================

resource "aws_vpc" "client" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.common_tags, {
    Name    = local.vpc_name
    Type    = "client-vpc"
    Purpose = "Client workloads and applications"
  })
}

# ==================================================
# SUBNETS
# ==================================================

# Workload Subnets
resource "aws_subnet" "workload" {
  count = length(var.workload_subnets)

  vpc_id            = aws_vpc.client.id
  cidr_block        = var.workload_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name        = "${var.project_name}-${var.environment}-workload-subnet-${substr(local.azs[count.index], -2, 2)}"
    Type        = "workload"
    Environment = "workload"
    Compliance  = "required"
    AZ          = local.azs[count.index]
  })
}

# Transit Gateway Attachment Subnets
resource "aws_subnet" "tgw" {
  count = length(var.tgw_subnets)

  vpc_id            = aws_vpc.client.id
  cidr_block        = var.tgw_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-tgw-subnet-${substr(local.azs[count.index], -2, 2)}"
    Type = "client-tgw"
    AZ   = local.azs[count.index]
  })
}

# ==================================================
# TRANSIT GATEWAY ATTACHMENT
# ==================================================

resource "aws_ec2_transit_gateway_vpc_attachment" "client" {
  subnet_ids         = aws_subnet.tgw[*].id
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.client.id

  # Disable default associations - will be managed by network hub
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-tgw-attachment"
    Type = "tgw-attachment"
  })
}

# ==================================================
# ROUTE TABLES
# ==================================================

# Single Workload Route Table for all subnets
resource "aws_route_table" "workload" {
  vpc_id = aws_vpc.client.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-workload-rt"
    Type = "workload-route-table"
  })
}

# ==================================================
# ROUTE TABLE ASSOCIATIONS
# ==================================================

# Associate all Workload subnets with the single route table
resource "aws_route_table_association" "workload" {
  count          = length(aws_subnet.workload)
  subnet_id      = aws_subnet.workload[count.index].id
  route_table_id = aws_route_table.workload.id
}

# ==================================================
# DEFAULT ROUTES
# ==================================================

# Workload subnets route all traffic via Transit Gateway
resource "aws_route" "workload_to_tgw" {
  route_table_id         = aws_route_table.workload.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.client]
}

# ==================================================
# TEST INSTANCE
# ==================================================

# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security group for test instance
resource "aws_security_group" "test_instance" {
  count = var.enable_test_instance ? 1 : 0

  name_prefix = "${var.project_name}-${var.environment}-test-instance-"
  vpc_id      = aws_vpc.client.id
  description = "Security group for test instance in Workload subnet"

  # Allow SSH from internal networks
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["100.96.0.0/11"]  # Global supernet
    description = "SSH from internal networks"
  }

  # Allow ICMP (ping) from internal networks
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["100.96.0.0/11"]  # Global supernet
    description = "ICMP from internal networks"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-test-instance-sg"
    Type = "security-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Test instance in workload subnet
resource "aws_instance" "test" {
  count = var.enable_test_instance ? 1 : 0

  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.test_instance_type
  key_name      = var.ssh_key_name

  # Deploy in workload subnet
  subnet_id                   = aws_subnet.workload[0].id
  vpc_security_group_ids      = [aws_security_group.test_instance[0].id]
  associate_public_ip_address = false

  tags = merge(var.common_tags, {
    Name        = "${var.project_name}-${var.environment}-test-instance"
    Type        = "test-instance"
    Environment = "workload"
    Purpose     = "network-testing"
  })

  lifecycle {
    create_before_destroy = true
  }
}