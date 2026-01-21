# ==================================================
# Environment Outputs Configuration
# ==================================================
# Outputs for the nonprod environment using new consolidated module outputs
# ==================================================

# ==================================================
# VPC INFORMATION
# ==================================================

output "vpc_details" {
  description = "Comprehensive VPC information"
  value       = module.network_hub.vpc_details
}

output "vpc_ids" {
  description = "IDs of all VPCs"
  value = {
    for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.id
  }
}

output "vpc_cidrs" {
  description = "CIDR blocks of all VPCs"
  value = {
    for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.cidr_block
  }
}

# ==================================================
# SUBNET INFORMATION
# ==================================================

output "subnet_details" {
  description = "Comprehensive subnet information by VPC and type"
  value       = module.network_hub.subnet_details
}

output "subnet_ids" {
  description = "IDs of all subnets organized by type"
  value = {
    transit_gateway   = [for idx, subnet in module.network_hub.subnet_details.transit_gateway : subnet.id]
    firewall_endpoint = [for idx, subnet in module.network_hub.subnet_details.firewall.endpoint : subnet.id]
    firewall_tgw      = [for idx, subnet in module.network_hub.subnet_details.firewall.tgw : subnet.id]
    egress_private    = [for idx, subnet in module.network_hub.subnet_details.central_egress.private : subnet.id]
    egress_public     = [for idx, subnet in module.network_hub.subnet_details.central_egress.public : subnet.id]
    client_cde        = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.id]
    client_ncde       = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.id]
    client_tgw        = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.id]
  }
}

output "subnet_cidrs" {
  description = "CIDR blocks of all subnets organized by type"
  value = {
    transit_gateway   = [for idx, subnet in module.network_hub.subnet_details.transit_gateway : subnet.cidr_block]
    firewall_endpoint = [for idx, subnet in module.network_hub.subnet_details.firewall.endpoint : subnet.cidr_block]
    firewall_tgw      = [for idx, subnet in module.network_hub.subnet_details.firewall.tgw : subnet.cidr_block]
    egress_private    = [for idx, subnet in module.network_hub.subnet_details.central_egress.private : subnet.cidr_block]
    egress_public     = [for idx, subnet in module.network_hub.subnet_details.central_egress.public : subnet.cidr_block]
    client_cde        = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.cidr_block]
    client_ncde       = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.cidr_block]
    client_tgw        = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.cidr_block]
  }
}

# Client subnet allocation breakdown
output "client_subnet_allocation" {
  description = "Client VPC subnet allocation by environment type"
  value = {
    cde_subnets  = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.cidr_block]
    ncde_subnets = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.cidr_block]
    tgw_subnets  = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.cidr_block]
  }
}

# ==================================================
# TRANSIT GATEWAY INFORMATION
# ==================================================

output "transit_gateway_details" {
  description = "Comprehensive Transit Gateway information"
  value       = module.network_hub.transit_gateway_details
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = module.network_hub.transit_gateway_details.id
}

output "tgw_route_table_ids" {
  description = "Transit Gateway route table IDs"
  value = {
    main = module.network_hub.transit_gateway_details.main_route_table_id
  }
}

output "tgw_vpc_attachments" {
  description = "Transit Gateway VPC attachment IDs"
  value       = module.network_hub.transit_gateway_details.attachments
}

# ==================================================
# FIREWALL INFORMATION
# ==================================================

output "firewall_details" {
  description = "Comprehensive firewall information"
  value       = module.network_hub.firewall_details
}

output "firewall_id" {
  description = "ID of the AWS Network Firewall"
  value       = module.network_hub.firewall_details.id
}

output "firewall_policy_id" {
  description = "ID of the Network Firewall policy"
  value       = module.network_hub.firewall_details.policy_id
}

output "firewall_endpoints" {
  description = "Network Firewall endpoint information by AZ"
  value       = module.network_hub.firewall_details.endpoints
}

# ==================================================
# INTERNET CONNECTIVITY
# ==================================================

output "internet_connectivity" {
  description = "Comprehensive internet connectivity information"
  value       = module.network_hub.internet_connectivity
}

output "internet_gateway_ids" {
  description = "Internet Gateway IDs by VPC"
  value       = module.network_hub.internet_connectivity.internet_gateways
}

output "nat_gateway_ids" {
  description = "IDs of NAT Gateways"
  value = [
    for az, nat_info in module.network_hub.internet_connectivity.nat_gateways : nat_info.id
  ]
}

output "elastic_ip_addresses" {
  description = "Elastic IP addresses for NAT Gateways"
  value       = module.network_hub.internet_connectivity.elastic_ips
}

# ==================================================
# RAM SHARING
# ==================================================

output "ram_share_details" {
  description = "Transit Gateway RAM share information"
  value       = module.network_hub.ram_share_details
}

# ==================================================
# TEST INSTANCES
# ==================================================

output "test_instances" {
  description = "Test instance details for network validation"
  value       = module.network_hub.test_instances
}

output "test_instance_security_groups" {
  description = "Security group IDs for test instances"
  value       = module.network_hub.test_instance_security_groups
}

output "security_group_ids" {
  description = "Security group IDs for test instances"
  value       = module.network_hub.test_instance_security_groups
}

# ==================================================
# NETWORK SUMMARY
# ==================================================

output "network_summary" {
  description = "High-level summary of the network architecture"
  value = {
    environment     = var.environment
    region         = var.region
    project_name   = var.project_name
    
    # VPC information
    vpc_count      = length(module.network_hub.vpc_details)
    vpc_cidrs = {
      for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.cidr_block
    }
    
    # Subnet counts
    subnet_counts = {
      cde_subnets   = length(module.network_hub.subnet_details.client.cde)
      ncde_subnets  = length(module.network_hub.subnet_details.client.ncde)
      tgw_subnets   = length(module.network_hub.subnet_details.client.tgw)
      total_subnets = (
        length(module.network_hub.subnet_details.client.cde) +
        length(module.network_hub.subnet_details.client.ncde) +
        length(module.network_hub.subnet_details.client.tgw) +
        length(module.network_hub.subnet_details.transit_gateway) +
        length(module.network_hub.subnet_details.firewall.endpoint) +
        length(module.network_hub.subnet_details.firewall.tgw) +
        length(module.network_hub.subnet_details.central_egress.private) +
        length(module.network_hub.subnet_details.central_egress.public) +
        length(module.network_hub.subnet_details.central_egress.firewall_endpoint)
      )
    }
    
    # Feature flags
    features = {
      firewall_enabled        = module.network_hub.firewall_details.id != null
      test_instances_enabled  = var.enable_test_instances
      ram_sharing_enabled     = module.network_hub.ram_share_details.share_id != null
    }
    
    # Availability zones
    availability_zones = module.network_hub.availability_zones
  }
}

# ==================================================
# QUICK ACCESS OUTPUTS
# ==================================================

output "quick_access" {
  description = "Quick access to commonly needed values"
  value = {
    # Most commonly accessed IDs
    transit_gateway_id = module.network_hub.transit_gateway_details.id
    firewall_id        = module.network_hub.firewall_details.id
    vpc_ids = {
      for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.id
    }
    
    # Test instance access
    test_instance_ssh = var.enable_test_instances ? {
      tgw_instance    = try(module.network_hub.test_instances.tgw_instance.ssh_command, null)
      client_instance = try(module.network_hub.test_instances.client_instance.ssh_command, null)
    } : null
    
    # Important endpoints
    nat_gateway_ips = module.network_hub.internet_connectivity.elastic_ips
  }
}