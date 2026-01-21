# outputs.tf - Development Environment
# Outputs for the dev environment using consolidated module outputs

# ==================================================
# CORE INFRASTRUCTURE OUTPUTS
# ==================================================

# ------------------------------------------------------
# VPC Information
# ------------------------------------------------------

output "vpc_details" {
  description = "Comprehensive VPC information for dev environment"
  value       = module.network_hub.vpc_details
}

output "vpc_ids" {
  description = "VPC IDs for integration with other resources"
  value = {
    for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.id
  }
}

output "vpc_cidrs" {
  description = "VPC CIDR blocks for network planning and routing"
  value = {
    for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.cidr_block
  }
}

# ------------------------------------------------------
# Transit Gateway Information
# ------------------------------------------------------

output "transit_gateway_details" {
  description = "Comprehensive Transit Gateway configuration details"
  value       = module.network_hub.transit_gateway_details
}

output "transit_gateway_id" {
  description = "Transit Gateway ID for cross-account sharing and peering"
  value       = module.network_hub.transit_gateway_details.id
}

output "tgw_route_table_ids" {
  description = "Transit Gateway route table IDs for routing configuration"
  value = {
    main = module.network_hub.transit_gateway_details.main_route_table_id
  }
}

output "tgw_vpc_attachments" {
  description = "Transit Gateway VPC attachment IDs for routing rules"
  value       = module.network_hub.transit_gateway_details.attachments
}

# ------------------------------------------------------
# Subnet Information
# ------------------------------------------------------

output "subnet_details" {
  description = "Comprehensive subnet information organized by VPC and type"
  value       = module.network_hub.subnet_details
}

output "subnet_ids" {
  description = "Subnet IDs organized by type for resource deployment"
  value = {
    #transit_gateway   = [for idx, subnet in module.network_hub.subnet_details.transit_gateway : subnet.id]
    firewall_endpoint = [for idx, subnet in module.network_hub.subnet_details.firewall.endpoint : subnet.id]
    firewall_tgw      = [for idx, subnet in module.network_hub.subnet_details.firewall.tgw : subnet.id]
    egress_public     = [for idx, subnet in module.network_hub.subnet_details.central_egress.public : subnet.id]
    egress_private    = [for idx, subnet in module.network_hub.subnet_details.central_egress.private : subnet.id]
    #client_cde        = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.id]
    #client_ncde       = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.id]
    #client_tgw        = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.id]
  }
}

output "subnet_cidrs" {
  description = "Subnet CIDR blocks organized by type for network planning"
  value = {
    #transit_gateway   = [for idx, subnet in module.network_hub.subnet_details.transit_gateway : subnet.cidr_block]
    firewall_endpoint = [for idx, subnet in module.network_hub.subnet_details.firewall.endpoint : subnet.cidr_block]
    firewall_tgw      = [for idx, subnet in module.network_hub.subnet_details.firewall.tgw : subnet.cidr_block]
    egress_public     = [for idx, subnet in module.network_hub.subnet_details.central_egress.public : subnet.cidr_block]
    egress_private    = [for idx, subnet in module.network_hub.subnet_details.central_egress.private : subnet.cidr_block]
    #client_cde        = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.cidr_block]
    #client_ncde       = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.cidr_block]
    #client_tgw        = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.cidr_block]
  }
}

#output "client_subnet_allocation" {
#  description = "Client VPC subnet allocation by compliance environment type"
#  value = {
#    cde_subnets  = [for idx, subnet in module.network_hub.subnet_details.client.cde : subnet.cidr_block]
#    ncde_subnets = [for idx, subnet in module.network_hub.subnet_details.client.ncde : subnet.cidr_block]
#    tgw_subnets  = [for idx, subnet in module.network_hub.subnet_details.client.tgw : subnet.cidr_block]
#  }
#}

# ==================================================
# SECURITY INFRASTRUCTURE OUTPUTS
# ==================================================

# ------------------------------------------------------
# Firewall Information
# ------------------------------------------------------

output "firewall_details" {
  description = "Comprehensive AWS Network Firewall configuration details"
  value       = module.network_hub.firewall_details
}

output "firewall_id" {
  description = "AWS Network Firewall ID for logging and monitoring"
  value       = module.network_hub.firewall_details.id
}

output "firewall_policy_id" {
  description = "Network Firewall policy ID for rule management"
  value       = module.network_hub.firewall_details.policy_id
}

output "firewall_endpoints" {
  description = "Network Firewall endpoint information organized by availability zone"
  value       = module.network_hub.firewall_details.endpoints
}

# ==================================================
# CONNECTIVITY OUTPUTS
# ==================================================

# ------------------------------------------------------
# Internet Connectivity
# ------------------------------------------------------

#output "internet_connectivity" {
#  description = "Comprehensive internet connectivity configuration details"
#  value       = module.network_hub.internet_connectivity
#}

#output "internet_gateway_ids" {
#  description = "Internet Gateway IDs by VPC for routing configuration"
#  value       = module.network_hub.internet_connectivity.internet_gateways
#}

#output "nat_gateway_ids" {
#  description = "NAT Gateway IDs for private subnet internet access"
#  value = [
#    for az, nat_info in module.network_hub.internet_connectivity.nat_gateways : nat_info.id
#  ]
#}

#output "elastic_ip_addresses" {
#  description = "Elastic IP addresses assigned to NAT Gateways"
#  value       = module.network_hub.internet_connectivity.elastic_ips
#}

# ------------------------------------------------------
# RAM Sharing
# ------------------------------------------------------

output "ram_share_details" {
  description = "Transit Gateway RAM share information for cross-account access"
  value       = module.network_hub.ram_share_details
}

# ==================================================
# TESTING AND DEVELOPMENT OUTPUTS
# ==================================================

# ------------------------------------------------------
# Test Instances
# ------------------------------------------------------

#output "test_instances" {
#  description = "Test instance details for network validation and troubleshooting"
#  value       = module.network_hub.test_instances
#}

#output "test_instance_security_groups" {
#  description = "Security group IDs for test instances"
#  value       = module.network_hub.test_instance_security_groups
#}

# ==================================================
# SUMMARY AND REFERENCE OUTPUTS
# ==================================================

# ------------------------------------------------------
# Network Architecture Summary
# ------------------------------------------------------

#output "network_summary" {
#  description = "High-level summary of the dev network architecture"
#  value = {
#    environment   = var.environment
#    region       = var.region
#    project_name = var.project_name
#    account_id   = data.aws_caller_identity.current.account_id
#    
#    vpc_count = length(module.network_hub.vpc_details)
#    vpc_cidrs = {
#      for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.cidr_block
#    }
#    
#    subnet_counts = {
#      cde_subnets   = length(module.network_hub.subnet_details.client.cde)
#      ncde_subnets  = length(module.network_hub.subnet_details.client.ncde)
#      tgw_subnets   = length(module.network_hub.subnet_details.client.tgw)
#      total_subnets = (
#        #length(module.network_hub.subnet_details.client.cde) +
#        #length(module.network_hub.subnet_details.client.ncde) +
#        #length(module.network_hub.subnet_details.client.tgw) +
#        #length(module.network_hub.subnet_details.transit_gateway) +
#        length(module.network_hub.subnet_details.firewall.endpoint) +
#        length(module.network_hub.subnet_details.firewall.tgw) +
#        length(module.network_hub.subnet_details.central_egress.private) +
#        length(module.network_hub.subnet_details.central_egress.public) +
#        length(module.network_hub.subnet_details.central_egress.firewall_endpoint)
#      )
#    }
#    
#    features = {
#      firewall_enabled       = module.network_hub.firewall_details.id != null
#      test_instances_enabled = var.enable_test_instances
#      ram_sharing_enabled    = module.network_hub.ram_share_details.share_id != null
#      peering_enabled        = var.enable_peering
#      is_peering_initiator   = var.is_peering_initiator
#    }
#    
#    availability_zones = module.network_hub.availability_zones
#  }
#}

# ------------------------------------------------------
# Account Information
# ------------------------------------------------------

output "account_id" {
  description = "AWS Account ID for dev environment"
  value       = data.aws_caller_identity.current.account_id
}

output "peering_attachment_ids" {
  description = "Peering attachment IDs for accepter environments"
  value       = module.network_hub.peering_attachment_ids
}