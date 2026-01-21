# outputs.tf - Non-Production Environment
# Outputs for the nonprod environment using consolidated module outputs

# ==================================================
# CORE INFRASTRUCTURE OUTPUTS
# ==================================================

# ------------------------------------------------------
# VPC Information
# ------------------------------------------------------

output "vpc_details" {
  description = "Comprehensive VPC information for nonprod environment"
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

# ------------------------------------------------------
# RAM Sharing
# ------------------------------------------------------

output "ram_share_details" {
  description = "Transit Gateway RAM share information for cross-account access"
  value       = module.network_hub.ram_share_details
}

# ==================================================
# SUMMARY AND REFERENCE OUTPUTS
# ==================================================

# ------------------------------------------------------
# Quick Access Reference
# ------------------------------------------------------

output "quick_access" {
  description = "Quick access to commonly needed values for automation and integration"
  value = {
    # Essential IDs for integration
    transit_gateway_id = module.network_hub.transit_gateway_details.id
    firewall_id        = module.network_hub.firewall_details.id
    account_id         = data.aws_caller_identity.current.account_id
    
    vpc_ids = {
      for vpc_name, vpc_info in module.network_hub.vpc_details : vpc_name => vpc_info.id
    }
    
    # Test instance access commands
    test_instance_ssh = var.enable_test_instances ? {
      tgw_instance    = try(module.network_hub.test_instances.tgw_instance.ssh_command, null)
      client_instance = try(module.network_hub.test_instances.client_instance.ssh_command, null)
    } : null
    
    # Internet connectivity
    #nat_gateway_ips = module.network_hub.internet_connectivity.elastic_ips
  }
}

# ------------------------------------------------------
# Account Information
# ------------------------------------------------------

output "account_id" {
  description = "AWS Account ID for nonprod environment"
  value       = data.aws_caller_identity.current.account_id
}