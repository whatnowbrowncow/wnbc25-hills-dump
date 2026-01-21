# ==================================================
# outputs.tf
# ==================================================

output "vpc_details" {
  description = "Client VPC details"
  value       = module.client_vpc.vpc_details
}

output "subnet_details" {
  description = "Client subnet details by environment type"
  value       = module.client_vpc.subnet_details
}

output "transit_gateway_attachment" {
  description = "Transit Gateway attachment details"
  value       = module.client_vpc.transit_gateway_attachment
}

output "test_instance" {
  description = "Test instance details"
  value       = module.client_vpc.test_instance
}

output "network_summary" {
  description = "High-level network summary for the client account"
  value = {
    account_name       = var.account_name
    vpc_cidr          = var.vpc_cidr
    environment       = var.environment
    region            = var.region
    availability_zones = var.availability_zones
    
    subnet_counts = {
      cde_subnets  = length(var.cde_subnets)
      ncde_subnets = length(var.ncde_subnets)
      tgw_subnets  = length(var.tgw_subnets)
    }
    
    network_hub_integration = {
      transit_gateway_id = data.terraform_remote_state.network_hub.outputs.transit_gateway_id
      connected         = module.client_vpc.transit_gateway_attachment.id != null
    }
  }
}