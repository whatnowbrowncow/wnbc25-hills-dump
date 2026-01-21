# ==================================================
# outputs.tf
# ==================================================

output "network_summary" {
  description = "High-level network summary for the client account"
  value = {
    account_name       = var.account_name
    vpc_cidr          = var.vpc_cidr
    environment       = var.environment
    region            = var.region
    availability_zones = var.availability_zones
    
    subnet_counts = {
      workload_subnets  = length(var.workload_subnets)
      tgw_subnets  = length(var.tgw_subnets)
    }
  }
}