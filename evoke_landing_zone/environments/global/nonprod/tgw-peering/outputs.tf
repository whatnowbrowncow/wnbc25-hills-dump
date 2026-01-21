# ==================================================
# Global TGW Peering Outputs
# ==================================================
# Outputs for cross-region Transit Gateway peering between EU West 1 and US East 1
# ==================================================

# ==================================================
# PEERING INFORMATION
# ==================================================

output "peering_details" {
  description = "Complete Transit Gateway peering information"
  value       = module.tgw_peering_eu_to_us.peering_details
}

output "route_details" {
  description = "Cross-region routing configuration"
  value       = module.tgw_peering_eu_to_us.route_details
}

output "peering_attachment_id" {
  description = "Transit Gateway peering attachment ID"
  value       = module.tgw_peering_eu_to_us.peering_attachment_id
}

output "peering_attachment_state" {
  description = "Transit Gateway peering attachment state"
  value       = module.tgw_peering_eu_to_us.peering_attachment_state
}

# ==================================================
# COMPREHENSIVE DEBUG INFORMATION
# ==================================================

output "debug_remote_state_data" {
  description = "Debug information from remote state"
  value = {
    eu_west = {
      tgw_id           = local.eu_west_tgw_id
      route_table_id   = local.eu_west_route_table_id
      supernet_cidr    = local.eu_west_supernet
    }
    us_east = {
      tgw_id           = local.us_east_tgw_id
      route_table_id   = local.us_east_route_table_id
      supernet_cidr    = local.us_east_supernet
    }
    account_id = data.aws_caller_identity.current.account_id
  }
}

# ==================================================
# PEERING SUMMARY
# ==================================================

output "peering_summary" {
  description = "High-level summary of cross-region peering"
  value = {
    status = module.tgw_peering_eu_to_us.peering_attachment_state
    
    regions = {
      local = "eu-west-1"
      peer  = "us-east-1"
    }
    
    networks = {
      eu_west_cidr = local.eu_west_supernet
      us_east_cidr = local.us_east_supernet
    }
    
    transit_gateways = {
      eu_west_tgw = local.eu_west_tgw_id
      us_east_tgw = local.us_east_tgw_id
    }
    
    attachment_id = module.tgw_peering_eu_to_us.peering_attachment_id
  }
}

# ==================================================
# QUICK ACCESS
# ==================================================

output "quick_access" {
  description = "Quick access to commonly needed values"
  value = {
    # Most commonly accessed IDs
    peering_attachment_id = module.tgw_peering_eu_to_us.peering_attachment_id
    peering_state        = module.tgw_peering_eu_to_us.peering_attachment_state
    
    # TGW IDs for reference
    eu_west_tgw_id = local.eu_west_tgw_id
    us_east_tgw_id = local.us_east_tgw_id
    
    # Network CIDRs
    eu_west_cidr = local.eu_west_supernet
    us_east_cidr = local.us_east_supernet
  }
}