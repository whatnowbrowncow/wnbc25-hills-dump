# outputs.tf
# Comprehensive outputs for the hub-and-spoke network architecture
# Organized by resource type with consolidated, structured outputs

# ==================================================
# CORE INFRASTRUCTURE OUTPUTS
# ==================================================

# ------------------------------------------------------
# VPC Information
# ------------------------------------------------------

output "vpc_details" {
  description = "Comprehensive VPC information for the hub-and-spoke architecture"
  value = {
    #transit_gateway = {
    #  id                     = aws_vpc.transit_gateway.id
    #  cidr_block            = aws_vpc.transit_gateway.cidr_block
    #  default_route_table_id = aws_vpc.transit_gateway.default_route_table_id
    #  name                  = "${var.project_name}-${var.environment}-tgw-vpc"
    #}
    firewall = {
      id                     = aws_vpc.firewall.id
      cidr_block            = aws_vpc.firewall.cidr_block
      default_route_table_id = aws_vpc.firewall.default_route_table_id
      name                  = "${var.project_name}-${var.environment}-firewall-vpc"
    }
    central_egress = {
      id                     = aws_vpc.central_egress.id
      cidr_block            = aws_vpc.central_egress.cidr_block
      default_route_table_id = aws_vpc.central_egress.default_route_table_id
      name                  = "${var.project_name}-${var.environment}-egress-vpc"
    }
    #client = {
    #  id                     = aws_vpc.client.id
    #  cidr_block            = aws_vpc.client.cidr_block
    #  default_route_table_id = aws_vpc.client.default_route_table_id
    #  name                  = "${var.project_name}-${var.environment}-client-vpc"
    #}
  }
}

# ------------------------------------------------------
# Transit Gateway Information
# ------------------------------------------------------

output "transit_gateway_details" {
  description = "Transit Gateway configuration details"
  value = {
    id                      = aws_ec2_transit_gateway.main.id
    arn                     = aws_ec2_transit_gateway.main.arn
    owner_id                = aws_ec2_transit_gateway.main.owner_id
    main_route_table_id     = aws_ec2_transit_gateway_route_table.main.id
    #gitlab_runner_rt_id     = var.environment == "prod" ? aws_ec2_transit_gateway_route_table.gitlab_runner_a[0].id : null
    
    attachments = {
      #transit_gateway = aws_ec2_transit_gateway_vpc_attachment.transit_gateway_vpc.id
      #firewall        = aws_ec2_transit_gateway_vpc_attachment.firewall_vpc.id
      central_egress  = aws_ec2_transit_gateway_vpc_attachment.central_egress_vpc.id
      #client          = aws_ec2_transit_gateway_vpc_attachment.client_vpc.id
    }
  }
}

# Simple TGW ID output for module composition
output "transit_gateway_id" {
  description = "Transit Gateway ID for use in other modules"
  value       = aws_ec2_transit_gateway.main.id
}

# ------------------------------------------------------
# Subnet Information
# ------------------------------------------------------

output "subnet_details" {
  description = "Comprehensive subnet information organized by VPC and type"
  value = {
    #transit_gateway = {
    #  for idx, subnet in aws_subnet.transit_gateway : idx => {
    #    id                = subnet.id
    #    cidr_block        = subnet.cidr_block
    #    availability_zone = subnet.availability_zone
    #  }
    #}
    #firewall = {
    #  endpoint = {
    #    for idx, subnet in aws_subnet.firewall_endpoint : idx => {
    #      id                = subnet.id
    #      cidr_block        = subnet.cidr_block
    #      availability_zone = subnet.availability_zone
    #    }
    #  }
    #  tgw = {
    #    for idx, subnet in aws_subnet.firewall_tgw : idx => {
    #      id                = subnet.id
    #      cidr_block        = subnet.cidr_block
    #      availability_zone = subnet.availability_zone
    #    }
    #  }
    #}
    central_egress = {
      public = {
        for idx, subnet in aws_subnet.egress_public : idx => {
          id                = subnet.id
          cidr_block        = subnet.cidr_block
          availability_zone = subnet.availability_zone
        }
      }
      private = {
        for idx, subnet in aws_subnet.egress_private : idx => {
          id                = subnet.id
          cidr_block        = subnet.cidr_block
          availability_zone = subnet.availability_zone
        }
      }
      firewall_endpoint = {
        for idx, subnet in aws_subnet.egress_firewall_endpoint : idx => {
          id                = subnet.id
          cidr_block        = subnet.cidr_block
          availability_zone = subnet.availability_zone
        }
      }
    }
#    client = {
#      cde = {
#        for idx, subnet in aws_subnet.client_cde : idx => {
#          id                = subnet.id
#          cidr_block        = subnet.cidr_block
#          availability_zone = subnet.availability_zone
#        }
#      }
#      ncde = {
#        for idx, subnet in aws_subnet.client_ncde : idx => {
#          id                = subnet.id
#          cidr_block        = subnet.cidr_block
#          availability_zone = subnet.availability_zone
#        }
#      }
#      tgw = {
#        for idx, subnet in aws_subnet.client_tgw : idx => {
#          id                = subnet.id
#          cidr_block        = subnet.cidr_block
#          availability_zone = subnet.availability_zone
#        }
#      }
#    }
  }
}

# ------------------------------------------------------
# Route Table Information
# ------------------------------------------------------

output "route_table_details" {
  description = "Custom route table IDs organized by purpose"
  value = {
    transit_gateway_main     = aws_ec2_transit_gateway_route_table.main.id
    egress_private          = aws_route_table.egress_private[*].id
    egress_public           = aws_route_table.egress_public[*].id
    #firewall_endpoint       = aws_route_table.firewall_endpoint[*].id
    #firewall_tgw            = aws_route_table.firewall_tgw[*].id
    egress_firewall_endpoint = aws_route_table.egress_firewall_endpoint[*].id
  }
}

# ==================================================
# SECURITY INFRASTRUCTURE OUTPUTS
# ==================================================

# ------------------------------------------------------
# Firewall Information
# ------------------------------------------------------

output "firewall_details" {
  description = "AWS Network Firewall configuration details"
  value = {
    id           = aws_networkfirewall_firewall.main.id
    arn          = aws_networkfirewall_firewall.main.arn
    policy_arn   = aws_networkfirewall_firewall_policy.main.arn
    policy_id    = aws_networkfirewall_firewall_policy.main.id
    endpoints    = aws_networkfirewall_firewall.main.firewall_status[0].sync_states
  }
}

# ==================================================
# CONNECTIVITY OUTPUTS
# ==================================================

# ------------------------------------------------------
# Internet Connectivity
# ------------------------------------------------------

#output "internet_connectivity" {
#  description = "Internet gateway and NAT gateway connectivity details"
#  value = {
#    internet_gateways = {
#      central_egress  = aws_internet_gateway.central_egress.id
#      transit_gateway = aws_internet_gateway.transit_gateway.id
#    }
#    nat_gateways = {
#      for idx, nat_gw in aws_nat_gateway.central_egress : local.azs[idx] => {
#        id        = nat_gw.id
#        public_ip = aws_eip.nat_gateway[idx].public_ip
#        subnet_id = aws_subnet.egress_public[idx].id
#      }
#    }
#    elastic_ips = aws_eip.nat_gateway[*].public_ip
#  }
#}

# ------------------------------------------------------
# RAM Sharing
# ------------------------------------------------------

output "ram_share_details" {
  description = "Transit Gateway RAM share information for cross-account access"
  value = {
    share_id         = aws_ram_resource_share.transit_gateway_share.id
    share_arn        = aws_ram_resource_share.transit_gateway_share.arn
    share_name       = aws_ram_resource_share.transit_gateway_share.name
    organization_arn = "arn:aws:organizations::${var.organization_management_account_id}:organization/${var.organization_id}"
  }
}

# ==================================================
# TESTING AND DEVELOPMENT OUTPUTS
# ==================================================

# ------------------------------------------------------
# Test Instances
# ------------------------------------------------------

#output "test_instances" {
#  description = "Test instance details for network validation and troubleshooting"
#  value = var.enable_test_instances ? {
#    tgw_instance = length(aws_instance.tgw_test) > 0 ? {
#      id                = aws_instance.tgw_test[0].id
#      public_ip         = aws_instance.tgw_test[0].public_ip
#      private_ip        = aws_instance.tgw_test[0].private_ip
#      availability_zone = aws_instance.tgw_test[0].availability_zone
#      subnet_id         = aws_instance.tgw_test[0].subnet_id
#      ssh_command       = "ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.tgw_test[0].public_ip}"
#    } : null
#    client_instance = length(aws_instance.client_test) > 0 ? {
#      id                = aws_instance.client_test[0].id
#      private_ip        = aws_instance.client_test[0].private_ip
#      availability_zone = aws_instance.client_test[0].availability_zone
#      subnet_id         = aws_instance.client_test[0].subnet_id
#      ssh_command       = "ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.client_test[0].private_ip}"
#      access_note       = "Access via TGW instance or VPN - no public IP"
#    } : null
#  } : null
#}
#
#output "test_instance_security_groups" {
#  description = "Security group IDs for test instances"
#  value = var.enable_test_instances ? {
#    tgw_instance_sg    = length(aws_security_group.tgw_instance) > 0 ? aws_security_group.tgw_instance[0].id : null
#    client_instance_sg = length(aws_security_group.client_instance) > 0 ? aws_security_group.client_instance[0].id : null
#  } : null
#}

# ==================================================
# GENERAL REFERENCE OUTPUTS
# ==================================================

output "availability_zones" {
  description = "Availability zones used for multi-AZ resource deployment"
  value       = local.azs
}

output "peering_attachment_ids" {
  description = "Peering attachment IDs created by this environment"
  value = {
    dev_to_prod    = try(aws_ec2_transit_gateway_peering_attachment.dev_to_prod[0].id, "")
    dev_to_nonprod = try(aws_ec2_transit_gateway_peering_attachment.dev_to_nonprod[0].id, "")
    nonprod_to_prod = try(aws_ec2_transit_gateway_peering_attachment.nonprod_to_prod[0].id, "")
  }
}

output "debug_dev_attachment" {
  value = {
    data_source_result = var.environment == "prod" && var.enable_dev_prod_peering ? try(data.external.dev_peering_attachment[0].result, {}) : {}
    local_attachment_id = local.dev_to_prod_attachment_id
  }
}