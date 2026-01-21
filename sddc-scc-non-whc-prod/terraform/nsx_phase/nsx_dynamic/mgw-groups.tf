#####################       Bomgar     #####################

resource "nsxt_policy_group" "Bomgar" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "Bomgar"
  description  = "role: Bomgar ip: 10.120.141.0/24, 10.180.141.0/24, 10.210.141.0/24, 10.112.15.0/24"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = [
        "10.120.141.0/24",
        "10.180.141.0/24",
        "10.210.141.0/24",
        "10.112.15.0/24"
      ]
    }
  }
}

##################### SCC vCentre Mgmt #####################
resource "nsxt_policy_group" "SCC_vCentre_Mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "role: SCC vCentre Mgmt ip:10.120.134.0/24"
  display_name = "SCC_vCentre_Mgmt"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.120.134.0/24"]

    }
  }
}

################# Service Management cidr ##################
resource "nsxt_policy_group" "service_management_cidr" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "role: Service Management cidr ip: ${var.service_management_cidr}"
  display_name = "service_management_cidr"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = [var.service_management_cidr]

    }
  }
}

################# VROPs env master node ##################
resource "nsxt_policy_group" "vrops_env_master_node" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "role: vrops env master ${var.vrops_env_master_node_name} ip: ${var.vrops_env_master_node}"
  display_name = "vrops_env_master_node"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = [var.vrops_env_master_node]

    }
  }
}

################# New Relic ##################
resource "nsxt_policy_group" "New_Relic" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "New Relic - 10.120.163.89"
  display_name = "New_Relic"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.120.163.89"]

    }
  }
}

############ SCC Prod SDDCs ############

resource "nsxt_policy_group" "scc_oracle_prod_vc" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "SCC-ORACLE-PROD vCenter"
  display_name = "SCC-ORACLE-PROD vCenter"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.126.254.4"]

    }
  }
}

resource "nsxt_policy_group" "scc_whc_prod_vc" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "SCC-WHC-PROD vCenter"
  display_name = "SCC-WHC-PROD vCenter"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.126.206.4"]

    }
  }
}

############ Commvault Segment ############

resource "nsxt_policy_group" "commvault" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "SCC-Non-WHC-Prod Commvault Segment"
  display_name = "SCC-Non-WHC-Prod Commvault Segment"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.156.5.128/27"]

    }
  }
}

############ SNOW Asset Collector ############

resource "nsxt_policy_group" "snow_asset_collector" {
  description  = "snow_asset_collector - 10.120.163.44"
  display_name = "snow_asset_collector"
  domain       = "mgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.44"]
    }
  }
}

############ brs_cp_vpn_range ############

resource "nsxt_policy_group" "brs_cp_vpn_range" {
  description  = "brs_cp_vpn_range - 192.168.2.0/23"
  display_name = "brs_cp_vpn_range"
  domain       = "mgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}

############ VMC Citrix Controllers ############

resource "nsxt_policy_group" "vmc_citrix_controllers" {
  description  = "vmc_citrix_controllers - 10.120.39.105, 10.120.39.106"
  display_name = "vmc_citrix_controllers"
  domain       = "mgw"
  criteria {
    ipaddress_expression {
      ip_addresses = [
        "10.120.39.105",
        "10.120.39.106"
      ]
    }
  }
}

############ AnyConnect VPN ############

resource "nsxt_policy_group" "anyconnect_vpn_ranges" {
  description  = "role: anyConnect vpn ranges ip: 192.168.12.0/22, 192.168.16.0/22, 192.168.48.0/20"
  display_name = "anyconnect_vpn_ranges"
  domain       = "mgw"
  criteria {
    ipaddress_expression {
      ip_addresses = [
        "192.168.12.0/22",
        "192.168.16.0/22",
        "192.168.48.0/20"
      ]
    }
  }
}

################ vRNI Appliance  ##################
resource "nsxt_policy_group" "vrni_appliance" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "vrni_appliance"
  display_name = "vrni_appliance"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.156.4.25"]

    }
  }
}

################ vROps Appliance  ##################
resource "nsxt_policy_group" "vrops_proxy" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "vrops_proxy"
  display_name = "vrops_proxy"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.156.4.70"]

    }
  }
}


################ AWS TechOps VPC  ##################
resource "nsxt_policy_group" "aws_techops_prod" {
  lifecycle {  
    create_before_destroy = true
  } 
  description  = "aws_techops_prod"
  display_name = "aws_techops_prod"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["100.79.16.0/20"]

    }
  }
}

resource "nsxt_policy_group" "ld6wnprxync01" {
  lifecycle {  
    create_before_destroy = true
  }     
  description  = "ld6wnprxync01"
  display_name = "ld6wnprxync01"
  domain       = "mgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["10.112.12.22"]
  
    }
  }
}
