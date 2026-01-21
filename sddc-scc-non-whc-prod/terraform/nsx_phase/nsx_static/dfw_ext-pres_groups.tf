/*======================================
#### Parse of ASA network objects ####

######### Example Format #############

resource "nsxt_policy_group" "group1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tf-group1"
  description  = "Terraform provisioned Group"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["211.1.1.1", "212.1.1.1"]
    }
  }
}

How we will format and standardise this:
The "resource" name and "display_name" will be the same/identical
The IP addresses/Networks will always be a list
IP address ranges are not permitted (e.g. 192.168.10.1-192.168.10.10)
The "description" must contain the "role" and "ip" keys (this format is to aid later computer based extraction):
role: describes the object, where this information is available. Where it isn't the group_name must be added
ip: lists the IP addresses/networks (CIDR) defined in the object in a comma separated format
The ip_addr_list must always be in the "description", as this allows us to overcome a limitation with the VMC rule search/filter


resource "nsxt_policy_group" "( group_name )" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "( group_name )"
  description  = "role: ( existing/valid object description | group_name ), ip: [( ip_addr_list )]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = [( ip_addr_list )]
    }
  }
}
========================================*/

resource "nsxt_policy_group" "ext-pres_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ext-pres_network"
  description  = "role: External Presentation Network, ip: [10.120.216.0/21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.0/21"]
    }
  }
}
resource "nsxt_policy_group" "ext-pres_all_pr-c-frontend_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ext-pres_all_pr-c-frontend_networks"
  description  = "role: All pr-c-frontend Networks, ip: [10.120.32.64/27, 10.120.33.0/29, 10.120.33.160/27, 10.120.37.0/24, 10.120.38.0/24, 10.120.39.0/24, 10.120.44.0/23, 10.120.46.0/25, 10.120.48.96/27, 10.120.50.0/24, 10.120.52.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.32.64/27", "10.120.33.0/29", "10.120.33.160/27", "10.120.37.0/24", "10.120.38.0/24", "10.120.39.0/24", "10.120.44.0/23", "10.120.46.0/25", "10.120.48.96/27", "10.120.50.0/24", "10.120.52.0/24"]
    }
  }
}
resource "nsxt_policy_group" "ext-pres_all_pr-n-frontend_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ext-pres_all_pr-n-frontend_networks"
  description  = "role: All pr-n-frontend Networks, ip: [10.120.64.0/27, 10.120.64.32/27, 10.120.64.64/27, 10.120.64.128/27, 10.120.64.160/27, 10.120.64.224/27, 10.120.66.0/24, 10.120.67.0/24, 10.120.69.96/27, 10.120.69.224/27, 10.120.69.192/27, 10.120.72.0/24, 10.120.70.0/27, 10.120.74.0/23, 10.120.65.64/27, 10.120.76.0/24, 10.120.65.96/27, 10.120.65.128/27, 10.120.98.0/24, 10.120.99.0/24, 10.120.100.0/24, 10.120.101.0/27, 10.120.102.0/24, 10.120.104.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.0/27", "10.120.64.32/27", "10.120.64.64/27", "10.120.64.128/27", "10.120.64.160/27", "10.120.64.224/27", "10.120.66.0/24", "10.120.67.0/24", "10.120.69.96/27", "10.120.69.224/27", "10.120.69.192/27", "10.120.72.0/24", "10.120.70.0/27", "10.120.74.0/23", "10.120.65.64/27", "10.120.76.0/24", "10.120.65.96/27", "10.120.65.128/27", "10.120.98.0/24", "10.120.99.0/24", "10.120.100.0/24", "10.120.101.0/27", "10.120.102.0/24", "10.120.104.0/27"]
    }
  }
}
resource "nsxt_policy_group" "ext-pres_all_pr-e-internal_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ext-pres_all_pr-e-internal_networks"
  description  = "role: All pr-e-internal Networks, ip: [10.120.162.0/24, 10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.0/24", "10.120.163.0/24"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

