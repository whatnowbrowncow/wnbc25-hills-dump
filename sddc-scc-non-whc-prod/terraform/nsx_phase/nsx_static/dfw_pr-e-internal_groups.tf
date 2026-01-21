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

resource "nsxt_policy_group" "pr-e-internal_ip_10-120-99-85" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-99-85"
  description  = "role: pr-e-internal_ip_10-120-99-85, ip: [10.120.99.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-26"
  description  = "role: pr-e-internal_ip_10-120-163-26, ip: [10.120.163.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-151"
  description  = "role: pr-e-internal_ip_10-120-129-151, ip: [10.120.129.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-134"
  description  = "role: pr-e-internal_ip_10-120-163-134, ip: [10.120.163.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-171"
  description  = "role: pr-e-internal_ip_10-120-143-171, ip: [10.120.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-89"
  description  = "role: pr-e-internal_ip_10-120-163-89, ip: [10.120.163.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-109"
  description  = "role: pr-e-internal_ip_10-121-10-109, ip: [10.121.10.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-13-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-13-33"
  description  = "role: pr-e-internal_ip_10-112-13-33, ip: [10.112.13.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.13.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-134-250" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-134-250"
  description  = "role: pr-e-internal_ip_10-120-134-250, ip: [10.120.134.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-100-9-73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-100-9-73"
  description  = "role: pr-e-internal_ip_10-100-9-73, ip: [10.100.9.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-201-230-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-201-230-17"
  description  = "role: pr-e-internal_ip_10-201-230-17, ip: [10.201.230.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.230.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-146-135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-146-135"
  description  = "role: pr-e-internal_ip_10-120-146-135, ip: [10.120.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-130" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-130"
  description  = "role: pr-e-internal_ip_10-120-163-130, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-136"
  description  = "role: pr-e-internal_ip_10-120-163-136, ip: [10.120.163.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-234"
  description  = "role: pr-e-internal_ip_10-180-163-234, ip: [10.180.163.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-234"
  description  = "role: pr-e-internal_ip_10-120-163-234, ip: [10.120.163.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-134-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-134-246"
  description  = "role: pr-e-internal_ip_10-120-134-246, ip: [10.120.134.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-193-132" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-193-132"
  description  = "role: pr-e-internal_ip_10-120-193-132, ip: [10.120.193.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-30"
  description  = "role: pr-e-internal_ip_10-120-46-30, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-31"
  description  = "role: pr-e-internal_ip_10-120-46-31, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-32"
  description  = "role: pr-e-internal_ip_10-120-46-32, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-237"
  description  = "role: pr-e-internal_ip_10-120-163-237, ip: [10.120.163.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-238"
  description  = "role: pr-e-internal_ip_10-120-163-238, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-239"
  description  = "role: pr-e-internal_ip_10-120-163-239, ip: [10.120.163.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-67"
  description  = "role: pr-e-internal_ip_10-120-180-67, ip: [10.120.180.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-212-180-138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-212-180-138"
  description  = "role: pr-e-internal_ip_10-212-180-138, ip: [10.212.180.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-214-180-138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-214-180-138"
  description  = "role: pr-e-internal_ip_10-214-180-138, ip: [10.214.180.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-10"
  description  = "role: pr-e-internal_ip_10-120-46-10, ip: [10.120.46.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-11"
  description  = "role: pr-e-internal_ip_10-120-46-11, ip: [10.120.46.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-12"
  description  = "role: pr-e-internal_ip_10-120-46-12, ip: [10.120.46.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-13"
  description  = "role: pr-e-internal_ip_10-120-46-13, ip: [10.120.46.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-14"
  description  = "role: pr-e-internal_ip_10-120-46-14, ip: [10.120.46.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-15"
  description  = "role: pr-e-internal_ip_10-120-46-15, ip: [10.120.46.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-16"
  description  = "role: pr-e-internal_ip_10-120-46-16, ip: [10.120.46.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-17"
  description  = "role: pr-e-internal_ip_10-120-46-17, ip: [10.120.46.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-18"
  description  = "role: pr-e-internal_ip_10-120-46-18, ip: [10.120.46.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-46-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-46-19"
  description  = "role: pr-e-internal_ip_10-120-46-19, ip: [10.120.46.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-172"
  description  = "role: pr-e-internal_ip_10-120-143-172, ip: [10.120.143.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-173" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-173"
  description  = "role: pr-e-internal_ip_10-120-143-173, ip: [10.120.143.173]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.173"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-182"
  description  = "role: pr-e-internal_ip_10-120-143-182, ip: [10.120.143.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-183"
  description  = "role: pr-e-internal_ip_10-120-143-183, ip: [10.120.143.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-130-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-130-36"
  description  = "role: pr-e-internal_ip_10-1-130-36, ip: [10.1.130.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.130.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-130-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-130-50"
  description  = "role: pr-e-internal_ip_10-1-130-50, ip: [10.1.130.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.130.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-99-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-99-220"
  description  = "role: pr-e-internal_ip_10-1-99-220, ip: [10.1.99.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.99.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-220"
  description  = "role: pr-e-internal_ip_10-120-129-220, ip: [10.120.129.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-4"
  description  = "role: pr-e-internal_ip_10-120-129-4, ip: [10.120.129.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-5"
  description  = "role: pr-e-internal_ip_10-120-129-5, ip: [10.120.129.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-160-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-160-68"
  description  = "role: pr-e-internal_ip_10-120-160-68, ip: [10.120.160.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.160.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-161-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-161-97"
  description  = "role: pr-e-internal_ip_10-120-161-97, ip: [10.120.161.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.161.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-92-100-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-92-100-13"
  description  = "role: pr-e-internal_ip_10-92-100-13, ip: [10.92.100.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.92.100.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-92-100-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-92-100-1"
  description  = "role: pr-e-internal_ip_10-92-100-1, ip: [10.92.100.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.92.100.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-92-100-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-92-100-5"
  description  = "role: pr-e-internal_ip_10-92-100-5, ip: [10.92.100.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.92.100.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-92-100-9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-92-100-9"
  description  = "role: pr-e-internal_ip_10-92-100-9, ip: [10.92.100.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.92.100.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-99-253-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-99-253-31"
  description  = "role: pr-e-internal_ip_10-99-253-31, ip: [10.99.253.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-99-253-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-99-253-41"
  description  = "role: pr-e-internal_ip_10-99-253-41, ip: [10.99.253.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-19"
  description  = "role: pr-e-internal_ip_10-120-129-19, ip: [10.120.129.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-177-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-177-37"
  description  = "role: pr-e-internal_ip_10-120-177-37, ip: [10.120.177.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-101"
  description  = "role: pr-e-internal_ip_10-120-180-101, ip: [10.120.180.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-102"
  description  = "role: pr-e-internal_ip_10-120-180-102, ip: [10.120.180.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-103"
  description  = "role: pr-e-internal_ip_10-120-180-103, ip: [10.120.180.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-104"
  description  = "role: pr-e-internal_ip_10-120-180-104, ip: [10.120.180.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-133" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-133"
  description  = "role: pr-e-internal_ip_10-120-180-133, ip: [10.120.180.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-134"
  description  = "role: pr-e-internal_ip_10-120-180-134, ip: [10.120.180.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-135"
  description  = "role: pr-e-internal_ip_10-120-180-135, ip: [10.120.180.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-136"
  description  = "role: pr-e-internal_ip_10-120-180-136, ip: [10.120.180.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-81"
  description  = "role: pr-e-internal_ip_10-120-180-81, ip: [10.120.180.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-82"
  description  = "role: pr-e-internal_ip_10-120-180-82, ip: [10.120.180.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-83"
  description  = "role: pr-e-internal_ip_10-120-180-83, ip: [10.120.180.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-180-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-180-84"
  description  = "role: pr-e-internal_ip_10-120-180-84, ip: [10.120.180.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-28-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-28-102"
  description  = "role: pr-e-internal_ip_10-1-28-102, ip: [10.1.28.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-28-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-28-26"
  description  = "role: pr-e-internal_ip_10-1-28-26, ip: [10.1.28.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-13-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-13-1"
  description  = "role: pr-e-internal_ip_10-112-13-1, ip: [10.112.13.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.13.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-97"
  description  = "role: pr-e-internal_ip_10-180-163-97, ip: [10.180.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-101"
  description  = "role: pr-e-internal_ip_10-210-163-101, ip: [10.210.163.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-211-163-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-211-163-101"
  description  = "role: pr-e-internal_ip_10-211-163-101, ip: [10.211.163.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.211.163.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-213-163-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-213-163-101"
  description  = "role: pr-e-internal_ip_10-213-163-101, ip: [10.213.163.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.163.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-215-163-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-215-163-101"
  description  = "role: pr-e-internal_ip_10-215-163-101, ip: [10.215.163.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.215.163.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-155" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-155"
  description  = "role: pr-e-internal_ip_10-120-163-155, ip: [10.120.163.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-156" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-156"
  description  = "role: pr-e-internal_ip_10-120-163-156, ip: [10.120.163.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-157" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-157"
  description  = "role: pr-e-internal_ip_10-120-163-157, ip: [10.120.163.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-158" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-158"
  description  = "role: pr-e-internal_ip_10-120-163-158, ip: [10.120.163.158]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.158"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-104"
  description  = "role: pr-e-internal_ip_10-112-12-104, ip: [10.112.12.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-105"
  description  = "role: pr-e-internal_ip_10-112-12-105, ip: [10.112.12.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-106"
  description  = "role: pr-e-internal_ip_10-112-12-106, ip: [10.112.12.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-107"
  description  = "role: pr-e-internal_ip_10-112-12-107, ip: [10.112.12.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-108"
  description  = "role: pr-e-internal_ip_10-112-12-108, ip: [10.112.12.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-109"
  description  = "role: pr-e-internal_ip_10-112-12-109, ip: [10.112.12.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-209" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-209"
  description  = "role: pr-e-internal_ip_10-120-163-209, ip: [10.120.163.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-43"
  description  = "role: pr-e-internal_ip_10-120-163-43, ip: [10.120.163.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-38"
  description  = "role: pr-e-internal_ip_10-180-163-38, ip: [10.180.163.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-39"
  description  = "role: pr-e-internal_ip_10-180-163-39, ip: [10.180.163.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-45"
  description  = "role: pr-e-internal_ip_10-180-163-45, ip: [10.180.163.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-46"
  description  = "role: pr-e-internal_ip_10-180-163-46, ip: [10.180.163.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-51"
  description  = "role: pr-e-internal_ip_10-180-163-51, ip: [10.180.163.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-52"
  description  = "role: pr-e-internal_ip_10-180-163-52, ip: [10.180.163.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_100-100-2-208" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_100-100-2-208"
  description  = "role: pr-e-internal_ip_100-100-2-208, ip: [100.100.2.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.100.2.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_100-100-2-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_100-100-2-55"
  description  = "role: pr-e-internal_ip_100-100-2-55, ip: [100.100.2.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.100.2.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-35"
  description  = "role: pr-e-internal_ip_10-120-163-35, ip: [10.120.163.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-170-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-170-100"
  description  = "role: pr-e-internal_ip_10-120-170-100, ip: [10.120.170.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.170.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-173-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-173-100"
  description  = "role: pr-e-internal_ip_10-120-173-100, ip: [10.120.173.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.173.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-177-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-177-38"
  description  = "role: pr-e-internal_ip_10-120-177-38, ip: [10.120.177.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-177-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-177-39"
  description  = "role: pr-e-internal_ip_10-120-177-39, ip: [10.120.177.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-4-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-4-11"
  description  = "role: pr-e-internal_ip_10-121-4-11, ip: [10.121.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-4-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-4-12"
  description  = "role: pr-e-internal_ip_10-121-4-12, ip: [10.121.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-5-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-5-11"
  description  = "role: pr-e-internal_ip_10-121-5-11, ip: [10.121.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-5-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-5-12"
  description  = "role: pr-e-internal_ip_10-121-5-12, ip: [10.121.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-110"
  description  = "role: pr-e-internal_ip_10-121-10-110, ip: [10.121.10.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-115"
  description  = "role: pr-e-internal_ip_10-121-10-115, ip: [10.121.10.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-4-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-4-205"
  description  = "role: pr-e-internal_ip_10-121-4-205, ip: [10.121.4.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-18"
  description  = "role: pr-e-internal_ip_10-120-163-18, ip: [10.120.163.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-27"
  description  = "role: pr-e-internal_ip_10-120-163-27, ip: [10.120.163.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-49"
  description  = "role: pr-e-internal_ip_10-120-163-49, ip: [10.120.163.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-74"
  description  = "role: pr-e-internal_ip_10-120-163-74, ip: [10.120.163.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-60"
  description  = "role: pr-e-internal_ip_10-120-129-60, ip: [10.120.129.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-61"
  description  = "role: pr-e-internal_ip_10-120-129-61, ip: [10.120.129.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-62"
  description  = "role: pr-e-internal_ip_10-120-129-62, ip: [10.120.129.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-63"
  description  = "role: pr-e-internal_ip_10-120-129-63, ip: [10.120.129.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-64"
  description  = "role: pr-e-internal_ip_10-120-129-64, ip: [10.120.129.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-65"
  description  = "role: pr-e-internal_ip_10-120-129-65, ip: [10.120.129.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-66"
  description  = "role: pr-e-internal_ip_10-120-129-66, ip: [10.120.129.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-67"
  description  = "role: pr-e-internal_ip_10-120-129-67, ip: [10.120.129.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-60"
  description  = "role: pr-e-internal_ip_10-180-129-60, ip: [10.180.129.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-61"
  description  = "role: pr-e-internal_ip_10-180-129-61, ip: [10.180.129.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-62"
  description  = "role: pr-e-internal_ip_10-180-129-62, ip: [10.180.129.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-63"
  description  = "role: pr-e-internal_ip_10-180-129-63, ip: [10.180.129.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-64"
  description  = "role: pr-e-internal_ip_10-180-129-64, ip: [10.180.129.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-65"
  description  = "role: pr-e-internal_ip_10-180-129-65, ip: [10.180.129.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-66"
  description  = "role: pr-e-internal_ip_10-180-129-66, ip: [10.180.129.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-67"
  description  = "role: pr-e-internal_ip_10-180-129-67, ip: [10.180.129.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-71"
  description  = "role: pr-e-internal_ip_10-180-163-71, ip: [10.180.163.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-70"
  description  = "role: pr-e-internal_ip_10-210-163-70, ip: [10.210.163.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-132-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-132-31"
  description  = "role: pr-e-internal_ip_10-120-132-31, ip: [10.120.132.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-132-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-132-32"
  description  = "role: pr-e-internal_ip_10-120-132-32, ip: [10.120.132.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-132-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-132-45"
  description  = "role: pr-e-internal_ip_10-120-132-45, ip: [10.120.132.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-132-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-132-46"
  description  = "role: pr-e-internal_ip_10-120-132-46, ip: [10.120.132.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-146-71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-146-71"
  description  = "role: pr-e-internal_ip_10-120-146-71, ip: [10.120.146.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-146-72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-146-72"
  description  = "role: pr-e-internal_ip_10-120-146-72, ip: [10.120.146.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-146-73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-146-73"
  description  = "role: pr-e-internal_ip_10-120-146-73, ip: [10.120.146.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-143-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-143-171"
  description  = "role: pr-e-internal_ip_10-210-143-171, ip: [10.210.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-243"
  description  = "role: pr-e-internal_ip_10-120-163-243, ip: [10.120.163.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-185"
  description  = "role: pr-e-internal_ip_10-120-143-185, ip: [10.120.143.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-143-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-143-185"
  description  = "role: pr-e-internal_ip_10-180-143-185, ip: [10.180.143.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.143.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-139-243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-139-243"
  description  = "role: pr-e-internal_ip_10-210-139-243, ip: [10.210.139.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-143-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-143-185"
  description  = "role: pr-e-internal_ip_10-210-143-185, ip: [10.210.143.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.143.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-130-252" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-130-252"
  description  = "role: pr-e-internal_ip_10-120-130-252, ip: [10.120.130.252]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.252"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-130-110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-130-110"
  description  = "role: pr-e-internal_ip_10-180-130-110, ip: [10.180.130.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-130-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-130-151"
  description  = "role: pr-e-internal_ip_10-180-130-151, ip: [10.180.130.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-130-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-130-68"
  description  = "role: pr-e-internal_ip_10-180-130-68, ip: [10.180.130.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-80-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-80-104"
  description  = "role: pr-e-internal_ip_10-180-80-104, ip: [10.180.80.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.80.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-80-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-80-98"
  description  = "role: pr-e-internal_ip_10-180-80-98, ip: [10.180.80.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.80.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-201-254-223" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-201-254-223"
  description  = "role: pr-e-internal_ip_10-201-254-223, ip: [10.201.254.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.254.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-115"
  description  = "role: pr-e-internal_ip_10-120-163-115, ip: [10.120.163.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-31"
  description  = "role: pr-e-internal_ip_10-120-163-31, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-32"
  description  = "role: pr-e-internal_ip_10-120-163-32, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-33"
  description  = "role: pr-e-internal_ip_10-120-163-33, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-34"
  description  = "role: pr-e-internal_ip_10-120-163-34, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-36"
  description  = "role: pr-e-internal_ip_10-120-163-36, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-79"
  description  = "role: pr-e-internal_ip_10-121-10-79, ip: [10.121.10.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-81"
  description  = "role: pr-e-internal_ip_10-121-10-81, ip: [10.121.10.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-82"
  description  = "role: pr-e-internal_ip_10-121-10-82, ip: [10.121.10.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-83"
  description  = "role: pr-e-internal_ip_10-121-10-83, ip: [10.121.10.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-84"
  description  = "role: pr-e-internal_ip_10-121-10-84, ip: [10.121.10.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-125" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-125"
  description  = "role: pr-e-internal_ip_10-112-12-125, ip: [10.112.12.125]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.125"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-126" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-126"
  description  = "role: pr-e-internal_ip_10-112-12-126, ip: [10.112.12.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-142"
  description  = "role: pr-e-internal_ip_10-112-12-142, ip: [10.112.12.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-143"
  description  = "role: pr-e-internal_ip_10-112-12-143, ip: [10.112.12.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-144"
  description  = "role: pr-e-internal_ip_10-112-12-144, ip: [10.112.12.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-122"
  description  = "role: pr-e-internal_ip_10-120-163-122, ip: [10.120.163.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-123" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-123"
  description  = "role: pr-e-internal_ip_10-120-163-123, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-142"
  description  = "role: pr-e-internal_ip_10-120-163-142, ip: [10.120.163.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-143"
  description  = "role: pr-e-internal_ip_10-120-163-143, ip: [10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-44-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-44-25"
  description  = "role: pr-e-internal_ip_10-120-44-25, ip: [10.120.44.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-44-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-44-26"
  description  = "role: pr-e-internal_ip_10-120-44-26, ip: [10.120.44.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-44-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-44-27"
  description  = "role: pr-e-internal_ip_10-120-44-27, ip: [10.120.44.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-145-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-145-40"
  description  = "role: pr-e-internal_ip_10-120-145-40, ip: [10.120.145.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-177-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-177-68"
  description  = "role: pr-e-internal_ip_10-120-177-68, ip: [10.120.177.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-143-85" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-143-85"
  description  = "role: pr-e-internal_ip_10-120-143-85, ip: [10.120.143.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_199-91-137-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_199-91-137-100"
  description  = "role: pr-e-internal_ip_199-91-137-100, ip: [199.91.137.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["199.91.137.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_37-98-232-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_37-98-232-100"
  description  = "role: pr-e-internal_ip_37-98-232-100, ip: [37.98.232.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["37.98.232.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-139-229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-139-229"
  description  = "role: pr-e-internal_ip_10-210-139-229, ip: [10.210.139.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-139-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-139-230"
  description  = "role: pr-e-internal_ip_10-210-139-230, ip: [10.210.139.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-139-231" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-139-231"
  description  = "role: pr-e-internal_ip_10-210-139-231, ip: [10.210.139.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-139-229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-139-229"
  description  = "role: pr-e-internal_ip_10-120-139-229, ip: [10.120.139.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-139-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-139-230"
  description  = "role: pr-e-internal_ip_10-120-139-230, ip: [10.120.139.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-139-231" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-139-231"
  description  = "role: pr-e-internal_ip_10-120-139-231, ip: [10.120.139.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-95"
  description  = "role: pr-e-internal_ip_10-210-163-95, ip: [10.210.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-96"
  description  = "role: pr-e-internal_ip_10-210-163-96, ip: [10.210.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-97"
  description  = "role: pr-e-internal_ip_10-210-163-97, ip: [10.210.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-98"
  description  = "role: pr-e-internal_ip_10-210-163-98, ip: [10.210.163.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-163-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-163-99"
  description  = "role: pr-e-internal_ip_10-210-163-99, ip: [10.210.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-211"
  description  = "role: pr-e-internal_ip_10-180-163-211, ip: [10.180.163.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-212"
  description  = "role: pr-e-internal_ip_10-180-163-212, ip: [10.180.163.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-213"
  description  = "role: pr-e-internal_ip_10-180-163-213, ip: [10.180.163.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-214"
  description  = "role: pr-e-internal_ip_10-180-163-214, ip: [10.180.163.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-218"
  description  = "role: pr-e-internal_ip_10-180-163-218, ip: [10.180.163.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-102"
  description  = "role: pr-e-internal_ip_10-180-163-102, ip: [10.180.163.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-220"
  description  = "role: pr-e-internal_ip_10-180-163-220, ip: [10.180.163.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-221"
  description  = "role: pr-e-internal_ip_10-180-163-221, ip: [10.180.163.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-163-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-163-40"
  description  = "role: pr-e-internal_ip_10-180-163-40, ip: [10.180.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-163-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-163-0s24"
  description  = "role: pr-e-internal_ip_10-120-163-0s24, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-10-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-10-0s24"
  description  = "role: pr-e-internal_ip_10-121-10-0s24, ip: [10.121.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-0-0s16"
  description  = "role: pr-e-internal_ip_10-120-0-0s16, ip: [10.120.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-121-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-121-0-0s16"
  description  = "role: pr-e-internal_ip_10-121-0-0s16, ip: [10.121.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-0-0-0s8"
  description  = "role: pr-e-internal_ip_10-0-0-0s8, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-3-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-3-0-0s24"
  description  = "role: pr-e-internal_ip_10-3-0-0s24, ip: [10.3.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-3-1-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-3-1-0s24"
  description  = "role: pr-e-internal_ip_10-3-1-0s24, ip: [10.3.1.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-3-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-3-99-0s24"
  description  = "role: pr-e-internal_ip_10-3-99-0s24, ip: [10.3.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-53-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-53-99-0s24"
  description  = "role: pr-e-internal_ip_10-53-99-0s24, ip: [10.53.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-53-113-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-53-113-0s24"
  description  = "role: pr-e-internal_ip_10-53-113-0s24, ip: [10.53.113.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.113.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-54-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-54-99-0s24"
  description  = "role: pr-e-internal_ip_10-54-99-0s24, ip: [10.54.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.54.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-129-0s24"
  description  = "role: pr-e-internal_ip_10-180-129-0s24, ip: [10.180.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-159-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-159-0s24"
  description  = "role: pr-e-internal_ip_10-180-159-0s24, ip: [10.180.159.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.159.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-152-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-152-0s23"
  description  = "role: pr-e-internal_ip_10-1-152-0s23, ip: [10.1.152.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.152.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-12-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-12-0s24"
  description  = "role: pr-e-internal_ip_10-112-12-0s24, ip: [10.112.12.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-129-0s24"
  description  = "role: pr-e-internal_ip_10-210-129-0s24, ip: [10.210.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-159-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-159-0s27"
  description  = "role: pr-e-internal_ip_10-210-159-0s27, ip: [10.210.159.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.159.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-164-192s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-164-192s27"
  description  = "role: pr-e-internal_ip_10-210-164-192s27, ip: [10.210.164.192/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.164.192/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-194-64s26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-194-64s26"
  description  = "role: pr-e-internal_ip_10-210-194-64s26, ip: [10.210.194.64/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.64/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-194-192s26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-194-192s26"
  description  = "role: pr-e-internal_ip_10-210-194-192s26, ip: [10.210.194.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.192/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_192-168-10-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_192-168-10-0s24"
  description  = "role: pr-e-internal_ip_192-168-10-0s24, ip: [192.168.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-129-0s24"
  description  = "role: pr-e-internal_ip_10-120-129-0s24, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-159-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-159-0s27"
  description  = "role: pr-e-internal_ip_10-120-159-0s27, ip: [10.120.159.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-159-96s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-159-96s27"
  description  = "role: pr-e-internal_ip_10-120-159-96s27, ip: [10.120.159.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-194-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-194-0s24"
  description  = "role: pr-e-internal_ip_10-120-194-0s24, ip: [10.120.194.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-55-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-55-99-0s24"
  description  = "role: pr-e-internal_ip_10-55-99-0s24, ip: [10.55.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-93-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-93-0-0s16"
  description  = "role: pr-e-internal_ip_10-93-0-0s16, ip: [10.93.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.93.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-94-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-94-0-0s16"
  description  = "role: pr-e-internal_ip_10-94-0-0s16, ip: [10.94.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.94.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-95-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-95-0-0s16"
  description  = "role: pr-e-internal_ip_10-95-0-0s16, ip: [10.95.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.95.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-96-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-96-0-0s16"
  description  = "role: pr-e-internal_ip_10-96-0-0s16, ip: [10.96.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.96.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-123-14-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-123-14-0s24"
  description  = "role: pr-e-internal_ip_10-123-14-0s24, ip: [10.123.14.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.14.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-123-142-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-123-142-0s24"
  description  = "role: pr-e-internal_ip_10-123-142-0s24, ip: [10.123.142.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.142.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-123-206-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-123-206-0s24"
  description  = "role: pr-e-internal_ip_10-123-206-0s24, ip: [10.123.206.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.206.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-99-239-224s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-99-239-224s27"
  description  = "role: pr-e-internal_ip_10-99-239-224s27, ip: [10.99.239.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.239.224/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-99-0s24"
  description  = "role: pr-e-internal_ip_10-1-99-0s24, ip: [10.1.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-56-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-56-99-0s24"
  description  = "role: pr-e-internal_ip_10-56-99-0s24, ip: [10.56.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-128-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-128-129-0s24"
  description  = "role: pr-e-internal_ip_10-128-129-0s24, ip: [10.128.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.128.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-98-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-98-0s24"
  description  = "role: pr-e-internal_ip_10-1-98-0s24, ip: [10.1.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-129-0s24"
  description  = "role: pr-e-internal_ip_10-112-129-0s24, ip: [10.112.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-99-253-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-99-253-0s24"
  description  = "role: pr-e-internal_ip_10-99-253-0s24, ip: [10.99.253.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-99-254-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-99-254-0s24"
  description  = "role: pr-e-internal_ip_10-99-254-0s24, ip: [10.99.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-19-0-96s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-19-0-96s27"
  description  = "role: pr-e-internal_ip_10-19-0-96s27, ip: [10.19.0.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.0.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-36-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-36-0s24"
  description  = "role: pr-e-internal_ip_10-1-36-0s24, ip: [10.1.36.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.36.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-130-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-130-129-0s24"
  description  = "role: pr-e-internal_ip_10-130-129-0s24, ip: [10.130.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-160-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-160-0s23"
  description  = "role: pr-e-internal_ip_10-120-160-0s23, ip: [10.120.160.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.160.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-105-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-105-0s24"
  description  = "role: pr-e-internal_ip_10-1-105-0s24, ip: [10.1.105.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.105.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-1-84-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-1-84-0s24"
  description  = "role: pr-e-internal_ip_10-1-84-0s24, ip: [10.1.84.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.84.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-32-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-32-0s24"
  description  = "role: pr-e-internal_ip_10-120-32-0s24, ip: [10.120.32.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.32.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-123-140-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-123-140-0s24"
  description  = "role: pr-e-internal_ip_10-123-140-0s24, ip: [10.123.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-159-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-159-0s24"
  description  = "role: pr-e-internal_ip_10-210-159-0s24, ip: [10.210.159.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.159.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-56-100-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-56-100-0s24"
  description  = "role: pr-e-internal_ip_10-56-100-0s24, ip: [10.56.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-92-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-92-0-0s16"
  description  = "role: pr-e-internal_ip_10-92-0-0s16, ip: [10.92.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.92.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_192-168-9-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_192-168-9-0s24"
  description  = "role: pr-e-internal_ip_192-168-9-0s24, ip: [192.168.9.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-159-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-159-0s27"
  description  = "role: pr-e-internal_ip_10-180-159-0s27, ip: [10.180.159.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.159.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-130-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-130-0s24"
  description  = "role: pr-e-internal_ip_10-120-130-0s24, ip: [10.120.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-120-80-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-120-80-0s24"
  description  = "role: pr-e-internal_ip_10-120-80-0s24, ip: [10.120.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-156-5-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-156-5-0s24"
  description  = "role: pr-e-internal_ip_10-156-5-0s24, ip: [10.156.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-0-0s16"
  description  = "role: pr-e-internal_ip_10-210-0-0s16, ip: [10.210.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-0-0s16"
  description  = "role: pr-e-internal_ip_10-180-0-0s16, ip: [10.180.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-112-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-112-0-0s16"
  description  = "role: pr-e-internal_ip_10-112-0-0s16, ip: [10.112.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-19-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-19-0-0s16"
  description  = "role: pr-e-internal_ip_10-19-0-0s16, ip: [10.19.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_0-0-0-0s0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_0-0-0-0s0"
  description  = "role: pr-e-internal_ip_0-0-0-0s0, ip: [0.0.0.0/0]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["0.0.0.0/0"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-100-254-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-100-254-0s24"
  description  = "role: pr-e-internal_ip_10-100-254-0s24, ip: [10.100.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-130-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-130-0s24"
  description  = "role: pr-e-internal_ip_10-180-130-0s24, ip: [10.180.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-180-80-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-180-80-0s24"
  description  = "role: pr-e-internal_ip_10-180-80-0s24, ip: [10.180.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-201-225-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-201-225-0s24"
  description  = "role: pr-e-internal_ip_10-201-225-0s24, ip: [10.201.225.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.225.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-201-254-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-201-254-0s24"
  description  = "role: pr-e-internal_ip_10-201-254-0s24, ip: [10.201.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-210-130-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-210-130-0s24"
  description  = "role: pr-e-internal_ip_10-210-130-0s24, ip: [10.210.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_192-168-48-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_192-168-48-0s20"
  description  = "role: pr-e-internal_ip_192-168-48-0s20, ip: [192.168.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_192-168-12-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_192-168-12-0s22"
  description  = "role: pr-e-internal_ip_192-168-12-0s22, ip: [192.168.12.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.12.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_192-168-16-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_192-168-16-0s22"
  description  = "role: pr-e-internal_ip_192-168-16-0s22, ip: [192.168.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-30-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-30-200-0s24"
  description  = "role: pr-e-internal_ip_10-30-200-0s24, ip: [10.30.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-30-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-30-202-0s24"
  description  = "role: pr-e-internal_ip_10-30-202-0s24, ip: [10.30.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-40-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-40-200-0s24"
  description  = "role: pr-e-internal_ip_10-40-200-0s24, ip: [10.40.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-40-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-40-202-0s24"
  description  = "role: pr-e-internal_ip_10-40-202-0s24, ip: [10.40.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ip_10-130-200-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ip_10-130-200-0s23"
  description  = "role: pr-e-internal_ip_10-130-200-0s23, ip: [10.130.200.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.200.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brs-git-nonprod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brs-git-nonprod-williamhill-plc"
  description  = "role: CHG0127786, ip: [10.201.230.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.230.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg30"
  description  = "role: CHG0125224, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn73"
  description  = "role: pr-e-internal_sc1wnpremn73, ip: [10.120.163.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnmem01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnmem01"
  description  = "role: CHG0117835, ip: [10.120.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg22"
  description  = "role: pr-e-internal_sc1uxpremg22, ip: [10.120.163.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_tufin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tufin"
  description  = "role: pr-e-internal_tufin, ip: [10.120.163.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxrdk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxrdk"
  description  = "role: pr-e-internal_sc1uxrdk, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn006"
  description  = "role: CHG0122369, ip: [10.120.163.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg31"
  description  = "role: CHG0115562, ip: [10.120.163.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_netbrain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_netbrain"
  description  = "role: pr-e-internal_netbrain, ip: [10.120.163.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gib-internal-traffic-mon" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gib-internal-traffic-mon"
  description  = "role: CHG0118366, ip: [10.120.163.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_prdxclo25srv001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_prdxclo25srv001-prod-williamhill-plc"
  description  = "role: pr-e-internal_prdxclo25srv001-prod-williamhill-plc, ip: [10.120.163.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg60"
  description  = "role: pr-e-internal_sc1uxpremg60, ip: [10.120.163.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_cran-r-project-org" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_cran-r-project-org"
  description  = "role: pr-e-internal_cran-r-project-org, ip: [137.208.57.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["137.208.57.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpreap242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpreap242"
  description  = "role: pr-e-internal_sc1uxpreap242, ip: [10.120.163.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg26"
  description  = "role: CHG0129308, ip: [10.120.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredb11-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredb11-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1wnpredb11-prod-williamhill-plc, ip: [10.120.163.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpredb11-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpredb11-prod-williamhill-plc"
  description  = "role: pr-e-internal_ld6wnpredb11-prod-williamhill-plc, ip: [10.112.12.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_in1-ilo-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_in1-ilo-net"
  description  = "role: CHG0135457, ip: [10.174.135.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.135.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcdb30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcdb30"
  description  = "role: pr-e-internal_sc1wnprcdb30, ip: [10.120.163.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprcdb30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprcdb30"
  description  = "role: pr-e-internal_ld6wnprcdb30, ip: [10.112.12.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prapvc01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prapvc01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prapvc01-prod-williamhill-plc, ip: [10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn17"
  description  = "role: pr-e-internal_sc1uxpremn17, ip: [10.120.163.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcmn250-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcmn250-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1wnprcmn250-prod-williamhill-plc, ip: [10.120.163.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn57"
  description  = "role: pr-e-internal_sc1wnpremn57, ip: [10.120.163.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremg32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremg32"
  description  = "role: CHG0129567, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_obmon-onshore" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_obmon-onshore"
  description  = "role: CHG0118366, ip: [10.120.163.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc_wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc_wsus"
  description  = "role: pr-e-internal_scc_wsus, ip: [10.120.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn81"
  description  = "role: CHG0139674, ip: [10.120.163.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn21"
  description  = "role: CHG0094217, ip: [10.120.163.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn74"
  description  = "role: CHG0067511, ip: [10.120.163.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1wnpremn01-prod-williamhill-plc, ip: [10.120.163.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremg44"
  description  = "role: pr-e-internal_sc1wnpremg44, ip: [10.120.163.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc"
  description  = "role: pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc, ip: [10.181.7.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.7.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc-nic2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc-nic2"
  description  = "role: pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc-nic2, ip: [10.181.7.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.7.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc-nessus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-nessus"
  description  = "role: pr-e-internal_scc-nessus, ip: [10.120.143.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-10-120-163-0_255-255-255-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-10-120-163-0_255-255-255-0"
  description  = "role: pr-e-internal_net-10-120-163-0_255-255-255-0, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-10-0-0-0_255-0-0-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-10-0-0-0_255-0-0-0"
  description  = "role: pr-e-internal_net-10-0-0-0_255-0-0-0, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_splunk-deploy-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_splunk-deploy-server"
  description  = "role: pr-e-internal_splunk-deploy-server, ip: [10.121.10.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpromn012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpromn012"
  description  = "role: pr-e-internal_sc1uxpromn012, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-10-120-216-0_255-255-248-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-10-120-216-0_255-255-248-0"
  description  = "role: pr-e-internal_net-10-120-216-0_255-255-248-0, ip: [10.120.216.0/21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.0/21"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-100-64-0-0slash10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-100-64-0-0slash10"
  description  = "role: pr-e-internal_aws-100-64-0-0slash10, ip: [100.64.0.0/10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.64.0.0/10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc_nimsoft_mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc_nimsoft_mgmt"
  description  = "role: CHG0070513, ip: [10.120.163.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc-ca-nfa-harvester" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-ca-nfa-harvester"
  description  = "role: CHG0077138, ip: [10.120.163.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_williamhillssl-cloudsoftcat-com" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_williamhillssl-cloudsoftcat-com"
  description  = "role: pr-e-internal_williamhillssl-cloudsoftcat-com, ip: [130.0.80.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["130.0.80.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremg45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremg45"
  description  = "role: pr-e-internal_sc1wnpremg45, ip: [10.120.163.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_williamhillssl-cloudsoftcat-com-secondary" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_williamhillssl-cloudsoftcat-com-secondary"
  description  = "role: pr-e-internal_williamhillssl-cloudsoftcat-com-secondary, ip: [130.0.80.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["130.0.80.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.125]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.125"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpremn79-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpremn79-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gib-cp-ext-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gib-cp-ext-1"
  description  = "role: pr-e-internal_gib-cp-ext-1, ip: [95.131.184.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["95.131.184.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpreap237_ip_10-120-163-237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpreap237_ip_10-120-163-237"
  description  = "role: pr-e-internal_sc1uxpreap237_ip_10-120-163-237, ip: [10.120.163.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpreap238_ip_10-120-163-238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpreap238_ip_10-120-163-238"
  description  = "role: pr-e-internal_sc1uxpreap238_ip_10-120-163-238, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpreap239_ip_10-120-163-239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpreap239_ip_10-120-163-239"
  description  = "role: pr-e-internal_sc1uxpreap239_ip_10-120-163-239, ip: [10.120.163.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-retail-prod-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-retail-prod-1"
  description  = "role: CHG0141604, ip: [100.73.16.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.73.16.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-retail-prod-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-retail-prod-2"
  description  = "role: CHG0141604, ip: [100.73.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.73.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-retail-prod-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-retail-prod-3"
  description  = "role: CHG0141604, ip: [100.73.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.73.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-brs-pp1-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-brs-pp1-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-brs-pp1-williamhill-plc, ip: [10.191.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.191.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-brs-pp2-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-brs-pp2-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-brs-pp2-williamhill-plc, ip: [10.193.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-brs-pp3-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-brs-pp3-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-brs-pp3-williamhill-plc, ip: [10.195.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-brs-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-brs-prod-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-brs-prod-williamhill-plc, ip: [10.241.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.241.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-gib-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-gib-prod-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-gib-prod-williamhill-plc, ip: [10.181.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-sc1-prod-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-sc1-prod-williamhill-plc, ip: [10.121.10.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_zoltan-brs-cxp-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_zoltan-brs-cxp-williamhill-plc"
  description  = "role: pr-e-internal_zoltan-brs-cxp-williamhill-plc, ip: [10.201.230.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.230.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1appresc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1appresc02"
  description  = "role: pr-e-internal_sc1appresc02, ip: [10.120.163.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1appresc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1appresc03"
  description  = "role: pr-e-internal_sc1appresc03, ip: [10.120.163.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcint01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcint01"
  description  = "role: CHG0134971, ip: [10.116.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcapi02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcapi02"
  description  = "role: CHG0134971, ip: [10.116.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcapi01"
  description  = "role: CHG0134971, ip: [10.116.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcint02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcint02"
  description  = "role: CHG0134971, ip: [10.116.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcextapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcextapi01"
  description  = "role: CHG0134971, ip: [10.116.7.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.7.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6pteadcextapi02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6pteadcextapi02"
  description  = "role: CHG0134971, ip: [10.116.7.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.7.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcint01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcint01"
  description  = "role: CHG0134971, ip: [10.122.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcint02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcint02"
  description  = "role: CHG0134971, ip: [10.122.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcapi01"
  description  = "role: CHG0134971, ip: [10.122.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcapi02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcapi02"
  description  = "role: CHG0134971, ip: [10.122.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcext01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcext01"
  description  = "role: CHG0134971, ip: [10.122.6.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.6.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcext02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcext02"
  description  = "role: CHG0134971, ip: [10.122.6.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.6.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp1adcapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp1adcapi01"
  description  = "role: CHG0134971, ip: [10.191.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.191.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp1adcapi02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp1adcapi02"
  description  = "role: CHG0134971, ip: [10.191.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.191.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brspp1adcextapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brspp1adcextapi01"
  description  = "role: CHG0134971, ip: [10.191.7.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.191.7.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp2adcint01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp2adcint01"
  description  = "role: CHG0134971, ip: [10.193.4.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.4.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp2adcapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp2adcapi01"
  description  = "role: CHG0134971, ip: [10.193.5.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.5.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brspp2adcextapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brspp2adcextapi01"
  description  = "role: CHG0134971, ip: [10.193.7.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.7.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp3adcint01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp3adcint01"
  description  = "role: CHG0134971, ip: [10.195.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_pp3adcapi01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_pp3adcapi01"
  description  = "role: CHG0134971, ip: [10.195.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcint01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcint01"
  description  = "role: CHG0134971, ip: [10.241.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.241.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcint02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcint02"
  description  = "role: CHG0134971, ip: [10.241.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.241.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibuxpredb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibuxpredb01"
  description  = "role: pr-e-internal_gibuxpredb01, ip: [10.180.163.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.112.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprbkcs01"
  description  = "role: CHG0112231, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibx9002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibx9002"
  description  = "role: pr-e-internal_gibx9002, ip: [10.180.143.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.143.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-172-16-0-0_255-240-0-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-172-16-0-0_255-240-0-0"
  description  = "role: pr-e-internal_net-172-16-0-0_255-240-0-0, ip: [172.16.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-192-168-0-0_255-255-0-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-192-168-0-0_255-255-0-0"
  description  = "role: pr-e-internal_net-192-168-0-0_255-255-0-0, ip: [192.168.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn137-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn137-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1uxpremn137-prod-williamhill-plc, ip: [10.120.163.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_am1xuim01col001-am1-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_am1xuim01col001-am1-williamhill-plc"
  description  = "role: pr-e-internal_am1xuim01col001-am1-williamhill-plc, ip: [10.125.159.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.159.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_am1xuim01col002-am1-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_am1xuim01col002-am1-williamhill-plc"
  description  = "role: pr-e-internal_am1xuim01col002-am1-williamhill-plc, ip: [10.125.156.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.156.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_njpxuim01col001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_njpxuim01col001"
  description  = "role: pr-e-internal_njpxuim01col001, ip: [100.100.8.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.100.8.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_njpxuim01col002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_njpxuim01col002"
  description  = "role: pr-e-internal_njpxuim01col002, ip: [100.100.8.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.100.8.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-ssn-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-ssn-mgmt"
  description  = "role: pr-e-internal_aws-ssn-mgmt, ip: [100.79.162.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.162.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_aws-ssp-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_aws-ssp-mgmt"
  description  = "role: pr-e-internal_aws-ssp-mgmt, ip: [100.79.130.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.130.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-163-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-163-31"
  description  = "role: pr-e-internal_10-120-163-31, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-163-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-163-32"
  description  = "role: pr-e-internal_10-120-163-32, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-163-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-163-33"
  description  = "role: pr-e-internal_10-120-163-33, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-163-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-163-34"
  description  = "role: pr-e-internal_10-120-163-34, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gi-mpl-es01-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gi-mpl-es01-vl20"
  description  = "role: pr-e-internal_gi-mpl-es01-vl20, ip: [95.131.184.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["95.131.184.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gi-mpl-es02-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gi-mpl-es02-vl20"
  description  = "role: pr-e-internal_gi-mpl-es02-vl20, ip: [95.131.184.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["95.131.184.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-brs-es01-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-brs-es01-vl20"
  description  = "role: pr-e-internal_uk-brs-es01-vl20, ip: [141.138.129.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.129.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-brs-es02-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-brs-es02-vl20"
  description  = "role: pr-e-internal_uk-brs-es02-vl20, ip: [141.138.129.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.129.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-ld6-es01-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-ld6-es01-vl20"
  description  = "role: pr-e-internal_uk-ld6-es01-vl20, ip: [185.119.152.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["185.119.152.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-ld6-es02-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-ld6-es02-vl20"
  description  = "role: pr-e-internal_uk-ld6-es02-vl20, ip: [185.119.152.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["185.119.152.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-es01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-es01"
  description  = "role: CHG0077662, ip: [141.138.128.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-es02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-es02"
  description  = "role: CHG0077662, ip: [141.138.128.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-174-104-0_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-174-104-0_24"
  description  = "role: CHG0129192, ip: [10.174.104.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.104.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-174-111-128_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-174-111-128_25"
  description  = "role: CHG0129192, ip: [10.174.111.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.111.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-1"
  description  = "role: pr-e-internal_10-129-11-1, ip: [10.129.11.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-2"
  description  = "role: pr-e-internal_10-129-11-2, ip: [10.129.11.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-3"
  description  = "role: pr-e-internal_10-129-11-3, ip: [10.129.11.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-4"
  description  = "role: pr-e-internal_10-129-11-4, ip: [10.129.11.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-5"
  description  = "role: pr-e-internal_10-129-11-5, ip: [10.129.11.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-6"
  description  = "role: pr-e-internal_10-129-11-6, ip: [10.129.11.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-7"
  description  = "role: pr-e-internal_10-129-11-7, ip: [10.129.11.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-129-11-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-129-11-8"
  description  = "role: pr-e-internal_10-129-11-8, ip: [10.129.11.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn20a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn20a"
  description  = "role: pr-e-internal_sc1wnpremn20a, ip: [10.120.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn21a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn21a"
  description  = "role: pr-e-internal_sc1wnpremn21a, ip: [10.120.163.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn79"
  description  = "role: pr-e-internal_sc1uxpremn79, ip: [10.120.163.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein04-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein04-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein04-prod-williamhill-plc, ip: [10.120.140.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein05-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein05-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein05-prod-williamhill-plc, ip: [10.120.140.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein06-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein06-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein06-prod-williamhill-plc, ip: [10.120.140.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein07-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein07-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein07-prod-williamhill-plc, ip: [10.120.140.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein08-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein08-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein08-prod-williamhill-plc, ip: [10.120.140.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein09-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein09-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein09-prod-williamhill-plc, ip: [10.120.140.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein10-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein10-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein10-prod-williamhill-plc, ip: [10.120.140.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein11-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein11-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein11-prod-williamhill-plc, ip: [10.120.140.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein12-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein12-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein12-prod-williamhill-plc, ip: [10.120.140.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1apprein13-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1apprein13-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1apprein13-prod-williamhill-plc, ip: [10.120.140.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcclb01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcclb01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcclb01-prod-williamhill-plc, ip: [10.120.44.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcclb02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcclb02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcclb02-prod-williamhill-plc, ip: [10.120.44.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcnlb01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcnlb01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcnlb01-prod-williamhill-plc, ip: [10.120.74.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcnlb02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcnlb02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcnlb02-prod-williamhill-plc, ip: [10.120.74.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sccadcrprapi01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sccadcrprapi01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sccadcrprapi01-prod-williamhill-plc, ip: [10.120.172.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.172.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sccadcrprapi02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sccadcrprapi02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sccadcrprapi02-prod-williamhill-plc, ip: [10.120.172.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.172.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-100-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-100-82"
  description  = "role: pr-e-internal_10-120-100-82, ip: [10.120.100.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-200-100-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-200-100-82"
  description  = "role: pr-e-internal_10-200-100-82, ip: [10.200.100.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.100.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-100-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-100-83"
  description  = "role: pr-e-internal_10-120-100-83, ip: [10.120.100.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-200-100-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-200-100-83"
  description  = "role: pr-e-internal_10-200-100-83, ip: [10.200.100.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.100.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-100-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-100-84"
  description  = "role: pr-e-internal_10-120-100-84, ip: [10.120.100.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-200-100-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-200-100-84"
  description  = "role: pr-e-internal_10-200-100-84, ip: [10.200.100.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.100.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-100-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-100-80"
  description  = "role: pr-e-internal_10-120-100-80, ip: [10.120.100.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-200-100-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-200-100-80"
  description  = "role: pr-e-internal_10-200-100-80, ip: [10.200.100.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.100.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswndrndb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswndrndb003"
  description  = "role: pr-e-internal_brswndrndb003, ip: [10.210.149.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.149.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswndrndb004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswndrndb004"
  description  = "role: pr-e-internal_brswndrndb004, ip: [10.210.149.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.149.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnppndb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnppndb002"
  description  = "role: pr-e-internal_brswnppndb002, ip: [10.1.29.245]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.245"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnppndb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnppndb003"
  description  = "role: pr-e-internal_brswnppndb003, ip: [10.1.29.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb01"
  description  = "role: pr-e-internal_sc1wnprgdb01, ip: [10.120.146.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb02"
  description  = "role: pr-e-internal_sc1wnprgdb02, ip: [10.120.146.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb03"
  description  = "role: pr-e-internal_sc1wnprgdb03, ip: [10.120.146.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb003_ip_10-120-149-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb003_ip_10-120-149-25"
  description  = "role: pr-e-internal_sc1wnprndb003_ip_10-120-149-25, ip: [10.120.149.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb004_ip_10-120-149-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb004_ip_10-120-149-26"
  description  = "role: pr-e-internal_sc1wnprndb004_ip_10-120-149-26, ip: [10.120.149.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb005_ip_10-120-149-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb005_ip_10-120-149-27"
  description  = "role: pr-e-internal_sc1wnprndb005_ip_10-120-149-27, ip: [10.120.149.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb006_ip_10-120-149-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb006_ip_10-120-149-28"
  description  = "role: pr-e-internal_sc1wnprndb006_ip_10-120-149-28, ip: [10.120.149.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrcs01"
  description  = "role: pr-e-internal_sc1wnprrcs01, ip: [10.120.180.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrcs02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrcs02"
  description  = "role: pr-e-internal_sc1wnprrcs02, ip: [10.120.180.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrto02_ip_10-120-180-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrto02_ip_10-120-180-59"
  description  = "role: pr-e-internal_sc1wnprrto02_ip_10-120-180-59, ip: [10.120.180.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrtp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrtp01"
  description  = "role: pr-e-internal_sc1wnprrtp01, ip: [10.120.180.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwn400" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwn400"
  description  = "role: pr-e-internal_gibwn400, ip: [10.180.33.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb05"
  description  = "role: pr-e-internal_sc1wnprgdb05, ip: [10.120.99.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb05-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb05-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb06"
  description  = "role: pr-e-internal_sc1wnprgdb06, ip: [10.120.99.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb06-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb06-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_corpservicessql-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_corpservicessql-prod-williamhill-plc"
  description  = "role: CHG0146032, ip: [10.120.99.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_corpservicessql-prod-williamhill-plc-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_corpservicessql-prod-williamhill-plc-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb05_06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb05_06"
  description  = "role: pr-e-internal_sc1wnprgdb05_06, ip: [10.120.99.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn74"
  description  = "role: CHG0123314, ip: [10.120.163.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn75"
  description  = "role: CHG0123314, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn77"
  description  = "role: pr-e-internal_sc1wnpremn77, ip: [10.120.163.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremn78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremn78"
  description  = "role: pr-e-internal_sc1wnpremn78, ip: [10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-143-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-143-171"
  description  = "role: pr-e-internal_10-180-143-171, ip: [10.180.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn105"
  description  = "role: pr-e-internal_sc1uxpremn105, ip: [10.120.163.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn106"
  description  = "role: pr-e-internal_sc1uxpremn106, ip: [10.120.163.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn107"
  description  = "role: pr-e-internal_sc1uxpremn107, ip: [10.120.163.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn108"
  description  = "role: pr-e-internal_sc1uxpremn108, ip: [10.120.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn120"
  description  = "role: pr-e-internal_sc1uxpremn120, ip: [10.120.163.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn121"
  description  = "role: pr-e-internal_sc1uxpremn121, ip: [10.120.163.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsppapvc01-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsppapvc01-group-williamhill-plc"
  description  = "role: pr-e-internal_brsppapvc01-group-williamhill-plc, ip: [10.201.226.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.226.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibprapvc01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibprapvc01-prod-williamhill-plc"
  description  = "role: pr-e-internal_gibprapvc01-prod-williamhill-plc, ip: [10.180.138.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.138.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6prapvc01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6prapvc01-prod-williamhill-plc"
  description  = "role: pr-e-internal_ld6prapvc01-prod-williamhill-plc, ip: [10.112.8.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.8.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprgdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprgdb01"
  description  = "role: pr-e-internal_sc1uxprgdb01, ip: [10.120.146.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprgdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprgdb05"
  description  = "role: pr-e-internal_sc1uxprgdb05, ip: [10.120.146.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprodb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprodb001"
  description  = "role: pr-e-internal_sc1uxprodb001, ip: [10.120.146.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprodb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprodb002"
  description  = "role: pr-e-internal_sc1uxprodb002, ip: [10.120.146.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprtdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprtdb001"
  description  = "role: pr-e-internal_sc1uxprtdb001, ip: [10.120.180.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_bfawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_bfawnpredc01"
  description  = "role: pr-e-internal_bfawnpredc01, ip: [10.56.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnpredc01"
  description  = "role: CHG0138309, ip: [10.210.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnpredc02_ip_10-210-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnpredc02_ip_10-210-194-12"
  description  = "role: CHG0141790, ip: [10.210.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnpredc03-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnpredc03-chg0144834"
  description  = "role: CHG0144834, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnpredc02_ip_10-180-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnpredc02_ip_10-180-194-12"
  description  = "role: CHG0141790, ip: [10.180.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnpredc03_ip_10-180-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnpredc03_ip_10-180-194-13"
  description  = "role: CHG0141790, ip: [10.180.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_irewnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_irewnprdc01"
  description  = "role: CHG0140344, ip: [100.72.225.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_irewnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_irewnprdc02"
  description  = "role: CHG0140344, ip: [100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_nvawnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_nvawnprdc01"
  description  = "role: CHG0140344, ip: [100.97.1.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_nvawnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_nvawnprdc02"
  description  = "role: CHG0140344, ip: [100.97.1.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_krawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_krawnpredc01"
  description  = "role: pr-e-internal_krawnpredc01, ip: [10.55.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_krawnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_krawnpredc02"
  description  = "role: pr-e-internal_krawnpredc02, ip: [10.55.9.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpredc01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpredc01-new"
  description  = "role: CHG0141790, ip: [10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpredc02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpredc02-new"
  description  = "role: CHG0141790, ip: [10.19.2.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_mnlwnpredc02_ip_10-123-197-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_mnlwnpredc02_ip_10-123-197-11"
  description  = "role: CHG0141790, ip: [10.123.197.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_mnlwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_mnlwnpredc03"
  description  = "role: pr-e-internal_mnlwnpredc03, ip: [10.123.197.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc01"
  description  = "role: CHG0138309, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc02"
  description  = "role: CHG0138309, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc03_ip_10-120-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc03_ip_10-120-194-13"
  description  = "role: CHG0141790, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc04_ip_10-120-194-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc04_ip_10-120-194-14"
  description  = "role: CHG0141790, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc05_ip_10-120-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc05_ip_10-120-194-15"
  description  = "role: CHG0141790, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredc08_ip_10-120-194-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredc08_ip_10-120-194-18"
  description  = "role: CHG0141790, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sofwnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sofwnpredc01"
  description  = "role: pr-e-internal_sofwnpredc01, ip: [10.53.98.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sofwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sofwnpredc02"
  description  = "role: pr-e-internal_sofwnpredc02, ip: [10.53.98.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_net-10-120-162-0_255-255-255-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_net-10-120-162-0_255-255-255-0"
  description  = "role: pr-e-internal_net-10-120-162-0_255-255-255-0, ip: [10.120.162.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein04-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein04-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein04-prod-williamhill-plc, ip: [10.210.140.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein05-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein05-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein05-prod-williamhill-plc, ip: [10.210.140.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein06-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein06-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein06-prod-williamhill-plc, ip: [10.210.140.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein07-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein07-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein07-prod-williamhill-plc, ip: [10.210.140.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein08-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein08-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein08-prod-williamhill-plc, ip: [10.210.140.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein09-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein09-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein09-prod-williamhill-plc, ip: [10.210.140.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein10-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein10-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein10-prod-williamhill-plc, ip: [10.210.140.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprein11-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprein11-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsapprein11-prod-williamhill-plc, ip: [10.210.140.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcclb01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcclb01-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcclb01-prod-williamhill-plc, ip: [10.210.44.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.44.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcclb02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcclb02-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcclb02-prod-williamhill-plc, ip: [10.210.44.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.44.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcint01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcint01-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcint01-prod-williamhill-plc, ip: [10.214.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcint02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcint02-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcint02-prod-williamhill-plc, ip: [10.214.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcnlb01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcnlb01-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcnlb01-prod-williamhill-plc, ip: [10.210.74.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.74.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsprdadcnlb02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsprdadcnlb02-prod-williamhill-plc"
  description  = "role: pr-e-internal_brsprdadcnlb02-prod-williamhill-plc, ip: [10.210.74.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.74.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcapi01-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcapi01-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcapi01-inv-williamhill-plc, ip: [10.122.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcapi02-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcapi02-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcapi02-inv-williamhill-plc, ip: [10.122.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcext01-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcext01-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcext01-inv-williamhill-plc, ip: [10.122.6.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.6.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcext02-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcext02-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcext02-inv-williamhill-plc, ip: [10.122.6.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.6.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcint01-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcint01-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcint01-inv-williamhill-plc, ip: [10.122.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1invadcint02-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1invadcint02-inv-williamhill-plc"
  description  = "role: pr-e-internal_sc1invadcint02-inv-williamhill-plc, ip: [10.122.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcapi01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcapi01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcapi01-prod-williamhill-plc, ip: [10.122.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcapi02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcapi02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcapi02-prod-williamhill-plc, ip: [10.122.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcint01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcint01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcint01-prod-williamhill-plc, ip: [10.121.4.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcint02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcint02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcint02-prod-williamhill-plc, ip: [10.121.4.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswndremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswndremg002"
  description  = "role: pr-e-internal_brswndremg002, ip: [10.210.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpremg002"
  description  = "role: pr-e-internal_sc1wnpremg002, ip: [10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc-nms-hub-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-nms-hub-dr"
  description  = "role: pr-e-internal_scc-nms-hub-dr, ip: [10.120.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_scc-nms-hub-live" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-nms-hub-live"
  description  = "role: pr-e-internal_scc-nms-hub-live, ip: [10.120.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb0506" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb0506"
  description  = "role: pr-e-internal_sc1wnprgdb0506, ip: [10.120.146.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-1-86-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-1-86-31"
  description  = "role: pr-e-internal_10-1-86-31, ip: [10.1.86.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-146-116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-146-116"
  description  = "role: pr-e-internal_10-120-146-116, ip: [10.120.146.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_cessql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_cessql"
  description  = "role: pr-e-internal_cessql, ip: [10.120.180.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnstrdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnstrdb001"
  description  = "role: pr-e-internal_brswnstrdb001, ip: [10.1.28.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnpredb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnpredb01"
  description  = "role: pr-e-internal_sc1wnpredb01, ip: [10.120.134.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprevo01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprevo01"
  description  = "role: pr-e-internal_sc1wnprevo01, ip: [10.120.194.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprgdb13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprgdb13"
  description  = "role: pr-e-internal_sc1wnprgdb13, ip: [10.120.146.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb019"
  description  = "role: pr-e-internal_sc1wnprndb019, ip: [10.120.146.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrdb01"
  description  = "role: pr-e-internal_sc1wnprrdb01, ip: [10.120.180.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrto01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrto01"
  description  = "role: pr-e-internal_sc1wnprrto01, ip: [10.120.180.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprrto02_ip_10-120-180-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprrto02_ip_10-120-180-54"
  description  = "role: pr-e-internal_sc1wnprrto02_ip_10-120-180-54, ip: [10.120.180.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_w7d-dbjump" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_w7d-dbjump"
  description  = "role: pr-e-internal_w7d-dbjump, ip: [10.120.149.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn002-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn002-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1uxpremn002-prod-williamhill-plc, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn003-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn003-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1uxpremn003-prod-williamhill-plc, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsapprcmg002-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsapprcmg002-group-williamhill-plc"
  description  = "role: CHG0142765, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn002"
  description  = "role: CHG0142763, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpremn003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpremn003"
  description  = "role: CHG0142763, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_splunkdeployment-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_splunkdeployment-sc1-prod-williamhill-plc"
  description  = "role: CHG0142763, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprbkms01"
  description  = "role: CHG0112231, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprbkms02"
  description  = "role: CHG0112231, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxprbkms03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxprbkms03"
  description  = "role: CHG0112231, ip: [10.112.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxprbkms04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxprbkms04"
  description  = "role: CHG0112231, ip: [10.112.46.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxprbkms01"
  description  = "role: CHG0112231, ip: [10.112.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxprbkms02"
  description  = "role: CHG0112231, ip: [10.112.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibuxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibuxprbkms01"
  description  = "role: CHG0112231, ip: [10.180.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibuxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibuxprbkms02"
  description  = "role: CHG0112231, ip: [10.180.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnpredc03"
  description  = "role: pr-e-internal_brswnpredc03, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpredc01"
  description  = "role: pr-e-internal_ld6wnpredc01, ip: [10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnpredc02"
  description  = "role: pr-e-internal_ld6wnpredc02, ip: [10.19.2.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_int-10-180-36-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_int-10-180-36-10"
  description  = "role: pr-e-internal_int-10-180-36-10, ip: [10.180.36.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.36.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_int-10-180-37-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_int-10-180-37-51"
  description  = "role: pr-e-internal_int-10-180-37-51, ip: [10.180.37.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.37.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_int-10-180-37-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_int-10-180-37-52"
  description  = "role: pr-e-internal_int-10-180-37-52, ip: [10.180.37.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.37.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_int-10-180-37-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_int-10-180-37-53"
  description  = "role: pr-e-internal_int-10-180-37-53, ip: [10.180.37.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.37.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_int-10-180-37-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_int-10-180-37-54"
  description  = "role: pr-e-internal_int-10-180-37-54, ip: [10.180.37.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.37.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-121-5-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-121-5-0slash24"
  description  = "role: pr-e-internal_10-121-5-0slash24, ip: [10.121.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-121-7-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-121-7-0slash24"
  description  = "role: pr-e-internal_10-121-7-0slash24, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsns01"
  description  = "role: pr-e-internal_brsns01, ip: [10.210.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsns02"
  description  = "role: pr-e-internal_brsns02, ip: [10.210.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibns01"
  description  = "role: pr-e-internal_gibns01, ip: [10.180.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibns02"
  description  = "role: pr-e-internal_gibns02, ip: [10.180.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1ns01"
  description  = "role: pr-e-internal_sc1ns01, ip: [10.120.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1ns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1ns02"
  description  = "role: pr-e-internal_sc1ns02, ip: [10.120.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6ns01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6ns01-new"
  description  = "role: pr-e-internal_ld6ns01-new, ip: [10.112.208.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6ns02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6ns02-new"
  description  = "role: pr-e-internal_ld6ns02-new, ip: [10.112.208.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost01"
  description  = "role: pr-e-internal_emailhost01, ip: [10.120.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost02"
  description  = "role: pr-e-internal_emailhost02, ip: [10.120.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost03"
  description  = "role: pr-e-internal_emailhost03, ip: [10.210.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost04"
  description  = "role: pr-e-internal_emailhost04, ip: [10.210.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost05"
  description  = "role: pr-e-internal_emailhost05, ip: [10.180.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_emailhost06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_emailhost06"
  description  = "role: pr-e-internal_emailhost06, ip: [10.180.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_clp-splunk-license-master-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_clp-splunk-license-master-prod-williamhill-plc"
  description  = "role: pr-e-internal_clp-splunk-license-master-prod-williamhill-plc, ip: [10.120.163.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux910"
  description  = "role: pr-e-internal_brsux910, ip: [10.1.28.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibux910"
  description  = "role: pr-e-internal_gibux910, ip: [10.180.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxpreds01"
  description  = "role: pr-e-internal_ld6uxpreds01, ip: [10.112.12.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpreds01"
  description  = "role: pr-e-internal_sc1uxpreds01, ip: [10.120.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprncp001-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprncp001-mgmt-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1wnprncp001-mgmt-prod-williamhill-plc, ip: [10.120.146.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxpredb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxpredb01"
  description  = "role: pr-e-internal_sc1uxpredb01, ip: [10.120.163.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprnap43_44vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprnap43_44vip"
  description  = "role: pr-e-internal_sc1uxprnap43_44vip, ip: [10.120.99.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprndb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprndb001"
  description  = "role: pr-e-internal_sc1uxprndb001, ip: [10.120.146.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprndb95_96vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprndb95_96vip"
  description  = "role: pr-e-internal_sc1uxprndb95_96vip, ip: [10.120.99.91]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.91"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb"
  description  = "role: pr-e-internal_sc1uxprrdb, ip: [10.120.146.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrvr05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrvr05"
  description  = "role: pr-e-internal_sc1uxprrvr05, ip: [10.120.180.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrvr06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrvr06"
  description  = "role: pr-e-internal_sc1uxprrvr06, ip: [10.120.180.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprecp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprecp01"
  description  = "role: pr-e-internal_sc1wnprecp01, ip: [10.120.146.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprndb037_38vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprndb037_38vip"
  description  = "role: pr-e-internal_sc1uxprndb037_38vip, ip: [10.120.98.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.98.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprnwb87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprnwb87"
  description  = "role: pr-e-internal_sc1wnprnwb87, ip: [10.120.146.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb003_ip_10-120-100-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb003_ip_10-120-100-17"
  description  = "role: pr-e-internal_sc1wnprndb003_ip_10-120-100-17, ip: [10.120.100.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb004_ip_10-120-100-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb004_ip_10-120-100-18"
  description  = "role: pr-e-internal_sc1wnprndb004_ip_10-120-100-18, ip: [10.120.100.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb005_ip_10-120-100-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb005_ip_10-120-100-19"
  description  = "role: pr-e-internal_sc1wnprndb005_ip_10-120-100-19, ip: [10.120.100.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprndb006_ip_10-120-100-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprndb006_ip_10-120-100-20"
  description  = "role: pr-e-internal_sc1wnprndb006_ip_10-120-100-20, ip: [10.120.100.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_host-10-121-5-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_host-10-121-5-11"
  description  = "role: pr-e-internal_host-10-121-5-11, ip: [10.121.5.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_host-10-121-5-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_host-10-121-5-12"
  description  = "role: pr-e-internal_host-10-121-5-12, ip: [10.121.5.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprnap024-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprnap024-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1wnprnap024-prod-williamhill-plc, ip: [10.120.100.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnprcmg41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnprcmg41"
  description  = "role: CHG0123314, ip: [10.210.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnprcmg42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnprcmg42"
  description  = "role: CHG0123314, ip: [10.210.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnprcmg43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnprcmg43"
  description  = "role: CHG0123314, ip: [10.210.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brswnprcmg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brswnprcmg44"
  description  = "role: CHG0123314, ip: [10.210.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnprcmg41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnprcmg41"
  description  = "role: CHG0123314, ip: [10.180.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnprcmg42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnprcmg42"
  description  = "role: CHG0123314, ip: [10.180.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnprcmg43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnprcmg43"
  description  = "role: CHG0123314, ip: [10.180.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibwnprcmg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibwnprcmg44"
  description  = "role: CHG0123314, ip: [10.180.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprcmg41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprcmg41"
  description  = "role: CHG0123314, ip: [10.112.12.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprcmg42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprcmg42"
  description  = "role: CHG0123314, ip: [10.112.12.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprcmg43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprcmg43"
  description  = "role: CHG0123314, ip: [10.112.12.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6wnprcmg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6wnprcmg44"
  description  = "role: CHG0123314, ip: [10.112.12.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcmg41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcmg41"
  description  = "role: pr-e-internal_sc1wnprcmg41, ip: [10.120.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcmg42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcmg42"
  description  = "role: pr-e-internal_sc1wnprcmg42, ip: [10.120.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcmg43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcmg43"
  description  = "role: pr-e-internal_sc1wnprcmg43, ip: [10.120.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1wnprcmg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1wnprcmg44"
  description  = "role: pr-e-internal_sc1wnprcmg44, ip: [10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_rackspace_nimsoft_ch_dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_rackspace_nimsoft_ch_dr"
  description  = "role: pr-e-internal_rackspace_nimsoft_ch_dr, ip: [134.213.60.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["134.213.60.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_rackspace_nimsoft_ch_live" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_rackspace_nimsoft_ch_live"
  description  = "role: pr-e-internal_rackspace_nimsoft_ch_live, ip: [134.213.60.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["134.213.60.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-er01-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-er01-lo0"
  description  = "role: CHG0077138, ip: [141.138.128.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-er02-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-er02-lo0"
  description  = "role: CHG0077138, ip: [141.138.128.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-dmvpn01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-dmvpn01"
  description  = "role: CHG0077667, ip: [141.138.128.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-dmvpn02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-dmvpn02"
  description  = "role: CHG0077667, ip: [141.138.128.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_servicenowams-datacentre" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_servicenowams-datacentre"
  description  = "role: pr-e-internal_servicenowams-datacentre, ip: [149.96.66.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["149.96.66.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_servicenowlhr-datacentre" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_servicenowlhr-datacentre"
  description  = "role: pr-e-internal_servicenowlhr-datacentre, ip: [149.96.50.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["149.96.50.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux1rdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux1rdb001"
  description  = "role: CHG0117835, ip: [10.212.180.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux1rdb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux1rdb002"
  description  = "role: CHG0117835, ip: [10.212.180.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux2rdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux2rdb001"
  description  = "role: CHG0117835, ip: [10.214.180.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux2rdb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux2rdb002"
  description  = "role: CHG0117835, ip: [10.214.180.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxdrrdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxdrrdb001"
  description  = "role: CHG0117835, ip: [10.210.180.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.180.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6uxptrdb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6uxptrdb002"
  description  = "role: CHG0117835, ip: [10.115.177.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.115.177.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_retail-omni-mysql-dev-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_retail-omni-mysql-dev-williamhill-plc"
  description  = "role: CHG0117835, ip: [10.210.201.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.201.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb001"
  description  = "role: CHG0117835, ip: [10.120.180.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb0012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb0012"
  description  = "role: CHG0117835, ip: [10.120.177.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb002"
  description  = "role: CHG0117835, ip: [10.120.180.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxdrrdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxdrrdb04"
  description  = "role: CHG0118067, ip: [10.201.9.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb-vip"
  description  = "role: CHG0118067, ip: [10.120.146.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb04"
  description  = "role: CHG0118067, ip: [10.120.146.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb05"
  description  = "role: CHG0118067, ip: [10.120.146.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux003"
  description  = "role: CHG0118070, ip: [10.201.8.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.8.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux232" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux232"
  description  = "role: CHG0118070, ip: [10.201.9.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_liability-live-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_liability-live-vip"
  description  = "role: CHG0118070, ip: [10.120.180.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb01"
  description  = "role: CHG0118070, ip: [10.120.180.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb02"
  description  = "role: CHG0118070, ip: [10.120.180.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxdrrvr05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxdrrvr05"
  description  = "role: CHG0118072, ip: [10.210.180.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.180.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp1rvr05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp1rvr05"
  description  = "role: CHG0118072, ip: [10.212.180.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp1rvr06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp1rvr06"
  description  = "role: CHG0118072, ip: [10.212.180.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp2rvr05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp2rvr05"
  description  = "role: CHG0118072, ip: [10.214.180.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp2rvr06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp2rvr06"
  description  = "role: CHG0118072, ip: [10.214.180.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp3rvr005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp3rvr005"
  description  = "role: CHG0118072, ip: [10.216.177.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.216.177.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp3rvr006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp3rvr006"
  description  = "role: CHG0118072, ip: [10.216.177.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.216.177.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxdrrdb010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxdrrdb010"
  description  = "role: pr-e-internal_brsuxdrrdb010, ip: [10.210.180.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.180.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp1rdb010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp1rdb010"
  description  = "role: pr-e-internal_brsuxp1rdb010, ip: [10.212.180.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxp2rdb010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxp2rdb010"
  description  = "role: pr-e-internal_brsuxp2rdb010, ip: [10.214.180.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.180.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprrdb010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprrdb010"
  description  = "role: CHG0118080, ip: [10.120.180.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxdrshd010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxdrshd010"
  description  = "role: pr-e-internal_brsuxdrshd010, ip: [10.210.177.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.177.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsuxr1rdb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsuxr1rdb003"
  description  = "role: CHG0118083, ip: [10.212.180.225]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.180.225"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprshd010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprshd010"
  description  = "role: pr-e-internal_sc1uxprshd010, ip: [10.120.177.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux121"
  description  = "role: CHG0119313, ip: [10.1.29.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_brsux122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_brsux122"
  description  = "role: CHG0119313, ip: [10.1.29.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibux321vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibux321vip"
  description  = "role: CHG0119313, ip: [10.180.133.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.133.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibux322" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibux322"
  description  = "role: CHG0119313, ip: [10.180.133.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.133.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_gibux322vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_gibux322vip"
  description  = "role: CHG0119313, ip: [10.180.133.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.133.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_ld6ux321" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ld6ux321"
  description  = "role: CHG0119313, ip: [10.114.135.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.135.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-99-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-99-95"
  description  = "role: pr-e-internal_10-120-99-95, ip: [10.120.99.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprndb001-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprndb001-vip"
  description  = "role: pr-e-internal_sc1uxprndb001-vip, ip: [10.120.99.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprndb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprndb002"
  description  = "role: pr-e-internal_sc1uxprndb002, ip: [10.120.99.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-99-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-99-151"
  description  = "role: pr-e-internal_10-120-99-151, ip: [10.120.99.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-99-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-99-152"
  description  = "role: pr-e-internal_10-120-99-152, ip: [10.120.99.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_vmc-retail-production-vsphere-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_vmc-retail-production-vsphere-mgmt"
  description  = "role: pr-e-internal_vmc-retail-production-vsphere-mgmt, ip: [10.126.32.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.32.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_vmc-retail-production-10-233-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_vmc-retail-production-10-233-0-0s24"
  description  = "role: pr-e-internal_vmc-retail-production-10-233-0-0s24, ip: [10.233.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_vmc-retail-production-services-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_vmc-retail-production-services-mgmt"
  description  = "role: pr-e-internal_vmc-retail-production-services-mgmt, ip: [10.156.1.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.1.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-40"
  description  = "role: pr-e-internal_10-180-46-40, ip: [10.180.46.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-41"
  description  = "role: pr-e-internal_10-180-46-41, ip: [10.180.46.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-42"
  description  = "role: pr-e-internal_10-180-46-42, ip: [10.180.46.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-43"
  description  = "role: pr-e-internal_10-180-46-43, ip: [10.180.46.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-44"
  description  = "role: pr-e-internal_10-180-46-44, ip: [10.180.46.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-45"
  description  = "role: pr-e-internal_10-180-46-45, ip: [10.180.46.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-46"
  description  = "role: pr-e-internal_10-180-46-46, ip: [10.180.46.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-47"
  description  = "role: pr-e-internal_10-180-46-47, ip: [10.180.46.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-48"
  description  = "role: pr-e-internal_10-180-46-48, ip: [10.180.46.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-49"
  description  = "role: pr-e-internal_10-180-46-49, ip: [10.180.46.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-50"
  description  = "role: pr-e-internal_10-180-46-50, ip: [10.180.46.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-51"
  description  = "role: pr-e-internal_10-180-46-51, ip: [10.180.46.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-52"
  description  = "role: pr-e-internal_10-180-46-52, ip: [10.180.46.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-53"
  description  = "role: pr-e-internal_10-180-46-53, ip: [10.180.46.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-54"
  description  = "role: pr-e-internal_10-180-46-54, ip: [10.180.46.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-55"
  description  = "role: pr-e-internal_10-180-46-55, ip: [10.180.46.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-56"
  description  = "role: pr-e-internal_10-180-46-56, ip: [10.180.46.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-57"
  description  = "role: pr-e-internal_10-180-46-57, ip: [10.180.46.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-58"
  description  = "role: pr-e-internal_10-180-46-58, ip: [10.180.46.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-180-46-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-180-46-59"
  description  = "role: pr-e-internal_10-180-46-59, ip: [10.180.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-40"
  description  = "role: pr-e-internal_10-112-46-40, ip: [10.112.46.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-41"
  description  = "role: pr-e-internal_10-112-46-41, ip: [10.112.46.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-42"
  description  = "role: pr-e-internal_10-112-46-42, ip: [10.112.46.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-43"
  description  = "role: pr-e-internal_10-112-46-43, ip: [10.112.46.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-44"
  description  = "role: pr-e-internal_10-112-46-44, ip: [10.112.46.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-45"
  description  = "role: pr-e-internal_10-112-46-45, ip: [10.112.46.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-46"
  description  = "role: pr-e-internal_10-112-46-46, ip: [10.112.46.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-47"
  description  = "role: pr-e-internal_10-112-46-47, ip: [10.112.46.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-48"
  description  = "role: pr-e-internal_10-112-46-48, ip: [10.112.46.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-49"
  description  = "role: pr-e-internal_10-112-46-49, ip: [10.112.46.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-50"
  description  = "role: pr-e-internal_10-112-46-50, ip: [10.112.46.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-51"
  description  = "role: pr-e-internal_10-112-46-51, ip: [10.112.46.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-52"
  description  = "role: pr-e-internal_10-112-46-52, ip: [10.112.46.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-53"
  description  = "role: pr-e-internal_10-112-46-53, ip: [10.112.46.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-54"
  description  = "role: pr-e-internal_10-112-46-54, ip: [10.112.46.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-55"
  description  = "role: pr-e-internal_10-112-46-55, ip: [10.112.46.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-56"
  description  = "role: pr-e-internal_10-112-46-56, ip: [10.112.46.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-57"
  description  = "role: pr-e-internal_10-112-46-57, ip: [10.112.46.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-58"
  description  = "role: pr-e-internal_10-112-46-58, ip: [10.112.46.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-112-46-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-112-46-59"
  description  = "role: pr-e-internal_10-112-46-59, ip: [10.112.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-40"
  description  = "role: pr-e-internal_10-120-77-40, ip: [10.120.77.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-41"
  description  = "role: pr-e-internal_10-120-77-41, ip: [10.120.77.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-42"
  description  = "role: pr-e-internal_10-120-77-42, ip: [10.120.77.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-43"
  description  = "role: pr-e-internal_10-120-77-43, ip: [10.120.77.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-44"
  description  = "role: pr-e-internal_10-120-77-44, ip: [10.120.77.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-45"
  description  = "role: pr-e-internal_10-120-77-45, ip: [10.120.77.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-46"
  description  = "role: pr-e-internal_10-120-77-46, ip: [10.120.77.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-47"
  description  = "role: pr-e-internal_10-120-77-47, ip: [10.120.77.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-48"
  description  = "role: pr-e-internal_10-120-77-48, ip: [10.120.77.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-49"
  description  = "role: pr-e-internal_10-120-77-49, ip: [10.120.77.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-50"
  description  = "role: pr-e-internal_10-120-77-50, ip: [10.120.77.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-51"
  description  = "role: pr-e-internal_10-120-77-51, ip: [10.120.77.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-52"
  description  = "role: pr-e-internal_10-120-77-52, ip: [10.120.77.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-53"
  description  = "role: pr-e-internal_10-120-77-53, ip: [10.120.77.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-54"
  description  = "role: pr-e-internal_10-120-77-54, ip: [10.120.77.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-55"
  description  = "role: pr-e-internal_10-120-77-55, ip: [10.120.77.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-56"
  description  = "role: pr-e-internal_10-120-77-56, ip: [10.120.77.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-57"
  description  = "role: pr-e-internal_10-120-77-57, ip: [10.120.77.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-58"
  description  = "role: pr-e-internal_10-120-77-58, ip: [10.120.77.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-77-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-77-59"
  description  = "role: pr-e-internal_10-120-77-59, ip: [10.120.77.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.77.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-40"
  description  = "role: pr-e-internal_10-120-46-40, ip: [10.120.46.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-41"
  description  = "role: pr-e-internal_10-120-46-41, ip: [10.120.46.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-42"
  description  = "role: pr-e-internal_10-120-46-42, ip: [10.120.46.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-43"
  description  = "role: pr-e-internal_10-120-46-43, ip: [10.120.46.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-44"
  description  = "role: pr-e-internal_10-120-46-44, ip: [10.120.46.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-45"
  description  = "role: pr-e-internal_10-120-46-45, ip: [10.120.46.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-46"
  description  = "role: pr-e-internal_10-120-46-46, ip: [10.120.46.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-47"
  description  = "role: pr-e-internal_10-120-46-47, ip: [10.120.46.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-48"
  description  = "role: pr-e-internal_10-120-46-48, ip: [10.120.46.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-49"
  description  = "role: pr-e-internal_10-120-46-49, ip: [10.120.46.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-50"
  description  = "role: pr-e-internal_10-120-46-50, ip: [10.120.46.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-51"
  description  = "role: pr-e-internal_10-120-46-51, ip: [10.120.46.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-52"
  description  = "role: pr-e-internal_10-120-46-52, ip: [10.120.46.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-53"
  description  = "role: pr-e-internal_10-120-46-53, ip: [10.120.46.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-54"
  description  = "role: pr-e-internal_10-120-46-54, ip: [10.120.46.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-55"
  description  = "role: pr-e-internal_10-120-46-55, ip: [10.120.46.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-56"
  description  = "role: pr-e-internal_10-120-46-56, ip: [10.120.46.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-57"
  description  = "role: pr-e-internal_10-120-46-57, ip: [10.120.46.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-58"
  description  = "role: pr-e-internal_10-120-46-58, ip: [10.120.46.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_10-120-46-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_10-120-46-59"
  description  = "role: pr-e-internal_10-120-46-59, ip: [10.120.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprcmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprcmg01"
  description  = "role: pr-e-internal_sc1uxprcmg01, ip: [10.120.131.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1uxprcmg02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1uxprcmg02"
  description  = "role: pr-e-internal_sc1uxprcmg02, ip: [10.120.131.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sccadcrprapi03-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sccadcrprapi03-prod-williamhill-plc"
  description  = "role: pr-e-internal_sccadcrprapi03-prod-williamhill-plc, ip: [10.120.172.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.172.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcextapi01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcextapi01-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcextapi01-prod-williamhill-plc, ip: [10.121.7.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_sc1prdadcextapi02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sc1prdadcextapi02-prod-williamhill-plc"
  description  = "role: pr-e-internal_sc1prdadcextapi02-prod-williamhill-plc, ip: [10.121.7.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-brs-er01-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-brs-er01-lo0"
  description  = "role: pr-e-internal_uk-brs-er01-lo0, ip: [141.138.129.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.129.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-brs-er02-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-brs-er02-lo0"
  description  = "role: pr-e-internal_uk-brs-er02-lo0, ip: [141.138.129.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.129.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-es01-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-es01-vl20"
  description  = "role: pr-e-internal_uk-sc1-es01-vl20, ip: [141.138.128.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-sc1-es02-vl20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-sc1-es02-vl20"
  description  = "role: pr-e-internal_uk-sc1-es02-vl20, ip: [141.138.128.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["141.138.128.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-stj-ar01-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-stj-ar01-lo0"
  description  = "role: pr-e-internal_uk-stj-ar01-lo0, ip: [10.99.253.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_uk-stj-ar02-lo0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_uk-stj-ar02-lo0"
  description  = "role: pr-e-internal_uk-stj-ar02-lo0, ip: [10.99.253.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.26"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

resource "nsxt_policy_group" "pr-e-internal_grp_grp-orion-app-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-orion-app-srvs"
  description  = "role: pr-e-internal_grp_grp-orion-app-srvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6wnpremn79-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_net-obj-g-solarwinds-destinations" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_net-obj-g-solarwinds-destinations"
  description  = "role: CHG0138766,CHG0140021"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_gib-cp-ext-1.path, nsxt_policy_group.pr-e-internal_ip_10-120-193-132.path, nsxt_policy_group.pr-e-internal_ip_10-3-0-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-3-1-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-3-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-53-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-53-113-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-54-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-159-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-1-152-0s23.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-210-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-210-159-0s27.path, nsxt_policy_group.pr-e-internal_ip_10-210-164-192s27.path, nsxt_policy_group.pr-e-internal_ip_10-210-194-64s26.path, nsxt_policy_group.pr-e-internal_ip_10-210-194-192s26.path, nsxt_policy_group.pr-e-internal_ip_192-168-10-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-159-0s27.path, nsxt_policy_group.pr-e-internal_ip_10-120-159-96s27.path, nsxt_policy_group.pr-e-internal_ip_10-120-194-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-55-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-93-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-94-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-95-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-96-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-123-14-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-142-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-206-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-99-239-224s27.path, nsxt_policy_group.pr-e-internal_ip_10-1-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-56-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-128-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-1-98-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-112-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-99-253-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-99-254-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-19-0-96s27.path, nsxt_policy_group.pr-e-internal_ip_10-1-36-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-130-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-160-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_26"
  description  = "role: pr-e-internal_grp_scc-migrated_network_26"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-46-30.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-31.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rundeck-app-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rundeck-app-servers"
  description  = "role: CHG0141604"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_sc1uxpreap239_ip_10-120-163-239.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_aws-retail-prod-vpc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_aws-retail-prod-vpc"
  description  = "role: CHG0141604"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_aws-retail-prod-1.path, nsxt_policy_group.pr-e-internal_aws-retail-prod-2.path, nsxt_policy_group.pr-e-internal_aws-retail-prod-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_27"
  description  = "role: pr-e-internal_grp_scc-migrated_network_27"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-239.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_28"
  description  = "role: pr-e-internal_grp_scc-migrated_network_28"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-180-67.path, nsxt_policy_group.pr-e-internal_ip_10-212-180-138.path, nsxt_policy_group.pr-e-internal_ip_10-214-180-138.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rundeck-primary-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rundeck-primary-cluster"
  description  = "role: pr-e-internal_grp_rundeck-primary-cluster"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_sc1uxpreap239_ip_10-120-163-239.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_14"
  description  = "role: pr-e-internal_grp_scc-migrated_network_14"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_zoltan-brs-pp1-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-brs-pp2-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-brs-pp3-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-brs-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-gib-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-sc1-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_zoltan-brs-cxp-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_skybox-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_skybox-appliances"
  description  = "role: CHG0121057"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1appresc02.path, nsxt_policy_group.pr-e-internal_sc1appresc03.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_skybox-clients" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_skybox-clients"
  description  = "role: CHG0134971"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ld6pteadcint01.path, nsxt_policy_group.pr-e-internal_ld6pteadcapi02.path, nsxt_policy_group.pr-e-internal_ld6pteadcapi01.path, nsxt_policy_group.pr-e-internal_ld6pteadcint02.path, nsxt_policy_group.pr-e-internal_ld6pteadcextapi01.path, nsxt_policy_group.pr-e-internal_ld6pteadcextapi02.path, nsxt_policy_group.pr-e-internal_sc1invadcint01.path, nsxt_policy_group.pr-e-internal_sc1invadcint02.path, nsxt_policy_group.pr-e-internal_sc1invadcapi01.path, nsxt_policy_group.pr-e-internal_sc1invadcapi02.path, nsxt_policy_group.pr-e-internal_sc1invadcext01.path, nsxt_policy_group.pr-e-internal_sc1invadcext02.path, nsxt_policy_group.pr-e-internal_pp1adcapi01.path, nsxt_policy_group.pr-e-internal_pp1adcapi02.path, nsxt_policy_group.pr-e-internal_brspp1adcextapi01.path, nsxt_policy_group.pr-e-internal_pp2adcint01.path, nsxt_policy_group.pr-e-internal_pp2adcapi01.path, nsxt_policy_group.pr-e-internal_brspp2adcextapi01.path, nsxt_policy_group.pr-e-internal_pp3adcint01.path, nsxt_policy_group.pr-e-internal_pp3adcapi01.path, nsxt_policy_group.pr-e-internal_brsprdadcint01.path, nsxt_policy_group.pr-e-internal_brsprdadcint02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_36"
  description  = "role: pr-e-internal_grp_scc-migrated_network_36"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_gibuxpredb01.path, nsxt_policy_group.pr-e-internal_grp_grp-sql-servers.path, nsxt_policy_group.pr-e-internal_grp_grp-trs-db-servers.path, nsxt_policy_group.pr-e-internal_grp_grp-liability-viewer-servers.path, nsxt_policy_group.pr-e-internal_grp_grp-oscar-db-servers.path, nsxt_policy_group.pr-e-internal_grp_grp-bingo-db-servers.path, nsxt_policy_group.pr-e-internal_grp_grp-shopdiary-db-servers.path, nsxt_policy_group.pr-e-internal_grp_mysqlenterprisemonitor.path, nsxt_policy_group.pr-e-internal_grp_grp-scc-mars-mysql-svrs.path, nsxt_policy_group.pr-e-internal_grp_grp-scc-mars-db-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_isilon-storage-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_isilon-storage-svrs"
  description  = "role: pr-e-internal_grp_isilon-storage-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-46-10.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-11.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-12.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-13.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-14.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-15.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-16.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-17.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-18.path, nsxt_policy_group.pr-e-internal_ip_10-120-46-19.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_pure-storage-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_pure-storage-svrs"
  description  = "role: pr-e-internal_grp_pure-storage-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-143-172.path, nsxt_policy_group.pr-e-internal_ip_10-120-143-173.path, nsxt_policy_group.pr-e-internal_ip_10-120-143-182.path, nsxt_policy_group.pr-e-internal_ip_10-120-143-183.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_tufin-endpoints" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_tufin-endpoints"
  description  = "role: pr-e-internal_grp_tufin-endpoints"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-1-130-36.path, nsxt_policy_group.pr-e-internal_ip_10-1-130-50.path, nsxt_policy_group.pr-e-internal_ip_10-1-99-220.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-220.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-4.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-5.path, nsxt_policy_group.pr-e-internal_ip_10-120-160-68.path, nsxt_policy_group.pr-e-internal_ip_10-120-161-97.path, nsxt_policy_group.pr-e-internal_ip_10-92-100-13.path, nsxt_policy_group.pr-e-internal_ip_10-92-100-1.path, nsxt_policy_group.pr-e-internal_ip_10-92-100-5.path, nsxt_policy_group.pr-e-internal_ip_10-92-100-9.path, nsxt_policy_group.pr-e-internal_ip_10-99-253-31.path, nsxt_policy_group.pr-e-internal_ip_10-99-253-41.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-19.path, nsxt_policy_group.pr-e-internal_ip_10-120-193-132.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_retail-liability-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_retail-liability-svrs"
  description  = "role: pr-e-internal_grp_retail-liability-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-177-37.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-101.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-102.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-103.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-104.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-133.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-134.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-135.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-136.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-81.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-82.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-83.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-84.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_41"
  description  = "role: pr-e-internal_grp_scc-migrated_network_41"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ld6wnprbkcs01.path, nsxt_policy_group.pr-e-internal_sc1uxprbkcs01.path, nsxt_policy_group.pr-e-internal_gibx9002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_puppet-master-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_puppet-master-db"
  description  = "role: CHG0115562"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-1-28-102.path, nsxt_policy_group.pr-e-internal_ip_10-1-28-26.path, nsxt_policy_group.pr-e-internal_ip_10-112-13-1.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-97.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-101.path, nsxt_policy_group.pr-e-internal_ip_10-211-163-101.path, nsxt_policy_group.pr-e-internal_ip_10-213-163-101.path, nsxt_policy_group.pr-e-internal_ip_10-215-163-101.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_netbrain-destinations" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_netbrain-destinations"
  description  = "role: pr-e-internal_grp_netbrain-destinations"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-1-105-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-1-84-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-1-98-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-1-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-194-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-32-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-14-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-140-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-142-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-123-206-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-210-159-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-3-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-53-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-55-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-56-100-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-56-99-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-92-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-99-253-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-99-254-0s24.path, nsxt_policy_group.pr-e-internal_ip_192-168-10-0s24.path, nsxt_policy_group.pr-e-internal_ip_192-168-9-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-159-0s27.path, nsxt_policy_group.pr-e-internal_ip_10-180-159-0s27.path, nsxt_policy_group.pr-e-internal_ip_10-210-159-0s27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rfc1918networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rfc1918networks"
  description  = "role: pr-e-internal_grp_rfc1918networks"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_net-10-0-0-0_255-0-0-0.path, nsxt_policy_group.pr-e-internal_net-172-16-0-0_255-240-0-0.path, nsxt_policy_group.pr-e-internal_net-192-168-0-0_255-255-0-0.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ca-hub-servers-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ca-hub-servers-scc"
  description  = "role: pr-e-internal_grp_ca-hub-servers-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremn137-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ca-hub-clients-aws" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ca-hub-clients-aws"
  description  = "role: pr-e-internal_grp_ca-hub-clients-aws"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_am1xuim01col001-am1-williamhill-plc.path, nsxt_policy_group.pr-e-internal_am1xuim01col002-am1-williamhill-plc.path, nsxt_policy_group.pr-e-internal_njpxuim01col001.path, nsxt_policy_group.pr-e-internal_njpxuim01col002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_51"
  description  = "role: pr-e-internal_grp_scc-migrated_network_51"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_aws-ssn-mgmt.path, nsxt_policy_group.pr-e-internal_aws-ssp-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_54"
  description  = "role: pr-e-internal_grp_scc-migrated_network_54"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-163-155.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-156.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-157.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-158.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_55"
  description  = "role: pr-e-internal_grp_scc-migrated_network_55"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-112-12-104.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-105.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-106.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-107.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-108.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-109.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-209.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-43.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-38.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-39.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-45.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-46.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-51.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-52.path, nsxt_policy_group.pr-e-internal_ip_100-100-2-208.path, nsxt_policy_group.pr-e-internal_ip_100-100-2-55.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_88"
  description  = "role: pr-e-internal_grp_scc-migrated_network_88"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-163-31.path, nsxt_policy_group.pr-e-internal_10-120-163-32.path, nsxt_policy_group.pr-e-internal_10-120-163-33.path, nsxt_policy_group.pr-e-internal_10-120-163-34.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-35.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_apache-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_apache-servers"
  description  = "role: pr-e-internal_grp_apache-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-170-100.path, nsxt_policy_group.pr-e-internal_ip_10-120-173-100.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-101.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-102.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-103.path, nsxt_policy_group.pr-e-internal_ip_10-120-180-104.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_91" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_91"
  description  = "role: pr-e-internal_grp_scc-migrated_network_91"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-163-31.path, nsxt_policy_group.pr-e-internal_10-120-163-32.path, nsxt_policy_group.pr-e-internal_10-120-163-33.path, nsxt_policy_group.pr-e-internal_10-120-163-34.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-35.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_92"
  description  = "role: pr-e-internal_grp_scc-migrated_network_92"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-177-38.path, nsxt_policy_group.pr-e-internal_ip_10-120-177-39.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wh-border-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wh-border-devices"
  description  = "role: pr-e-internal_grp_wh-border-devices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_gi-mpl-es01-vl20.path, nsxt_policy_group.pr-e-internal_gi-mpl-es02-vl20.path, nsxt_policy_group.pr-e-internal_uk-brs-es01-vl20.path, nsxt_policy_group.pr-e-internal_uk-brs-es02-vl20.path, nsxt_policy_group.pr-e-internal_uk-ld6-es01-vl20.path, nsxt_policy_group.pr-e-internal_uk-ld6-es02-vl20.path, nsxt_policy_group.pr-e-internal_uk-sc1-es01.path, nsxt_policy_group.pr-e-internal_uk-sc1-es02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_us-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_us-subnets"
  description  = "role: CHG0129192"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-174-104-0_24.path, nsxt_policy_group.pr-e-internal_10-174-111-128_25.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_69"
  description  = "role: pr-e-internal_grp_scc-migrated_network_69"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremn006.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-134.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_malta_pure_array" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_malta_pure_array"
  description  = "role: CHG0131597"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-129-11-1.path, nsxt_policy_group.pr-e-internal_10-129-11-2.path, nsxt_policy_group.pr-e-internal_10-129-11-3.path, nsxt_policy_group.pr-e-internal_10-129-11-4.path, nsxt_policy_group.pr-e-internal_10-129-11-5.path, nsxt_policy_group.pr-e-internal_10-129-11-6.path, nsxt_policy_group.pr-e-internal_10-129-11-7.path, nsxt_policy_group.pr-e-internal_10-129-11-8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_athene-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_athene-servers"
  description  = "role: pr-e-internal_grp_athene-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnpremn20a.path, nsxt_policy_group.pr-e-internal_sc1wnpremn21a.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_107"
  description  = "role: pr-e-internal_grp_scc-migrated_network_107"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-121-4-11.path, nsxt_policy_group.pr-e-internal_ip_10-121-4-12.path, nsxt_policy_group.pr-e-internal_ip_10-121-5-11.path, nsxt_policy_group.pr-e-internal_ip_10-121-5-12.path, nsxt_policy_group.pr-e-internal_grp_stingrays.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_106"
  description  = "role: pr-e-internal_grp_scc-migrated_network_106"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-121-10-110.path, nsxt_policy_group.pr-e-internal_ip_10-121-10-115.path, nsxt_policy_group.pr-e-internal_ip_10-121-4-205.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_130" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_130"
  description  = "role: pr-e-internal_grp_scc-migrated_network_130"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-163-18.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-27.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-49.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-74.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_84"
  description  = "role: pr-e-internal_grp_scc-migrated_network_84"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_grp_brs-xiv.path, nsxt_policy_group.pr-e-internal_grp_sc1-xiv.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_131" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_131"
  description  = "role: pr-e-internal_grp_scc-migrated_network_131"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_tufin.path, nsxt_policy_group.pr-e-internal_sc1uxpremn79.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_checkpoint-cma" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_checkpoint-cma"
  description  = "role: CHG0065974"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-129-60.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-61.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-62.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-63.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-64.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-65.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-66.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-67.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-60.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-61.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-62.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-63.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-64.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-65.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-66.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-67.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_stingrays" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_stingrays"
  description  = "role: CHG0141421"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1apprein04-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein05-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein06-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein07-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein08-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein09-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein10-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein11-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein12-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein13-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcclb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcclb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcnlb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcnlb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi02-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whdpops01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whdpops01"
  description  = "role: pr-e-internal_grp_whdpops01"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-100-82.path, nsxt_policy_group.pr-e-internal_10-200-100-82.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whdppresent01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whdppresent01"
  description  = "role: pr-e-internal_grp_whdppresent01"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-100-83.path, nsxt_policy_group.pr-e-internal_10-200-100-83.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whdpservices01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whdpservices01"
  description  = "role: pr-e-internal_grp_whdpservices01"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-100-84.path, nsxt_policy_group.pr-e-internal_10-200-100-84.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whdpservices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whdpservices"
  description  = "role: pr-e-internal_grp_whdpservices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-100-80.path, nsxt_policy_group.pr-e-internal_10-200-100-80.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sql-monitored-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sql-monitored-servers"
  description  = "role: pr-e-internal_grp_sql-monitored-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brswndrndb003.path, nsxt_policy_group.pr-e-internal_brswndrndb004.path, nsxt_policy_group.pr-e-internal_brswnppndb002.path, nsxt_policy_group.pr-e-internal_brswnppndb003.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb02.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb03.path, nsxt_policy_group.pr-e-internal_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-e-internal_sc1wnprndb004_ip_10-120-149-26.path, nsxt_policy_group.pr-e-internal_sc1wnprndb005_ip_10-120-149-27.path, nsxt_policy_group.pr-e-internal_sc1wnprndb006_ip_10-120-149-28.path, nsxt_policy_group.pr-e-internal_sc1wnprrcs01.path, nsxt_policy_group.pr-e-internal_sc1wnprrcs02.path, nsxt_policy_group.pr-e-internal_sc1wnprrto02_ip_10-120-180-59.path, nsxt_policy_group.pr-e-internal_sc1wnprrtp01.path, nsxt_policy_group.pr-e-internal_gibwn400.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05-vmc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06-vmc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc-vmc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sql-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sql-servers"
  description  = "role: pr-e-internal_grp_sql-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnprgdb01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb02.path, nsxt_policy_group.pr-e-internal_sc1wnprrcs01.path, nsxt_policy_group.pr-e-internal_sc1wnprrcs02.path, nsxt_policy_group.pr-e-internal_sc1wnprrto02_ip_10-120-180-59.path, nsxt_policy_group.pr-e-internal_sc1wnprrtp01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb03.path, nsxt_policy_group.pr-e-internal_sc1wnprndb004_ip_10-120-149-26.path, nsxt_policy_group.pr-e-internal_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-e-internal_sc1wnprndb005_ip_10-120-149-27.path, nsxt_policy_group.pr-e-internal_sc1wnprndb006_ip_10-120-149-28.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05_06.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05-vmc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06-vmc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc-vmc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_76"
  description  = "role: pr-e-internal_grp_scc-migrated_network_76"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-180-163-71.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-70.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_77"
  description  = "role: pr-e-internal_grp_scc-migrated_network_77"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnpremn74.path, nsxt_policy_group.pr-e-internal_sc1wnpremn75.path, nsxt_policy_group.pr-e-internal_sc1wnpremn77.path, nsxt_policy_group.pr-e-internal_sc1wnpremn78.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_78"
  description  = "role: pr-e-internal_grp_scc-migrated_network_78"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-112-12-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-129-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-129-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_80"
  description  = "role: pr-e-internal_grp_scc-migrated_network_80"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-130-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_81"
  description  = "role: pr-e-internal_grp_scc-migrated_network_81"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-132-31.path, nsxt_policy_group.pr-e-internal_ip_10-120-132-32.path, nsxt_policy_group.pr-e-internal_ip_10-120-132-45.path, nsxt_policy_group.pr-e-internal_ip_10-120-132-46.path, nsxt_policy_group.pr-e-internal_ip_10-120-146-71.path, nsxt_policy_group.pr-e-internal_ip_10-120-146-72.path, nsxt_policy_group.pr-e-internal_ip_10-120-146-73.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_95"
  description  = "role: pr-e-internal_grp_scc-migrated_network_95"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-180-143-171.path, nsxt_policy_group.pr-e-internal_ip_10-120-143-171.path, nsxt_policy_group.pr-e-internal_ip_10-210-143-171.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_139"
  description  = "role: pr-e-internal_grp_scc-migrated_network_139"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremg30.path, nsxt_policy_group.pr-e-internal_grp_ilo-nets.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_82"
  description  = "role: pr-e-internal_grp_scc-migrated_network_82"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-180-163-38.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-39.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-45.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-46.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-51.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_93"
  description  = "role: pr-e-internal_grp_scc-migrated_network_93"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-239.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-243.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_138"
  description  = "role: pr-e-internal_grp_scc-migrated_network_138"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-143-185.path, nsxt_policy_group.pr-e-internal_ip_10-180-143-185.path, nsxt_policy_group.pr-e-internal_ip_10-210-139-243.path, nsxt_policy_group.pr-e-internal_ip_10-210-143-185.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_134"
  description  = "role: pr-e-internal_grp_scc-migrated_network_134"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-130-252.path, nsxt_policy_group.pr-e-internal_ip_10-180-130-110.path, nsxt_policy_group.pr-e-internal_ip_10-180-130-151.path, nsxt_policy_group.pr-e-internal_ip_10-180-130-68.path, nsxt_policy_group.pr-e-internal_ip_10-180-80-104.path, nsxt_policy_group.pr-e-internal_ip_10-180-80-98.path, nsxt_policy_group.pr-e-internal_ip_10-201-254-223.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_140"
  description  = "role: pr-e-internal_grp_scc-migrated_network_140"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremg26.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-115.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wily_svrs_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wily_svrs_scc"
  description  = "role: pr-e-internal_grp_wily_svrs_scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremn105.path, nsxt_policy_group.pr-e-internal_sc1uxpremn106.path, nsxt_policy_group.pr-e-internal_sc1uxpremn107.path, nsxt_policy_group.pr-e-internal_sc1uxpremn108.path, nsxt_policy_group.pr-e-internal_sc1uxpremn120.path, nsxt_policy_group.pr-e-internal_sc1uxpremn121.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-31.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-32.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-33.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-34.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_consul-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_consul-hosts"
  description  = "role: pr-e-internal_grp_consul-hosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-121-10-79.path, nsxt_policy_group.pr-e-internal_ip_10-121-10-81.path, nsxt_policy_group.pr-e-internal_ip_10-121-10-82.path, nsxt_policy_group.pr-e-internal_ip_10-121-10-83.path, nsxt_policy_group.pr-e-internal_ip_10-121-10-84.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_vcenter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_vcenter"
  description  = "role: pr-e-internal_grp_vcenter"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsppapvc01-group-williamhill-plc.path, nsxt_policy_group.pr-e-internal_gibprapvc01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prapvc01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_ld6prapvc01-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_master-rundeck-app-nodes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_master-rundeck-app-nodes"
  description  = "role: pr-e-internal_grp_master-rundeck-app-nodes"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_sc1uxpreap239_ip_10-120-163-239.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-oracle-instances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-oracle-instances"
  description  = "role: pr-e-internal_grp_scc-oracle-instances"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxprgdb01.path, nsxt_policy_group.pr-e-internal_sc1uxprgdb05.path, nsxt_policy_group.pr-e-internal_sc1uxprodb001.path, nsxt_policy_group.pr-e-internal_sc1uxprodb002.path, nsxt_policy_group.pr-e-internal_sc1uxprtdb001.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_vmc-sddcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_vmc-sddcs"
  description  = "role: pr-e-internal_grp_vmc-sddcs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-156-5-0s24.path, nsxt_policy_group.pr-e-internal_grp_vmc-sddc-retail-production.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whgroup_ad_servers-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whgroup_ad_servers-chg0144834"
  description  = "role: pr-e-internal_grp_whgroup_ad_servers-chg0144834"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_bfawnpredc01.path, nsxt_policy_group.pr-e-internal_brswnpredc01.path, nsxt_policy_group.pr-e-internal_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-e-internal_brswnpredc03-chg0144834.path, nsxt_policy_group.pr-e-internal_gibwnpredc02_ip_10-180-194-12.path, nsxt_policy_group.pr-e-internal_gibwnpredc03_ip_10-180-194-13.path, nsxt_policy_group.pr-e-internal_irewnprdc01.path, nsxt_policy_group.pr-e-internal_irewnprdc02.path, nsxt_policy_group.pr-e-internal_nvawnprdc01.path, nsxt_policy_group.pr-e-internal_nvawnprdc02.path, nsxt_policy_group.pr-e-internal_krawnpredc01.path, nsxt_policy_group.pr-e-internal_krawnpredc02.path, nsxt_policy_group.pr-e-internal_ld6wnpredc01-new.path, nsxt_policy_group.pr-e-internal_ld6wnpredc02-new.path, nsxt_policy_group.pr-e-internal_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-e-internal_mnlwnpredc03.path, nsxt_policy_group.pr-e-internal_sc1wnpredc01.path, nsxt_policy_group.pr-e-internal_sc1wnpredc02.path, nsxt_policy_group.pr-e-internal_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-e-internal_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-e-internal_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-e-internal_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-e-internal_sofwnpredc01.path, nsxt_policy_group.pr-e-internal_sofwnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_internal-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_internal-nets"
  description  = "role: pr-e-internal_grp_internal-nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_net-10-120-162-0_255-255-255-0.path, nsxt_policy_group.pr-e-internal_net-10-120-163-0_255-255-255-0.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sccbrs-stingray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sccbrs-stingray"
  description  = "role: pr-e-internal_grp_sccbrs-stingray"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsapprein04-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein05-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein06-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein07-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein08-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein09-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein10-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsapprein11-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcclb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcclb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcint01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcint02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcnlb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_brsprdadcnlb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcapi01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcapi02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcext01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcext02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcint01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcint02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcapi02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcclb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcclb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcint01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcint02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcnlb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcnlb02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi02-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rds-kms-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rds-kms-server"
  description  = "role: KMS/RDS license servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brswndremg002.path, nsxt_policy_group.pr-e-internal_sc1wnpremg002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_31"
  description  = "role: pr-e-internal_grp_scc-migrated_network_31"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_grp_gibstorage.path, nsxt_policy_group.pr-e-internal_grp_ld6storage.path, nsxt_policy_group.pr-e-internal_grp_sc1nas.path, nsxt_policy_group.pr-e-internal_grp_sccstorage.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_135"
  description  = "role: pr-e-internal_grp_scc-migrated_network_135"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_scc-nms-hub-dr.path, nsxt_policy_group.pr-e-internal_scc-nms-hub-live.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_136"
  description  = "role: pr-e-internal_grp_scc-migrated_network_136"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_scc-nms-hub-dr.path, nsxt_policy_group.pr-e-internal_scc-nms-hub-live.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_6"
  description  = "role: pr-e-internal_grp_scc-migrated_network_6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb0506.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05-vmc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06-vmc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc-vmc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_7"
  description  = "role: pr-e-internal_grp_scc-migrated_network_7"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-1-86-31.path, nsxt_policy_group.pr-e-internal_10-120-146-116.path, nsxt_policy_group.pr-e-internal_cessql.path, nsxt_policy_group.pr-e-internal_sc1wnprrtp01.path, nsxt_policy_group.pr-e-internal_brswnstrdb001.path, nsxt_policy_group.pr-e-internal_sc1wnpredb01.path, nsxt_policy_group.pr-e-internal_sc1wnprevo01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb13.path, nsxt_policy_group.pr-e-internal_sc1wnprndb019.path, nsxt_policy_group.pr-e-internal_sc1wnprrdb01.path, nsxt_policy_group.pr-e-internal_sc1wnprrto01.path, nsxt_policy_group.pr-e-internal_sc1wnprrto02_ip_10-120-180-54.path, nsxt_policy_group.pr-e-internal_w7d-dbjump.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_18"
  description  = "role: pr-e-internal_grp_scc-migrated_network_18"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1prdadcclb01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcclb02-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_splunk-heavy-forwarders" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_splunk-heavy-forwarders"
  description  = "role: pr-e-internal_grp_splunk-heavy-forwarders"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremn002-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1uxpremn003-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-orion-app-srvs-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-orion-app-srvs-ld6"
  description  = "role: pr-e-internal_grp_grp-orion-app-srvs-ld6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-112-12-125.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-126.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-142.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-143.path, nsxt_policy_group.pr-e-internal_ip_10-112-12-144.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-orion-app-srvs-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-orion-app-srvs-scc"
  description  = "role: pr-e-internal_grp_grp-orion-app-srvs-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-163-122.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-123.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-142.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-143.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_euc_mgmt_server-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_euc_mgmt_server-group-chg0142765"
  description  = "role: pr-e-internal_grp_euc_mgmt_server-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsapprcmg002-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_on_premise_datacentre_vlans-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_on_premise_datacentre_vlans-group-chg0142765"
  description  = "role: pr-e-internal_grp_on_premise_datacentre_vlans-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-210-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-180-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-112-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-19-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wh_nets-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wh_nets-chg0143200"
  description  = "role: pr-e-internal_grp_wh_nets-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_splunk_heavy_forwarders-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_splunk_heavy_forwarders-chg0143200"
  description  = "role: pr-e-internal_grp_splunk_heavy_forwarders-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpremn002.path, nsxt_policy_group.pr-e-internal_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_splunk_deployment_server-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_splunk_deployment_server-chg0143200"
  description  = "role: pr-e-internal_grp_splunk_deployment_server-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ras-vpn-pool"
  description  = "role: pr-e-internal_grp_ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_grp_ld6-ras-vpn-pool.path, nsxt_policy_group.pr-e-internal_grp_sc1-ras-vpn-pool.path, nsxt_policy_group.pr-e-internal_grp_mrg-ras-vpn-pool.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-scc-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-scc-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxprbkms01.path, nsxt_policy_group.pr-e-internal_sc1uxprbkms02.path, nsxt_policy_group.pr-e-internal_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-ld6-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-ld6-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ld6uxprbkms03.path, nsxt_policy_group.pr-e-internal_ld6uxprbkms04.path, nsxt_policy_group.pr-e-internal_ld6wnprbkcs01.path, nsxt_policy_group.pr-e-internal_ld6uxprbkms01.path, nsxt_policy_group.pr-e-internal_ld6uxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-gib-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-gib-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_gibuxprbkms01.path, nsxt_policy_group.pr-e-internal_gibuxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_whgroup-ad-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_whgroup-ad-servers"
  description  = "role: pr-e-internal_grp_whgroup-ad-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-e-internal_brswnpredc03.path, nsxt_policy_group.pr-e-internal_gibwnpredc02_ip_10-180-194-12.path, nsxt_policy_group.pr-e-internal_gibwnpredc03_ip_10-180-194-13.path, nsxt_policy_group.pr-e-internal_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-e-internal_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-e-internal_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-e-internal_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-e-internal_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-e-internal_bfawnpredc01.path, nsxt_policy_group.pr-e-internal_krawnpredc01.path, nsxt_policy_group.pr-e-internal_krawnpredc02.path, nsxt_policy_group.pr-e-internal_ld6wnpredc01.path, nsxt_policy_group.pr-e-internal_ld6wnpredc02.path, nsxt_policy_group.pr-e-internal_mnlwnpredc03.path, nsxt_policy_group.pr-e-internal_sofwnpredc01.path, nsxt_policy_group.pr-e-internal_sofwnpredc02.path, nsxt_policy_group.pr-e-internal_brswnpredc01.path, nsxt_policy_group.pr-e-internal_sc1wnpredc01.path, nsxt_policy_group.pr-e-internal_sc1wnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wily-svrs_all" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wily-svrs_all"
  description  = "role: pr-e-internal_grp_wily-svrs_all"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_grp_wily_svrs_brs.path, nsxt_policy_group.pr-e-internal_grp_wily_svrs_scc.path, nsxt_policy_group.pr-e-internal_grp_wily_svrs_gib.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wily-access-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wily-access-group"
  description  = "role: pr-e-internal_grp_wily-access-group"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_int-10-180-36-10.path, nsxt_policy_group.pr-e-internal_int-10-180-37-51.path, nsxt_policy_group.pr-e-internal_int-10-180-37-52.path, nsxt_policy_group.pr-e-internal_int-10-180-37-53.path, nsxt_policy_group.pr-e-internal_int-10-180-37-54.path, nsxt_policy_group.pr-e-internal_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rundeck-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rundeck-servers"
  description  = "role: pr-e-internal_grp_rundeck-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-e-internal_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-e-internal_sc1uxpreap239_ip_10-120-163-239.path, nsxt_policy_group.pr-e-internal_sc1uxpreap242.path, nsxt_policy_group.pr-e-internal_sc1uxrdk.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_webproxies-cx-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_webproxies-cx-scc"
  description  = "role: pr-e-internal_grp_webproxies-cx-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-121-5-0slash24.path, nsxt_policy_group.pr-e-internal_10-121-7-0slash24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_infoblox-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_infoblox-servers"
  description  = "role: pr-e-internal_grp_infoblox-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsns01.path, nsxt_policy_group.pr-e-internal_brsns02.path, nsxt_policy_group.pr-e-internal_gibns01.path, nsxt_policy_group.pr-e-internal_gibns02.path, nsxt_policy_group.pr-e-internal_sc1ns01.path, nsxt_policy_group.pr-e-internal_sc1ns02.path, nsxt_policy_group.pr-e-internal_ld6ns01-new.path, nsxt_policy_group.pr-e-internal_ld6ns02-new.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_mailhosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_mailhosts"
  description  = "role: pr-e-internal_grp_mailhosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_emailhost01.path, nsxt_policy_group.pr-e-internal_emailhost02.path, nsxt_policy_group.pr-e-internal_emailhost03.path, nsxt_policy_group.pr-e-internal_emailhost04.path, nsxt_policy_group.pr-e-internal_emailhost05.path, nsxt_policy_group.pr-e-internal_emailhost06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_10"
  description  = "role: pr-e-internal_grp_scc-migrated_network_10"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_clp-splunk-license-master-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1uxpromn012.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_17"
  description  = "role: pr-e-internal_grp_scc-migrated_network_17"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-0-0s16.path, nsxt_policy_group.pr-e-internal_ip_10-120-163-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_16"
  description  = "role: pr-e-internal_grp_scc-migrated_network_16"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-44-25.path, nsxt_policy_group.pr-e-internal_ip_10-120-44-26.path, nsxt_policy_group.pr-e-internal_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_33"
  description  = "role: pr-e-internal_grp_scc-migrated_network_33"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsux910.path, nsxt_policy_group.pr-e-internal_gibux910.path, nsxt_policy_group.pr-e-internal_ld6uxpreds01.path, nsxt_policy_group.pr-e-internal_sc1uxpreds01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_scc-migrated_network_11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_scc-migrated_network_11"
  description  = "role: pr-e-internal_grp_scc-migrated_network_11"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1uxprgdb01.path, nsxt_policy_group.pr-e-internal_sc1uxprgdb05.path, nsxt_policy_group.pr-e-internal_10-120-146-116.path, nsxt_policy_group.pr-e-internal_cessql.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb02.path, nsxt_policy_group.pr-e-internal_sc1wnprrto02_ip_10-120-180-59.path, nsxt_policy_group.pr-e-internal_sc1wnprrtp01.path, nsxt_policy_group.pr-e-internal_sc1wnprevo01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb13.path, nsxt_policy_group.pr-e-internal_sc1wnprncp001-mgmt-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnprndb019.path, nsxt_policy_group.pr-e-internal_sc1uxpredb01.path, nsxt_policy_group.pr-e-internal_sc1uxpremn17.path, nsxt_policy_group.pr-e-internal_sc1uxprnap43_44vip.path, nsxt_policy_group.pr-e-internal_sc1uxprndb001.path, nsxt_policy_group.pr-e-internal_sc1uxprndb95_96vip.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb.path, nsxt_policy_group.pr-e-internal_sc1uxprrvr05.path, nsxt_policy_group.pr-e-internal_sc1uxprrvr06.path, nsxt_policy_group.pr-e-internal_sc1wnprecp01.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb01.path, nsxt_policy_group.pr-e-internal_sc1uxprndb037_38vip.path, nsxt_policy_group.pr-e-internal_sc1wnprnwb87.path, nsxt_policy_group.pr-e-internal_sc1wnprndb003_ip_10-120-100-17.path, nsxt_policy_group.pr-e-internal_sc1wnprndb004_ip_10-120-100-18.path, nsxt_policy_group.pr-e-internal_sc1wnprndb005_ip_10-120-100-19.path, nsxt_policy_group.pr-e-internal_sc1wnprndb006_ip_10-120-100-20.path, nsxt_policy_group.pr-e-internal_host-10-121-5-11.path, nsxt_policy_group.pr-e-internal_host-10-121-5-12.path, nsxt_policy_group.pr-e-internal_sc1wnprnap024-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb05-vmc.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06.path, nsxt_policy_group.pr-e-internal_sc1wnprgdb06-vmc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_corpservicessql-prod-williamhill-plc-vmc.path, nsxt_policy_group.pr-e-internal_ip_10-120-145-40.path, nsxt_policy_group.pr-e-internal_ip_10-120-177-68.path, nsxt_policy_group.pr-e-internal_ip_10-120-143-85.path, nsxt_policy_group.pr-e-internal_ip_0-0-0-0s0.path, nsxt_policy_group.pr-e-internal_grp_snmpget.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-bomgar-cde-jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-bomgar-cde-jumphosts"
  description  = "role: CHG0123314"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brswnprcmg41.path, nsxt_policy_group.pr-e-internal_brswnprcmg42.path, nsxt_policy_group.pr-e-internal_brswnprcmg43.path, nsxt_policy_group.pr-e-internal_brswnprcmg44.path, nsxt_policy_group.pr-e-internal_gibwnprcmg41.path, nsxt_policy_group.pr-e-internal_gibwnprcmg42.path, nsxt_policy_group.pr-e-internal_gibwnprcmg43.path, nsxt_policy_group.pr-e-internal_gibwnprcmg44.path, nsxt_policy_group.pr-e-internal_ld6wnprcmg41.path, nsxt_policy_group.pr-e-internal_ld6wnprcmg42.path, nsxt_policy_group.pr-e-internal_ld6wnprcmg43.path, nsxt_policy_group.pr-e-internal_ld6wnprcmg44.path, nsxt_policy_group.pr-e-internal_sc1wnprcmg41.path, nsxt_policy_group.pr-e-internal_sc1wnprcmg42.path, nsxt_policy_group.pr-e-internal_sc1wnprcmg43.path, nsxt_policy_group.pr-e-internal_sc1wnprcmg44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_direct-internet-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_direct-internet-access"
  description  = "role: pr-e-internal_grp_direct-internet-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_scc_wsus.path, nsxt_policy_group.pr-e-internal_netbrain.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_rackspace_nimsoft_ch" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_rackspace_nimsoft_ch"
  description  = "role: CHG0069736"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_rackspace_nimsoft_ch_dr.path, nsxt_policy_group.pr-e-internal_rackspace_nimsoft_ch_live.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_external-netflow-sources" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_external-netflow-sources"
  description  = "role: pr-e-internal_grp_external-netflow-sources"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_grp_gi-mpl-border-routers.path, nsxt_policy_group.pr-e-internal_grp_uk-brs-border-routers.path, nsxt_policy_group.pr-e-internal_grp_uk-ld6-border-routers.path, nsxt_policy_group.pr-e-internal_grp_uk-sc1-border-routers.path, nsxt_policy_group.pr-e-internal_grp_stj-ar-routers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-swinds-polling-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-swinds-polling-svrs"
  description  = "role: pr-e-internal_grp_grp-swinds-polling-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1wnpremn74.path, nsxt_policy_group.pr-e-internal_sc1wnpremn75.path, nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_uk-sc1-border-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_uk-sc1-border-routers"
  description  = "role: CHG0077138"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_uk-sc1-er01-lo0.path, nsxt_policy_group.pr-e-internal_uk-sc1-er02-lo0.path, nsxt_policy_group.pr-e-internal_uk-sc1-es01.path, nsxt_policy_group.pr-e-internal_uk-sc1-es02.path, nsxt_policy_group.pr-e-internal_uk-sc1-dmvpn01.path, nsxt_policy_group.pr-e-internal_uk-sc1-dmvpn02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_snow_public" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_snow_public"
  description  = "role: pr-e-internal_grp_snow_public"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_servicenowams-datacentre.path, nsxt_policy_group.pr-e-internal_servicenowlhr-datacentre.path, nsxt_policy_group.pr-e-internal_ip_199-91-137-100.path, nsxt_policy_group.pr-e-internal_ip_37-98-232-100.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-sql-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-sql-servers"
  description  = "role: CHG0117835"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsux1rdb001.path, nsxt_policy_group.pr-e-internal_brsux1rdb002.path, nsxt_policy_group.pr-e-internal_brsux2rdb001.path, nsxt_policy_group.pr-e-internal_brsux2rdb002.path, nsxt_policy_group.pr-e-internal_brsuxdrrdb001.path, nsxt_policy_group.pr-e-internal_ld6uxptrdb002.path, nsxt_policy_group.pr-e-internal_retail-omni-mysql-dev-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb001.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb0012.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-trs-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-trs-db-servers"
  description  = "role: CHG0118067"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsuxdrrdb04.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb-vip.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb04.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-liability-viewer-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-liability-viewer-servers"
  description  = "role: CHG0118070"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsux003.path, nsxt_policy_group.pr-e-internal_brsux232.path, nsxt_policy_group.pr-e-internal_liability-live-vip.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb01.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-oscar-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-oscar-db-servers"
  description  = "role: CHG0118072"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsuxdrrvr05.path, nsxt_policy_group.pr-e-internal_brsuxp1rvr05.path, nsxt_policy_group.pr-e-internal_brsuxp1rvr06.path, nsxt_policy_group.pr-e-internal_brsuxp2rvr05.path, nsxt_policy_group.pr-e-internal_brsuxp2rvr06.path, nsxt_policy_group.pr-e-internal_brsuxp3rvr005.path, nsxt_policy_group.pr-e-internal_brsuxp3rvr006.path, nsxt_policy_group.pr-e-internal_sc1uxprrvr05.path, nsxt_policy_group.pr-e-internal_sc1uxprrvr06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-bingo-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-bingo-db-servers"
  description  = "role: CHG0118080"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsuxdrrdb010.path, nsxt_policy_group.pr-e-internal_brsuxp1rdb010.path, nsxt_policy_group.pr-e-internal_brsuxp2rdb010.path, nsxt_policy_group.pr-e-internal_sc1uxprrdb010.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-shopdiary-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-shopdiary-db-servers"
  description  = "role: CHG0118083"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsuxdrshd010.path, nsxt_policy_group.pr-e-internal_brsuxr1rdb003.path, nsxt_policy_group.pr-e-internal_sc1uxprshd010.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_mysqlenterprisemonitor" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_mysqlenterprisemonitor"
  description  = "role: CHG0119313"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_brsux121.path, nsxt_policy_group.pr-e-internal_brsux122.path, nsxt_policy_group.pr-e-internal_gibux321vip.path, nsxt_policy_group.pr-e-internal_gibux322.path, nsxt_policy_group.pr-e-internal_gibux322vip.path, nsxt_policy_group.pr-e-internal_ld6ux321.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-scc-mars-mysql-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-scc-mars-mysql-svrs"
  description  = "role: pr-e-internal_grp_grp-scc-mars-mysql-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-99-95.path, nsxt_policy_group.pr-e-internal_sc1uxprndb001-vip.path, nsxt_policy_group.pr-e-internal_sc1uxprndb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_grp-scc-mars-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_grp-scc-mars-db-servers"
  description  = "role: pr-e-internal_grp_grp-scc-mars-db-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-99-151.path, nsxt_policy_group.pr-e-internal_10-120-99-152.path, nsxt_policy_group.pr-e-internal_sc1uxprnap43_44vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_brs-xiv" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_brs-xiv"
  description  = "role: pr-e-internal_grp_brs-xiv"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-210-139-229.path, nsxt_policy_group.pr-e-internal_ip_10-210-139-230.path, nsxt_policy_group.pr-e-internal_ip_10-210-139-231.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sc1-xiv" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sc1-xiv"
  description  = "role: pr-e-internal_grp_sc1-xiv"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-120-139-229.path, nsxt_policy_group.pr-e-internal_ip_10-120-139-230.path, nsxt_policy_group.pr-e-internal_ip_10-120-139-231.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ilo-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ilo-nets"
  description  = "role: pr-e-internal_grp_ilo-nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-100-254-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-130-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-120-80-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-130-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-180-80-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-201-225-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-201-254-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-210-130-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_vmc-sddc-retail-production" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_vmc-sddc-retail-production"
  description  = "role: pr-e-internal_grp_vmc-sddc-retail-production"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_vmc-retail-production-vsphere-mgmt.path, nsxt_policy_group.pr-e-internal_vmc-retail-production-10-233-0-0s24.path, nsxt_policy_group.pr-e-internal_vmc-retail-production-services-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_gibstorage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_gibstorage"
  description  = "role: CHG0115147"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-180-46-40.path, nsxt_policy_group.pr-e-internal_10-180-46-41.path, nsxt_policy_group.pr-e-internal_10-180-46-42.path, nsxt_policy_group.pr-e-internal_10-180-46-43.path, nsxt_policy_group.pr-e-internal_10-180-46-44.path, nsxt_policy_group.pr-e-internal_10-180-46-45.path, nsxt_policy_group.pr-e-internal_10-180-46-46.path, nsxt_policy_group.pr-e-internal_10-180-46-47.path, nsxt_policy_group.pr-e-internal_10-180-46-48.path, nsxt_policy_group.pr-e-internal_10-180-46-49.path, nsxt_policy_group.pr-e-internal_10-180-46-50.path, nsxt_policy_group.pr-e-internal_10-180-46-51.path, nsxt_policy_group.pr-e-internal_10-180-46-52.path, nsxt_policy_group.pr-e-internal_10-180-46-53.path, nsxt_policy_group.pr-e-internal_10-180-46-54.path, nsxt_policy_group.pr-e-internal_10-180-46-55.path, nsxt_policy_group.pr-e-internal_10-180-46-56.path, nsxt_policy_group.pr-e-internal_10-180-46-57.path, nsxt_policy_group.pr-e-internal_10-180-46-58.path, nsxt_policy_group.pr-e-internal_10-180-46-59.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ld6storage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ld6storage"
  description  = "role: CHG0115147"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-112-46-40.path, nsxt_policy_group.pr-e-internal_10-112-46-41.path, nsxt_policy_group.pr-e-internal_10-112-46-42.path, nsxt_policy_group.pr-e-internal_10-112-46-43.path, nsxt_policy_group.pr-e-internal_10-112-46-44.path, nsxt_policy_group.pr-e-internal_10-112-46-45.path, nsxt_policy_group.pr-e-internal_10-112-46-46.path, nsxt_policy_group.pr-e-internal_10-112-46-47.path, nsxt_policy_group.pr-e-internal_10-112-46-48.path, nsxt_policy_group.pr-e-internal_10-112-46-49.path, nsxt_policy_group.pr-e-internal_10-112-46-50.path, nsxt_policy_group.pr-e-internal_10-112-46-51.path, nsxt_policy_group.pr-e-internal_10-112-46-52.path, nsxt_policy_group.pr-e-internal_10-112-46-53.path, nsxt_policy_group.pr-e-internal_10-112-46-54.path, nsxt_policy_group.pr-e-internal_10-112-46-55.path, nsxt_policy_group.pr-e-internal_10-112-46-56.path, nsxt_policy_group.pr-e-internal_10-112-46-57.path, nsxt_policy_group.pr-e-internal_10-112-46-58.path, nsxt_policy_group.pr-e-internal_10-112-46-59.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sc1nas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sc1nas"
  description  = "role: CHG0118220"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-77-40.path, nsxt_policy_group.pr-e-internal_10-120-77-41.path, nsxt_policy_group.pr-e-internal_10-120-77-42.path, nsxt_policy_group.pr-e-internal_10-120-77-43.path, nsxt_policy_group.pr-e-internal_10-120-77-44.path, nsxt_policy_group.pr-e-internal_10-120-77-45.path, nsxt_policy_group.pr-e-internal_10-120-77-46.path, nsxt_policy_group.pr-e-internal_10-120-77-47.path, nsxt_policy_group.pr-e-internal_10-120-77-48.path, nsxt_policy_group.pr-e-internal_10-120-77-49.path, nsxt_policy_group.pr-e-internal_10-120-77-50.path, nsxt_policy_group.pr-e-internal_10-120-77-51.path, nsxt_policy_group.pr-e-internal_10-120-77-52.path, nsxt_policy_group.pr-e-internal_10-120-77-53.path, nsxt_policy_group.pr-e-internal_10-120-77-54.path, nsxt_policy_group.pr-e-internal_10-120-77-55.path, nsxt_policy_group.pr-e-internal_10-120-77-56.path, nsxt_policy_group.pr-e-internal_10-120-77-57.path, nsxt_policy_group.pr-e-internal_10-120-77-58.path, nsxt_policy_group.pr-e-internal_10-120-77-59.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sccstorage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sccstorage"
  description  = "role: CHG0115147"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_10-120-46-40.path, nsxt_policy_group.pr-e-internal_10-120-46-41.path, nsxt_policy_group.pr-e-internal_10-120-46-42.path, nsxt_policy_group.pr-e-internal_10-120-46-43.path, nsxt_policy_group.pr-e-internal_10-120-46-44.path, nsxt_policy_group.pr-e-internal_10-120-46-45.path, nsxt_policy_group.pr-e-internal_10-120-46-46.path, nsxt_policy_group.pr-e-internal_10-120-46-47.path, nsxt_policy_group.pr-e-internal_10-120-46-48.path, nsxt_policy_group.pr-e-internal_10-120-46-49.path, nsxt_policy_group.pr-e-internal_10-120-46-50.path, nsxt_policy_group.pr-e-internal_10-120-46-51.path, nsxt_policy_group.pr-e-internal_10-120-46-52.path, nsxt_policy_group.pr-e-internal_10-120-46-53.path, nsxt_policy_group.pr-e-internal_10-120-46-54.path, nsxt_policy_group.pr-e-internal_10-120-46-55.path, nsxt_policy_group.pr-e-internal_10-120-46-56.path, nsxt_policy_group.pr-e-internal_10-120-46-57.path, nsxt_policy_group.pr-e-internal_10-120-46-58.path, nsxt_policy_group.pr-e-internal_10-120-46-59.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_ld6-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_ld6-ras-vpn-pool"
  description  = "role: pr-e-internal_grp_ld6-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_192-168-48-0s20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_sc1-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_sc1-ras-vpn-pool"
  description  = "role: pr-e-internal_grp_sc1-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_192-168-12-0s22.path, nsxt_policy_group.pr-e-internal_ip_192-168-16-0s22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_mrg-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_mrg-ras-vpn-pool"
  description  = "role: pr-e-internal_grp_mrg-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-30-200-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-30-202-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-40-200-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-40-202-0s24.path, nsxt_policy_group.pr-e-internal_ip_10-130-200-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wily_svrs_brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wily_svrs_brs"
  description  = "role: pr-e-internal_grp_wily_svrs_brs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-210-163-95.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-96.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-97.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-98.path, nsxt_policy_group.pr-e-internal_ip_10-210-163-99.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_wily_svrs_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_wily_svrs_gib"
  description  = "role: pr-e-internal_grp_wily_svrs_gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_ip_10-180-163-211.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-212.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-213.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-214.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-218.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-102.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-220.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-221.path, nsxt_policy_group.pr-e-internal_ip_10-180-163-40.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_snmpget" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_snmpget"
  description  = "role: pr-e-internal_grp_snmpget"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_sc1apprein04-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein05-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein06-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein07-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein08-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein09-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein10-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein11-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein12-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1apprein13-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1uxprcmg01.path, nsxt_policy_group.pr-e-internal_sc1uxprcmg02.path, nsxt_policy_group.pr-e-internal_sccadcrprapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sccadcrprapi03-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcapi01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcapi02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcext01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcext02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcint01-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1invadcint02-inv-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcapi02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcextapi01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcextapi02-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcint01-prod-williamhill-plc.path, nsxt_policy_group.pr-e-internal_sc1prdadcint02-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_gi-mpl-border-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_gi-mpl-border-routers"
  description  = "role: pr-e-internal_grp_gi-mpl-border-routers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_gi-mpl-es01-vl20.path, nsxt_policy_group.pr-e-internal_gi-mpl-es02-vl20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_uk-brs-border-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_uk-brs-border-routers"
  description  = "role: pr-e-internal_grp_uk-brs-border-routers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_uk-brs-er01-lo0.path, nsxt_policy_group.pr-e-internal_uk-brs-er02-lo0.path, nsxt_policy_group.pr-e-internal_uk-brs-es01-vl20.path, nsxt_policy_group.pr-e-internal_uk-brs-es02-vl20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_uk-ld6-border-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_uk-ld6-border-routers"
  description  = "role: pr-e-internal_grp_uk-ld6-border-routers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_uk-sc1-er01-lo0.path, nsxt_policy_group.pr-e-internal_uk-sc1-er02-lo0.path, nsxt_policy_group.pr-e-internal_uk-sc1-es01-vl20.path, nsxt_policy_group.pr-e-internal_uk-sc1-es02-vl20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-e-internal_grp_stj-ar-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_grp_stj-ar-routers"
  description  = "role: pr-e-internal_grp_stj-ar-routers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-e-internal_uk-stj-ar01-lo0.path, nsxt_policy_group.pr-e-internal_uk-stj-ar02-lo0.path]
    }
  }
}
