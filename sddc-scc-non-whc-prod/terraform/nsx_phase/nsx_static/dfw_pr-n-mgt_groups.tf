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

resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-193-235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-193-235"
  description  = "role: pr-n-mgt_ip_10-210-193-235, ip: [10.210.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-193-236" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-193-236"
  description  = "role: pr-n-mgt_ip_10-210-193-236, ip: [10.210.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-193-235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-193-235"
  description  = "role: pr-n-mgt_ip_10-180-193-235, ip: [10.180.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-193-236" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-193-236"
  description  = "role: pr-n-mgt_ip_10-180-193-236, ip: [10.180.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-193-235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-193-235"
  description  = "role: pr-n-mgt_ip_10-120-193-235, ip: [10.120.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-193-236" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-193-236"
  description  = "role: pr-n-mgt_ip_10-120-193-236, ip: [10.120.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-201-9-248" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-201-9-248"
  description  = "role: pr-n-mgt_ip_10-201-9-248, ip: [10.201.9.248]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.248"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-100-9-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-100-9-230"
  description  = "role: pr-n-mgt_ip_10-100-9-230, ip: [10.100.9.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-115"
  description  = "role: pr-n-mgt_ip_10-120-146-115, ip: [10.120.146.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-148-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-148-10"
  description  = "role: pr-n-mgt_ip_10-120-148-10, ip: [10.120.148.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-15"
  description  = "role: pr-n-mgt_ip_10-120-194-15, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-3-20-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-3-20-45"
  description  = "role: pr-n-mgt_ip_10-3-20-45, ip: [10.3.20.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-139-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-139-145"
  description  = "role: pr-n-mgt_ip_10-180-139-145, ip: [10.180.139.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.139.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-40"
  description  = "role: pr-n-mgt_ip_10-120-149-40, ip: [10.120.149.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-135"
  description  = "role: pr-n-mgt_ip_10-120-146-135, ip: [10.120.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-25"
  description  = "role: pr-n-mgt_ip_10-120-146-25, ip: [10.120.146.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-34"
  description  = "role: pr-n-mgt_ip_10-120-146-34, ip: [10.120.146.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-194-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-194-83"
  description  = "role: pr-n-mgt_ip_10-210-194-83, ip: [10.210.194.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-165" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-165"
  description  = "role: pr-n-mgt_ip_10-120-146-165, ip: [10.120.146.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-27"
  description  = "role: pr-n-mgt_ip_10-120-146-27, ip: [10.120.146.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-44-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-44-25"
  description  = "role: pr-n-mgt_ip_10-120-44-25, ip: [10.120.44.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-44-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-44-26"
  description  = "role: pr-n-mgt_ip_10-120-44-26, ip: [10.120.44.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-44-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-44-27"
  description  = "role: pr-n-mgt_ip_10-120-44-27, ip: [10.120.44.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-28-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-28-4"
  description  = "role: pr-n-mgt_ip_10-1-28-4, ip: [10.1.28.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-200-4-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-200-4-246"
  description  = "role: pr-n-mgt_ip_10-200-4-246, ip: [10.200.4.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.4.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-201-9-247" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-201-9-247"
  description  = "role: pr-n-mgt_ip_10-201-9-247, ip: [10.201.9.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-53"
  description  = "role: pr-n-mgt_ip_10-120-146-53, ip: [10.120.146.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-54"
  description  = "role: pr-n-mgt_ip_10-120-146-54, ip: [10.120.146.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-148-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-148-36"
  description  = "role: pr-n-mgt_ip_10-120-148-36, ip: [10.120.148.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-148-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-148-37"
  description  = "role: pr-n-mgt_ip_10-120-148-37, ip: [10.120.148.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-36"
  description  = "role: pr-n-mgt_ip_10-120-149-36, ip: [10.120.149.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-37"
  description  = "role: pr-n-mgt_ip_10-120-149-37, ip: [10.120.149.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-60"
  description  = "role: pr-n-mgt_ip_10-120-149-60, ip: [10.120.149.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-31"
  description  = "role: pr-n-mgt_ip_10-120-163-31, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-32"
  description  = "role: pr-n-mgt_ip_10-120-163-32, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-33"
  description  = "role: pr-n-mgt_ip_10-120-163-33, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-34"
  description  = "role: pr-n-mgt_ip_10-120-163-34, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-153-79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-153-79"
  description  = "role: pr-n-mgt_ip_10-120-153-79, ip: [10.120.153.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-153-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-153-80"
  description  = "role: pr-n-mgt_ip_10-120-153-80, ip: [10.120.153.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-148-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-148-11"
  description  = "role: pr-n-mgt_ip_10-120-148-11, ip: [10.120.148.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-180" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-180"
  description  = "role: pr-n-mgt_ip_10-17-100-180, ip: [10.17.100.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-47"
  description  = "role: pr-n-mgt_ip_10-17-100-47, ip: [10.17.100.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-66"
  description  = "role: pr-n-mgt_ip_10-180-19-66, ip: [10.180.19.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-53-33-219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-53-33-219"
  description  = "role: pr-n-mgt_ip_10-53-33-219, ip: [10.53.33.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.33.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-201"
  description  = "role: pr-n-mgt_ip_10-180-19-201, ip: [10.180.19.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-2-232" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-2-232"
  description  = "role: pr-n-mgt_ip_192-168-2-232, ip: [192.168.2.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-143"
  description  = "role: pr-n-mgt_ip_10-40-10-143, ip: [10.40.10.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-144"
  description  = "role: pr-n-mgt_ip_10-40-10-144, ip: [10.40.10.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-145"
  description  = "role: pr-n-mgt_ip_10-40-10-145, ip: [10.40.10.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-146" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-146"
  description  = "role: pr-n-mgt_ip_10-40-10-146, ip: [10.40.10.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-147"
  description  = "role: pr-n-mgt_ip_10-40-10-147, ip: [10.40.10.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-148"
  description  = "role: pr-n-mgt_ip_10-40-10-148, ip: [10.40.10.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-149" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-149"
  description  = "role: pr-n-mgt_ip_10-40-10-149, ip: [10.40.10.149]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.149"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-150" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-150"
  description  = "role: pr-n-mgt_ip_10-40-10-150, ip: [10.40.10.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-151"
  description  = "role: pr-n-mgt_ip_10-40-10-151, ip: [10.40.10.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-152"
  description  = "role: pr-n-mgt_ip_10-40-10-152, ip: [10.40.10.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-153" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-153"
  description  = "role: pr-n-mgt_ip_10-40-10-153, ip: [10.40.10.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-154"
  description  = "role: pr-n-mgt_ip_10-40-10-154, ip: [10.40.10.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-155" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-155"
  description  = "role: pr-n-mgt_ip_10-40-10-155, ip: [10.40.10.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-156" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-156"
  description  = "role: pr-n-mgt_ip_10-40-10-156, ip: [10.40.10.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-157" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-157"
  description  = "role: pr-n-mgt_ip_10-40-10-157, ip: [10.40.10.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-158" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-158"
  description  = "role: pr-n-mgt_ip_10-40-10-158, ip: [10.40.10.158]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.158"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-199" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-199"
  description  = "role: pr-n-mgt_ip_10-40-10-199, ip: [10.40.10.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-102"
  description  = "role: pr-n-mgt_ip_10-40-10-102, ip: [10.40.10.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-124"
  description  = "role: pr-n-mgt_ip_10-40-10-124, ip: [10.40.10.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-132" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-132"
  description  = "role: pr-n-mgt_ip_10-40-10-132, ip: [10.40.10.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-159" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-159"
  description  = "role: pr-n-mgt_ip_10-40-10-159, ip: [10.40.10.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-112" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-112"
  description  = "role: pr-n-mgt_ip_10-40-10-112, ip: [10.40.10.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-113"
  description  = "role: pr-n-mgt_ip_10-40-10-113, ip: [10.40.10.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-116"
  description  = "role: pr-n-mgt_ip_10-40-10-116, ip: [10.40.10.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-123" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-123"
  description  = "role: pr-n-mgt_ip_10-40-10-123, ip: [10.40.10.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-142"
  description  = "role: pr-n-mgt_ip_10-40-10-142, ip: [10.40.10.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-171"
  description  = "role: pr-n-mgt_ip_10-40-10-171, ip: [10.40.10.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-172"
  description  = "role: pr-n-mgt_ip_10-40-10-172, ip: [10.40.10.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-173" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-173"
  description  = "role: pr-n-mgt_ip_10-40-10-173, ip: [10.40.10.173]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.173"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-174" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-174"
  description  = "role: pr-n-mgt_ip_10-40-10-174, ip: [10.40.10.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-175" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-175"
  description  = "role: pr-n-mgt_ip_10-40-10-175, ip: [10.40.10.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-176" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-176"
  description  = "role: pr-n-mgt_ip_10-40-10-176, ip: [10.40.10.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-177" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-177"
  description  = "role: pr-n-mgt_ip_10-40-10-177, ip: [10.40.10.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-178" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-178"
  description  = "role: pr-n-mgt_ip_10-40-10-178, ip: [10.40.10.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-179"
  description  = "role: pr-n-mgt_ip_10-40-10-179, ip: [10.40.10.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-180" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-180"
  description  = "role: pr-n-mgt_ip_10-40-10-180, ip: [10.40.10.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-181"
  description  = "role: pr-n-mgt_ip_10-40-10-181, ip: [10.40.10.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-182"
  description  = "role: pr-n-mgt_ip_10-40-10-182, ip: [10.40.10.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-183"
  description  = "role: pr-n-mgt_ip_10-40-10-183, ip: [10.40.10.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-184" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-184"
  description  = "role: pr-n-mgt_ip_10-40-10-184, ip: [10.40.10.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-185"
  description  = "role: pr-n-mgt_ip_10-40-10-185, ip: [10.40.10.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-186" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-186"
  description  = "role: pr-n-mgt_ip_10-40-10-186, ip: [10.40.10.186]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.186"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-187" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-187"
  description  = "role: pr-n-mgt_ip_10-40-10-187, ip: [10.40.10.187]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.187"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-188" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-188"
  description  = "role: pr-n-mgt_ip_10-40-10-188, ip: [10.40.10.188]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.188"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-189" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-189"
  description  = "role: pr-n-mgt_ip_10-40-10-189, ip: [10.40.10.189]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.189"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-190" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-190"
  description  = "role: pr-n-mgt_ip_10-40-10-190, ip: [10.40.10.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.190"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-191" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-191"
  description  = "role: pr-n-mgt_ip_10-40-10-191, ip: [10.40.10.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-192" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-192"
  description  = "role: pr-n-mgt_ip_10-40-10-192, ip: [10.40.10.192]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.192"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-193" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-193"
  description  = "role: pr-n-mgt_ip_10-40-10-193, ip: [10.40.10.193]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.193"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-194" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-194"
  description  = "role: pr-n-mgt_ip_10-40-10-194, ip: [10.40.10.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-195" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-195"
  description  = "role: pr-n-mgt_ip_10-40-10-195, ip: [10.40.10.195]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.195"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-196" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-196"
  description  = "role: pr-n-mgt_ip_10-40-10-196, ip: [10.40.10.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-197" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-197"
  description  = "role: pr-n-mgt_ip_10-40-10-197, ip: [10.40.10.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-198" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-198"
  description  = "role: pr-n-mgt_ip_10-40-10-198, ip: [10.40.10.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-200"
  description  = "role: pr-n-mgt_ip_10-40-10-200, ip: [10.40.10.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-201"
  description  = "role: pr-n-mgt_ip_10-40-10-201, ip: [10.40.10.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-202" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-202"
  description  = "role: pr-n-mgt_ip_10-40-10-202, ip: [10.40.10.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-203"
  description  = "role: pr-n-mgt_ip_10-40-10-203, ip: [10.40.10.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-204"
  description  = "role: pr-n-mgt_ip_10-40-10-204, ip: [10.40.10.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-205"
  description  = "role: pr-n-mgt_ip_10-40-10-205, ip: [10.40.10.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-206"
  description  = "role: pr-n-mgt_ip_10-40-10-206, ip: [10.40.10.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-207" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-207"
  description  = "role: pr-n-mgt_ip_10-40-10-207, ip: [10.40.10.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-208" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-208"
  description  = "role: pr-n-mgt_ip_10-40-10-208, ip: [10.40.10.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-209" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-209"
  description  = "role: pr-n-mgt_ip_10-40-10-209, ip: [10.40.10.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-210" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-210"
  description  = "role: pr-n-mgt_ip_10-40-10-210, ip: [10.40.10.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-211"
  description  = "role: pr-n-mgt_ip_10-40-10-211, ip: [10.40.10.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-212"
  description  = "role: pr-n-mgt_ip_10-40-10-212, ip: [10.40.10.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-213"
  description  = "role: pr-n-mgt_ip_10-40-10-213, ip: [10.40.10.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-214"
  description  = "role: pr-n-mgt_ip_10-40-10-214, ip: [10.40.10.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-215" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-215"
  description  = "role: pr-n-mgt_ip_10-40-10-215, ip: [10.40.10.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-130" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-130"
  description  = "role: pr-n-mgt_ip_10-40-10-130, ip: [10.40.10.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-11-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-11-100"
  description  = "role: pr-n-mgt_ip_10-40-11-100, ip: [10.40.11.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.11.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-231" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-231"
  description  = "role: pr-n-mgt_ip_10-40-10-231, ip: [10.40.10.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-232" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-232"
  description  = "role: pr-n-mgt_ip_10-40-10-232, ip: [10.40.10.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-216" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-216"
  description  = "role: pr-n-mgt_ip_10-40-10-216, ip: [10.40.10.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-217" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-217"
  description  = "role: pr-n-mgt_ip_10-40-10-217, ip: [10.40.10.217]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.217"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-218"
  description  = "role: pr-n-mgt_ip_10-40-10-218, ip: [10.40.10.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-53-32-168" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-53-32-168"
  description  = "role: pr-n-mgt_ip_10-53-32-168, ip: [10.53.32.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-220"
  description  = "role: pr-n-mgt_ip_10-40-10-220, ip: [10.40.10.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-221"
  description  = "role: pr-n-mgt_ip_10-40-10-221, ip: [10.40.10.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-222" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-222"
  description  = "role: pr-n-mgt_ip_10-40-10-222, ip: [10.40.10.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-223" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-223"
  description  = "role: pr-n-mgt_ip_10-40-10-223, ip: [10.40.10.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-224" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-224"
  description  = "role: pr-n-mgt_ip_10-40-10-224, ip: [10.40.10.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.224"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-225" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-225"
  description  = "role: pr-n-mgt_ip_10-40-10-225, ip: [10.40.10.225]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.225"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-226" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-226"
  description  = "role: pr-n-mgt_ip_10-40-10-226, ip: [10.40.10.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-227" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-227"
  description  = "role: pr-n-mgt_ip_10-40-10-227, ip: [10.40.10.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-228" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-228"
  description  = "role: pr-n-mgt_ip_10-40-10-228, ip: [10.40.10.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-229"
  description  = "role: pr-n-mgt_ip_10-40-10-229, ip: [10.40.10.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-230"
  description  = "role: pr-n-mgt_ip_10-40-10-230, ip: [10.40.10.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-233" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-233"
  description  = "role: pr-n-mgt_ip_10-40-10-233, ip: [10.40.10.233]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.233"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-241" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-241"
  description  = "role: pr-n-mgt_ip_10-40-10-241, ip: [10.40.10.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-234"
  description  = "role: pr-n-mgt_ip_10-40-10-234, ip: [10.40.10.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-116"
  description  = "role: pr-n-mgt_ip_10-120-146-116, ip: [10.120.146.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-131" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-131"
  description  = "role: pr-n-mgt_ip_10-120-163-131, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-128" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-128"
  description  = "role: pr-n-mgt_ip_10-120-163-128, ip: [10.120.163.128]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.128"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-136-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-136-140"
  description  = "role: pr-n-mgt_ip_10-120-136-140, ip: [10.120.136.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-77"
  description  = "role: pr-n-mgt_ip_10-120-194-77, ip: [10.120.194.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-44"
  description  = "role: pr-n-mgt_ip_10-180-18-44, ip: [10.180.18.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-95"
  description  = "role: pr-n-mgt_ip_10-180-18-95, ip: [10.180.18.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-131-191" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-131-191"
  description  = "role: pr-n-mgt_ip_10-120-131-191, ip: [10.120.131.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-136-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-136-181"
  description  = "role: pr-n-mgt_ip_10-120-136-181, ip: [10.120.136.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-97"
  description  = "role: pr-n-mgt_ip_10-180-18-97, ip: [10.180.18.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-219"
  description  = "role: pr-n-mgt_ip_10-180-19-219, ip: [10.180.19.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-22-168" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-22-168"
  description  = "role: pr-n-mgt_ip_10-1-22-168, ip: [10.1.22.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-22-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-22-17"
  description  = "role: pr-n-mgt_ip_10-1-22-17, ip: [10.1.22.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-22-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-22-181"
  description  = "role: pr-n-mgt_ip_10-1-22-181, ip: [10.1.22.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-22-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-22-185"
  description  = "role: pr-n-mgt_ip_10-1-22-185, ip: [10.1.22.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-82-92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-82-92"
  description  = "role: pr-n-mgt_ip_10-1-82-92, ip: [10.1.82.92]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.92"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-3-60-206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-3-60-206"
  description  = "role: pr-n-mgt_ip_10-3-60-206, ip: [10.3.60.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.60.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-145-121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-145-121"
  description  = "role: pr-n-mgt_ip_10-120-145-121, ip: [10.120.145.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-145-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-145-122"
  description  = "role: pr-n-mgt_ip_10-120-145-122, ip: [10.120.145.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-145-123" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-145-123"
  description  = "role: pr-n-mgt_ip_10-120-145-123, ip: [10.120.145.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-145-124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-145-124"
  description  = "role: pr-n-mgt_ip_10-120-145-124, ip: [10.120.145.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-61"
  description  = "role: pr-n-mgt_ip_10-120-147-61, ip: [10.120.147.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-62"
  description  = "role: pr-n-mgt_ip_10-120-147-62, ip: [10.120.147.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-63"
  description  = "role: pr-n-mgt_ip_10-120-147-63, ip: [10.120.147.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-64"
  description  = "role: pr-n-mgt_ip_10-120-147-64, ip: [10.120.147.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-71-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-71-2"
  description  = "role: pr-n-mgt_ip_10-1-71-2, ip: [10.1.71.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.71.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-224" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-224"
  description  = "role: pr-n-mgt_ip_10-180-19-224, ip: [10.180.19.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.224"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-141" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-141"
  description  = "role: pr-n-mgt_ip_10-180-19-141, ip: [10.180.19.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-222" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-222"
  description  = "role: pr-n-mgt_ip_10-180-19-222, ip: [10.180.19.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-221"
  description  = "role: pr-n-mgt_ip_10-180-19-221, ip: [10.180.19.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-143"
  description  = "role: pr-n-mgt_ip_10-180-19-143, ip: [10.180.19.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-226" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-226"
  description  = "role: pr-n-mgt_ip_10-180-19-226, ip: [10.180.19.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-139"
  description  = "role: pr-n-mgt_ip_10-180-19-139, ip: [10.180.19.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-166"
  description  = "role: pr-n-mgt_ip_10-17-100-166, ip: [10.17.100.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-204"
  description  = "role: pr-n-mgt_ip_10-17-100-204, ip: [10.17.100.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-160" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-160"
  description  = "role: pr-n-mgt_ip_10-17-100-160, ip: [10.17.100.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-161" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-161"
  description  = "role: pr-n-mgt_ip_10-17-100-161, ip: [10.17.100.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.161"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-168" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-168"
  description  = "role: pr-n-mgt_ip_10-17-100-168, ip: [10.17.100.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-142"
  description  = "role: pr-n-mgt_ip_10-180-19-142, ip: [10.180.19.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-140"
  description  = "role: pr-n-mgt_ip_10-180-19-140, ip: [10.180.19.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-135"
  description  = "role: pr-n-mgt_ip_10-180-19-135, ip: [10.180.19.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-133" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-133"
  description  = "role: pr-n-mgt_ip_10-180-19-133, ip: [10.180.19.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-165" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-165"
  description  = "role: pr-n-mgt_ip_10-180-18-165, ip: [10.180.18.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-144"
  description  = "role: pr-n-mgt_ip_10-180-18-144, ip: [10.180.18.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-134"
  description  = "role: pr-n-mgt_ip_10-180-19-134, ip: [10.180.19.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-137"
  description  = "role: pr-n-mgt_ip_10-180-19-137, ip: [10.180.19.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-228" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-228"
  description  = "role: pr-n-mgt_ip_10-180-19-228, ip: [10.180.19.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-136"
  description  = "role: pr-n-mgt_ip_10-180-19-136, ip: [10.180.19.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-229"
  description  = "role: pr-n-mgt_ip_10-180-19-229, ip: [10.180.19.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-98"
  description  = "role: pr-n-mgt_ip_10-180-18-98, ip: [10.180.18.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-73"
  description  = "role: pr-n-mgt_ip_10-180-19-73, ip: [10.180.19.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-69"
  description  = "role: pr-n-mgt_ip_10-180-18-69, ip: [10.180.18.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-46"
  description  = "role: pr-n-mgt_ip_10-180-19-46, ip: [10.180.19.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-39"
  description  = "role: pr-n-mgt_ip_10-180-18-39, ip: [10.180.18.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-45"
  description  = "role: pr-n-mgt_ip_10-180-18-45, ip: [10.180.18.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-181"
  description  = "role: pr-n-mgt_ip_10-180-19-181, ip: [10.180.19.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-182"
  description  = "role: pr-n-mgt_ip_10-180-19-182, ip: [10.180.19.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-70"
  description  = "role: pr-n-mgt_ip_10-180-19-70, ip: [10.180.19.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-67"
  description  = "role: pr-n-mgt_ip_10-180-19-67, ip: [10.180.19.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-9"
  description  = "role: pr-n-mgt_ip_10-180-19-9, ip: [10.180.19.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-21"
  description  = "role: pr-n-mgt_ip_10-180-19-21, ip: [10.180.19.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-124"
  description  = "role: pr-n-mgt_ip_10-1-18-124, ip: [10.1.18.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-159" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-159"
  description  = "role: pr-n-mgt_ip_10-1-18-159, ip: [10.1.18.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-19"
  description  = "role: pr-n-mgt_ip_10-1-18-19, ip: [10.1.18.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-226" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-226"
  description  = "role: pr-n-mgt_ip_10-1-18-226, ip: [10.1.18.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-228" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-228"
  description  = "role: pr-n-mgt_ip_10-1-18-228, ip: [10.1.18.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-28"
  description  = "role: pr-n-mgt_ip_10-1-18-28, ip: [10.1.18.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-69"
  description  = "role: pr-n-mgt_ip_10-1-18-69, ip: [10.1.18.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-45"
  description  = "role: pr-n-mgt_ip_10-1-66-45, ip: [10.1.66.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-112-237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-112-237"
  description  = "role: pr-n-mgt_ip_10-1-112-237, ip: [10.1.112.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-75"
  description  = "role: pr-n-mgt_ip_10-1-113-75, ip: [10.1.113.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-77"
  description  = "role: pr-n-mgt_ip_10-1-113-77, ip: [10.1.113.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-78"
  description  = "role: pr-n-mgt_ip_10-1-113-78, ip: [10.1.113.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-79"
  description  = "role: pr-n-mgt_ip_10-1-113-79, ip: [10.1.113.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-82"
  description  = "role: pr-n-mgt_ip_10-1-113-82, ip: [10.1.113.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-87"
  description  = "role: pr-n-mgt_ip_10-1-113-87, ip: [10.1.113.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-150" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-150"
  description  = "role: pr-n-mgt_ip_10-1-13-150, ip: [10.1.13.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-177" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-177"
  description  = "role: pr-n-mgt_ip_10-1-13-177, ip: [10.1.13.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-211"
  description  = "role: pr-n-mgt_ip_10-1-13-211, ip: [10.1.13.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-216" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-216"
  description  = "role: pr-n-mgt_ip_10-1-13-216, ip: [10.1.13.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-30"
  description  = "role: pr-n-mgt_ip_10-1-13-30, ip: [10.1.13.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-54"
  description  = "role: pr-n-mgt_ip_10-1-13-54, ip: [10.1.13.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-84"
  description  = "role: pr-n-mgt_ip_10-1-13-84, ip: [10.1.13.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-98"
  description  = "role: pr-n-mgt_ip_10-1-13-98, ip: [10.1.13.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-100"
  description  = "role: pr-n-mgt_ip_10-1-18-100, ip: [10.1.18.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-107"
  description  = "role: pr-n-mgt_ip_10-1-18-107, ip: [10.1.18.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-113"
  description  = "role: pr-n-mgt_ip_10-1-18-113, ip: [10.1.18.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-114" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-114"
  description  = "role: pr-n-mgt_ip_10-1-18-114, ip: [10.1.18.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-122"
  description  = "role: pr-n-mgt_ip_10-1-18-122, ip: [10.1.18.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-137"
  description  = "role: pr-n-mgt_ip_10-1-18-137, ip: [10.1.18.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-139"
  description  = "role: pr-n-mgt_ip_10-1-18-139, ip: [10.1.18.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-147"
  description  = "role: pr-n-mgt_ip_10-1-18-147, ip: [10.1.18.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-148"
  description  = "role: pr-n-mgt_ip_10-1-18-148, ip: [10.1.18.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-156" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-156"
  description  = "role: pr-n-mgt_ip_10-1-18-156, ip: [10.1.18.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-15"
  description  = "role: pr-n-mgt_ip_10-1-18-15, ip: [10.1.18.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-161" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-161"
  description  = "role: pr-n-mgt_ip_10-1-18-161, ip: [10.1.18.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.161"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-162" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-162"
  description  = "role: pr-n-mgt_ip_10-1-18-162, ip: [10.1.18.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-164"
  description  = "role: pr-n-mgt_ip_10-1-18-164, ip: [10.1.18.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-166"
  description  = "role: pr-n-mgt_ip_10-1-18-166, ip: [10.1.18.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-167" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-167"
  description  = "role: pr-n-mgt_ip_10-1-18-167, ip: [10.1.18.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-17"
  description  = "role: pr-n-mgt_ip_10-1-18-17, ip: [10.1.18.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-190" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-190"
  description  = "role: pr-n-mgt_ip_10-1-18-190, ip: [10.1.18.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.190"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-193" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-193"
  description  = "role: pr-n-mgt_ip_10-1-18-193, ip: [10.1.18.193]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.193"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-198" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-198"
  description  = "role: pr-n-mgt_ip_10-1-18-198, ip: [10.1.18.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-203"
  description  = "role: pr-n-mgt_ip_10-1-18-203, ip: [10.1.18.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-208" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-208"
  description  = "role: pr-n-mgt_ip_10-1-18-208, ip: [10.1.18.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-215" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-215"
  description  = "role: pr-n-mgt_ip_10-1-18-215, ip: [10.1.18.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-219"
  description  = "role: pr-n-mgt_ip_10-1-18-219, ip: [10.1.18.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-223" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-223"
  description  = "role: pr-n-mgt_ip_10-1-18-223, ip: [10.1.18.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-242"
  description  = "role: pr-n-mgt_ip_10-1-18-242, ip: [10.1.18.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-24"
  description  = "role: pr-n-mgt_ip_10-1-18-24, ip: [10.1.18.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-25"
  description  = "role: pr-n-mgt_ip_10-1-18-25, ip: [10.1.18.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-29"
  description  = "role: pr-n-mgt_ip_10-1-18-29, ip: [10.1.18.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-31"
  description  = "role: pr-n-mgt_ip_10-1-18-31, ip: [10.1.18.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-48"
  description  = "role: pr-n-mgt_ip_10-1-18-48, ip: [10.1.18.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-50"
  description  = "role: pr-n-mgt_ip_10-1-18-50, ip: [10.1.18.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-51"
  description  = "role: pr-n-mgt_ip_10-1-18-51, ip: [10.1.18.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-53"
  description  = "role: pr-n-mgt_ip_10-1-18-53, ip: [10.1.18.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-54"
  description  = "role: pr-n-mgt_ip_10-1-18-54, ip: [10.1.18.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-66"
  description  = "role: pr-n-mgt_ip_10-1-18-66, ip: [10.1.18.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-74"
  description  = "role: pr-n-mgt_ip_10-1-18-74, ip: [10.1.18.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-76"
  description  = "role: pr-n-mgt_ip_10-1-18-76, ip: [10.1.18.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-82"
  description  = "role: pr-n-mgt_ip_10-1-18-82, ip: [10.1.18.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-154"
  description  = "role: pr-n-mgt_ip_10-1-30-154, ip: [10.1.30.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-179"
  description  = "role: pr-n-mgt_ip_10-1-30-179, ip: [10.1.30.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-194" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-194"
  description  = "role: pr-n-mgt_ip_10-1-30-194, ip: [10.1.30.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-196" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-196"
  description  = "role: pr-n-mgt_ip_10-1-30-196, ip: [10.1.30.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-246"
  description  = "role: pr-n-mgt_ip_10-1-30-246, ip: [10.1.30.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-39"
  description  = "role: pr-n-mgt_ip_10-1-30-39, ip: [10.1.30.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-77"
  description  = "role: pr-n-mgt_ip_10-1-30-77, ip: [10.1.30.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-80"
  description  = "role: pr-n-mgt_ip_10-1-30-80, ip: [10.1.30.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-88"
  description  = "role: pr-n-mgt_ip_10-1-30-88, ip: [10.1.30.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-94" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-94"
  description  = "role: pr-n-mgt_ip_10-1-30-94, ip: [10.1.30.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-95"
  description  = "role: pr-n-mgt_ip_10-1-30-95, ip: [10.1.30.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-33"
  description  = "role: pr-n-mgt_ip_10-1-66-33, ip: [10.1.66.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-34"
  description  = "role: pr-n-mgt_ip_10-1-66-34, ip: [10.1.66.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-58"
  description  = "role: pr-n-mgt_ip_10-1-66-58, ip: [10.1.66.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-60"
  description  = "role: pr-n-mgt_ip_10-1-66-60, ip: [10.1.66.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-63"
  description  = "role: pr-n-mgt_ip_10-1-66-63, ip: [10.1.66.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-138"
  description  = "role: pr-n-mgt_ip_10-1-13-138, ip: [10.1.13.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-140"
  description  = "role: pr-n-mgt_ip_10-1-18-140, ip: [10.1.18.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-75"
  description  = "role: pr-n-mgt_ip_10-1-18-75, ip: [10.1.18.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-37"
  description  = "role: pr-n-mgt_ip_10-1-66-37, ip: [10.1.66.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-38"
  description  = "role: pr-n-mgt_ip_10-1-66-38, ip: [10.1.66.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-39"
  description  = "role: pr-n-mgt_ip_10-1-66-39, ip: [10.1.66.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-41"
  description  = "role: pr-n-mgt_ip_10-1-66-41, ip: [10.1.66.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-47"
  description  = "role: pr-n-mgt_ip_10-1-66-47, ip: [10.1.66.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-48"
  description  = "role: pr-n-mgt_ip_10-1-66-48, ip: [10.1.66.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-49"
  description  = "role: pr-n-mgt_ip_10-1-66-49, ip: [10.1.66.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-51"
  description  = "role: pr-n-mgt_ip_10-1-66-51, ip: [10.1.66.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-66-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-66-53"
  description  = "role: pr-n-mgt_ip_10-1-66-53, ip: [10.1.66.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-38"
  description  = "role: pr-n-mgt_ip_10-1-18-38, ip: [10.1.18.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-150" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-150"
  description  = "role: pr-n-mgt_ip_10-180-19-150, ip: [10.180.19.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-2-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-2-40"
  description  = "role: pr-n-mgt_ip_192-168-2-40, ip: [192.168.2.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-2-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-2-37"
  description  = "role: pr-n-mgt_ip_192-168-2-37, ip: [192.168.2.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-93"
  description  = "role: pr-n-mgt_ip_10-180-19-93, ip: [10.180.19.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-201-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-201-84"
  description  = "role: pr-n-mgt_ip_192-168-201-84, ip: [192.168.201.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-176" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-176"
  description  = "role: pr-n-mgt_ip_10-180-19-176, ip: [10.180.19.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-62"
  description  = "role: pr-n-mgt_ip_10-180-19-62, ip: [10.180.19.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-14"
  description  = "role: pr-n-mgt_ip_10-180-19-14, ip: [10.180.19.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-82"
  description  = "role: pr-n-mgt_ip_10-180-19-82, ip: [10.180.19.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-201"
  description  = "role: pr-n-mgt_ip_10-180-18-201, ip: [10.180.18.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-24"
  description  = "role: pr-n-mgt_ip_10-180-19-24, ip: [10.180.19.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-67-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-67-171"
  description  = "role: pr-n-mgt_ip_10-1-67-171, ip: [10.1.67.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.67.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-239"
  description  = "role: pr-n-mgt_ip_10-180-19-239, ip: [10.180.19.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-83-128" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-83-128"
  description  = "role: pr-n-mgt_ip_10-1-83-128, ip: [10.1.83.128]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.128"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-62"
  description  = "role: pr-n-mgt_ip_10-120-163-62, ip: [10.120.163.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-55"
  description  = "role: pr-n-mgt_ip_10-120-146-55, ip: [10.120.146.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-55-0-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-55-0-55"
  description  = "role: pr-n-mgt_ip_10-55-0-55, ip: [10.55.0.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-55-1-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-55-1-221"
  description  = "role: pr-n-mgt_ip_10-55-1-221, ip: [10.55.1.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.1.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-133" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-133"
  description  = "role: pr-n-mgt_ip_10-120-146-133, ip: [10.120.146.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-134"
  description  = "role: pr-n-mgt_ip_10-120-146-134, ip: [10.120.146.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-151"
  description  = "role: pr-n-mgt_ip_10-120-146-151, ip: [10.120.146.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-152"
  description  = "role: pr-n-mgt_ip_10-120-146-152, ip: [10.120.146.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-60"
  description  = "role: pr-n-mgt_ip_10-120-146-60, ip: [10.120.146.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-62"
  description  = "role: pr-n-mgt_ip_10-120-146-62, ip: [10.120.146.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-97"
  description  = "role: pr-n-mgt_ip_10-120-146-97, ip: [10.120.146.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-98"
  description  = "role: pr-n-mgt_ip_10-120-146-98, ip: [10.120.146.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-59"
  description  = "role: pr-n-mgt_ip_10-180-27-59, ip: [10.180.27.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-60"
  description  = "role: pr-n-mgt_ip_10-180-27-60, ip: [10.180.27.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-105"
  description  = "role: pr-n-mgt_ip_10-40-10-105, ip: [10.40.10.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-107"
  description  = "role: pr-n-mgt_ip_10-40-10-107, ip: [10.40.10.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-100"
  description  = "role: pr-n-mgt_ip_10-40-10-100, ip: [10.40.10.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-101"
  description  = "role: pr-n-mgt_ip_10-40-10-101, ip: [10.40.10.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-103"
  description  = "role: pr-n-mgt_ip_10-40-10-103, ip: [10.40.10.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-104"
  description  = "role: pr-n-mgt_ip_10-40-10-104, ip: [10.40.10.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-106"
  description  = "role: pr-n-mgt_ip_10-40-10-106, ip: [10.40.10.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-108"
  description  = "role: pr-n-mgt_ip_10-40-10-108, ip: [10.40.10.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-109"
  description  = "role: pr-n-mgt_ip_10-40-10-109, ip: [10.40.10.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-110"
  description  = "role: pr-n-mgt_ip_10-40-10-110, ip: [10.40.10.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-111" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-111"
  description  = "role: pr-n-mgt_ip_10-40-10-111, ip: [10.40.10.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-114" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-114"
  description  = "role: pr-n-mgt_ip_10-40-10-114, ip: [10.40.10.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-115"
  description  = "role: pr-n-mgt_ip_10-40-10-115, ip: [10.40.10.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-117" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-117"
  description  = "role: pr-n-mgt_ip_10-40-10-117, ip: [10.40.10.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-118"
  description  = "role: pr-n-mgt_ip_10-40-10-118, ip: [10.40.10.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-119" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-119"
  description  = "role: pr-n-mgt_ip_10-40-10-119, ip: [10.40.10.119]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.119"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-120"
  description  = "role: pr-n-mgt_ip_10-40-10-120, ip: [10.40.10.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-121"
  description  = "role: pr-n-mgt_ip_10-40-10-121, ip: [10.40.10.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-10-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-10-122"
  description  = "role: pr-n-mgt_ip_10-40-10-122, ip: [10.40.10.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-59"
  description  = "role: pr-n-mgt_ip_10-120-163-59, ip: [10.120.163.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-21"
  description  = "role: pr-n-mgt_ip_10-210-163-21, ip: [10.210.163.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-73"
  description  = "role: pr-n-mgt_ip_10-120-163-73, ip: [10.120.163.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-65-68"
  description  = "role: pr-n-mgt_ip_10-120-65-68, ip: [10.120.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-65-68"
  description  = "role: pr-n-mgt_ip_10-210-65-68, ip: [10.210.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-13"
  description  = "role: pr-n-mgt_ip_10-120-194-13, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-14"
  description  = "role: pr-n-mgt_ip_10-120-194-14, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-18"
  description  = "role: pr-n-mgt_ip_10-120-194-18, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-16"
  description  = "role: pr-n-mgt_ip_10-120-194-16, ip: [10.120.194.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-17"
  description  = "role: pr-n-mgt_ip_10-120-194-17, ip: [10.120.194.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-11"
  description  = "role: pr-n-mgt_ip_10-120-194-11, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-12"
  description  = "role: pr-n-mgt_ip_10-120-194-12, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-51"
  description  = "role: pr-n-mgt_ip_10-120-149-51, ip: [10.120.149.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-194-12"
  description  = "role: pr-n-mgt_ip_10-210-194-12, ip: [10.210.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-194-13"
  description  = "role: pr-n-mgt_ip_10-210-194-13, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-194-15"
  description  = "role: pr-n-mgt_ip_10-210-194-15, ip: [10.210.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-106"
  description  = "role: pr-n-mgt_ip_10-1-148-106, ip: [10.1.148.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-137"
  description  = "role: pr-n-mgt_ip_10-1-148-137, ip: [10.1.148.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-157" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-157"
  description  = "role: pr-n-mgt_ip_10-1-148-157, ip: [10.1.148.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-246"
  description  = "role: pr-n-mgt_ip_10-1-148-246, ip: [10.1.148.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-66"
  description  = "role: pr-n-mgt_ip_10-1-148-66, ip: [10.1.148.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-148-85" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-148-85"
  description  = "role: pr-n-mgt_ip_10-1-148-85, ip: [10.1.148.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-74-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-74-144"
  description  = "role: pr-n-mgt_ip_10-1-74-144, ip: [10.1.74.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-74-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-74-166"
  description  = "role: pr-n-mgt_ip_10-1-74-166, ip: [10.1.74.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-112-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-112-230"
  description  = "role: pr-n-mgt_ip_10-1-112-230, ip: [10.1.112.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-21-118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-21-118"
  description  = "role: pr-n-mgt_ip_10-1-21-118, ip: [10.1.21.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.21.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-83-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-83-15"
  description  = "role: pr-n-mgt_ip_10-1-83-15, ip: [10.1.83.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-25"
  description  = "role: pr-n-mgt_ip_10-120-147-25, ip: [10.120.147.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-26"
  description  = "role: pr-n-mgt_ip_10-120-147-26, ip: [10.120.147.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-69"
  description  = "role: pr-n-mgt_ip_10-120-147-69, ip: [10.120.147.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-70"
  description  = "role: pr-n-mgt_ip_10-120-147-70, ip: [10.120.147.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-241" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-241"
  description  = "role: pr-n-mgt_ip_10-120-147-241, ip: [10.120.147.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-242"
  description  = "role: pr-n-mgt_ip_10-120-147-242, ip: [10.120.147.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-243"
  description  = "role: pr-n-mgt_ip_10-120-147-243, ip: [10.120.147.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-244" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-244"
  description  = "role: pr-n-mgt_ip_10-120-147-244, ip: [10.120.147.244]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.244"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-245" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-245"
  description  = "role: pr-n-mgt_ip_10-120-147-245, ip: [10.120.147.245]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.245"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-147-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-147-246"
  description  = "role: pr-n-mgt_ip_10-120-147-246, ip: [10.120.147.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-14"
  description  = "role: pr-n-mgt_ip_10-1-18-14, ip: [10.1.18.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-236" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-236"
  description  = "role: pr-n-mgt_ip_10-1-113-236, ip: [10.1.113.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-46"
  description  = "role: pr-n-mgt_ip_10-1-113-46, ip: [10.1.113.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-51"
  description  = "role: pr-n-mgt_ip_10-1-113-51, ip: [10.1.113.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-113-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-113-62"
  description  = "role: pr-n-mgt_ip_10-1-113-62, ip: [10.1.113.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-145"
  description  = "role: pr-n-mgt_ip_10-1-13-145, ip: [10.1.13.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-166"
  description  = "role: pr-n-mgt_ip_10-1-13-166, ip: [10.1.13.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-13-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-13-212"
  description  = "role: pr-n-mgt_ip_10-1-13-212, ip: [10.1.13.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-175" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-175"
  description  = "role: pr-n-mgt_ip_10-1-18-175, ip: [10.1.18.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-42"
  description  = "role: pr-n-mgt_ip_10-1-18-42, ip: [10.1.18.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-21"
  description  = "role: pr-n-mgt_ip_10-1-30-21, ip: [10.1.30.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-30-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-30-56"
  description  = "role: pr-n-mgt_ip_10-1-30-56, ip: [10.1.30.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-52-162" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-52-162"
  description  = "role: pr-n-mgt_ip_10-1-52-162, ip: [10.1.52.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.52.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-12-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-12-211"
  description  = "role: pr-n-mgt_ip_10-123-12-211, ip: [10.123.12.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-23"
  description  = "role: pr-n-mgt_ip_10-180-18-23, ip: [10.180.18.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-12-149" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-12-149"
  description  = "role: pr-n-mgt_ip_10-123-12-149, ip: [10.123.12.149]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.149"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-12-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-12-171"
  description  = "role: pr-n-mgt_ip_10-123-12-171, ip: [10.123.12.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-13-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-13-24"
  description  = "role: pr-n-mgt_ip_10-123-13-24, ip: [10.123.13.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-22-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-22-211"
  description  = "role: pr-n-mgt_ip_10-123-22-211, ip: [10.123.22.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.22.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-123-12-132" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-123-12-132"
  description  = "role: pr-n-mgt_ip_10-123-12-132, ip: [10.123.12.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-169" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-169"
  description  = "role: pr-n-mgt_ip_10-180-18-169, ip: [10.180.18.169]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.169"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-148"
  description  = "role: pr-n-mgt_ip_10-180-18-148, ip: [10.180.18.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-202" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-202"
  description  = "role: pr-n-mgt_ip_10-180-18-202, ip: [10.180.18.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-152"
  description  = "role: pr-n-mgt_ip_10-180-19-152, ip: [10.180.19.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-157" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-157"
  description  = "role: pr-n-mgt_ip_10-180-18-157, ip: [10.180.18.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-189" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-189"
  description  = "role: pr-n-mgt_ip_10-180-18-189, ip: [10.180.18.189]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.189"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-89"
  description  = "role: pr-n-mgt_ip_10-180-19-89, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-80"
  description  = "role: pr-n-mgt_ip_10-180-19-80, ip: [10.180.19.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-122"
  description  = "role: pr-n-mgt_ip_10-180-19-122, ip: [10.180.19.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-26"
  description  = "role: pr-n-mgt_ip_10-180-19-26, ip: [10.180.19.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-110"
  description  = "role: pr-n-mgt_ip_10-180-18-110, ip: [10.180.18.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-18-113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-18-113"
  description  = "role: pr-n-mgt_ip_10-180-18-113, ip: [10.180.18.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-217" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-217"
  description  = "role: pr-n-mgt_ip_10-180-19-217, ip: [10.180.19.217]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.217"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-19-179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-19-179"
  description  = "role: pr-n-mgt_ip_10-180-19-179, ip: [10.180.19.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-102-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-102-55"
  description  = "role: pr-n-mgt_ip_10-120-102-55, ip: [10.120.102.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-102-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-102-56"
  description  = "role: pr-n-mgt_ip_10-120-102-56, ip: [10.120.102.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-102-61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-102-61"
  description  = "role: pr-n-mgt_ip_10-120-102-61, ip: [10.120.102.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-102-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-102-62"
  description  = "role: pr-n-mgt_ip_10-120-102-62, ip: [10.120.102.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-18"
  description  = "role: pr-n-mgt_ip_10-180-27-18, ip: [10.180.27.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-22"
  description  = "role: pr-n-mgt_ip_10-180-27-22, ip: [10.180.27.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-66"
  description  = "role: pr-n-mgt_ip_10-180-27-66, ip: [10.180.27.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-81"
  description  = "role: pr-n-mgt_ip_10-180-27-81, ip: [10.180.27.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-82"
  description  = "role: pr-n-mgt_ip_10-180-27-82, ip: [10.180.27.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-27-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-27-93"
  description  = "role: pr-n-mgt_ip_10-180-27-93, ip: [10.180.27.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-95"
  description  = "role: pr-n-mgt_ip_10-210-163-95, ip: [10.210.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-96"
  description  = "role: pr-n-mgt_ip_10-210-163-96, ip: [10.210.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-97"
  description  = "role: pr-n-mgt_ip_10-210-163-97, ip: [10.210.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-98"
  description  = "role: pr-n-mgt_ip_10-210-163-98, ip: [10.210.163.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-163-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-163-99"
  description  = "role: pr-n-mgt_ip_10-210-163-99, ip: [10.210.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-36"
  description  = "role: pr-n-mgt_ip_10-120-163-36, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-211"
  description  = "role: pr-n-mgt_ip_10-180-163-211, ip: [10.180.163.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-212"
  description  = "role: pr-n-mgt_ip_10-180-163-212, ip: [10.180.163.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-213"
  description  = "role: pr-n-mgt_ip_10-180-163-213, ip: [10.180.163.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-214"
  description  = "role: pr-n-mgt_ip_10-180-163-214, ip: [10.180.163.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-218"
  description  = "role: pr-n-mgt_ip_10-180-163-218, ip: [10.180.163.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-102"
  description  = "role: pr-n-mgt_ip_10-180-163-102, ip: [10.180.163.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-220"
  description  = "role: pr-n-mgt_ip_10-180-163-220, ip: [10.180.163.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-221"
  description  = "role: pr-n-mgt_ip_10-180-163-221, ip: [10.180.163.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-163-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-163-40"
  description  = "role: pr-n-mgt_ip_10-180-163-40, ip: [10.180.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-151-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-151-0s24"
  description  = "role: pr-n-mgt_ip_10-120-151-0s24, ip: [10.120.151.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-145-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-145-0s24"
  description  = "role: pr-n-mgt_ip_10-120-145-0s24, ip: [10.120.145.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-46-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-46-0s25"
  description  = "role: pr-n-mgt_ip_10-120-46-0s25, ip: [10.120.46.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-146-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-146-0s24"
  description  = "role: pr-n-mgt_ip_10-120-146-0s24, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-149-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-149-0s24"
  description  = "role: pr-n-mgt_ip_10-120-149-0s24, ip: [10.120.149.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-153-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-153-0s24"
  description  = "role: pr-n-mgt_ip_10-120-153-0s24, ip: [10.120.153.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-159-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-159-0s27"
  description  = "role: pr-n-mgt_ip_10-120-159-0s27, ip: [10.120.159.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-2-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-2-0s23"
  description  = "role: pr-n-mgt_ip_192-168-2-0s23, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-0-0-0s8"
  description  = "role: pr-n-mgt_ip_10-0-0-0s8, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-0-0s16"
  description  = "role: pr-n-mgt_ip_10-120-0-0s16, ip: [10.120.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-20s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-20s32"
  description  = "role: pr-n-mgt_ip_10-120-194-20s32, ip: [10.120.194.20/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.20/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-194-140-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-194-140-0s24"
  description  = "role: pr-n-mgt_ip_10-194-140-0s24, ip: [10.194.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_172-16-0-0s12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_172-16-0-0s12"
  description  = "role: pr-n-mgt_ip_172-16-0-0s12, ip: [172.16.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-0-0s16"
  description  = "role: pr-n-mgt_ip_192-168-0-0s16, ip: [192.168.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-144-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-144-0s20"
  description  = "role: pr-n-mgt_ip_10-120-144-0s20, ip: [10.120.144.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.144.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-159-96s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-159-96s27"
  description  = "role: pr-n-mgt_ip_10-120-159-96s27, ip: [10.120.159.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-194-64s26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-194-64s26"
  description  = "role: pr-n-mgt_ip_10-120-194-64s26, ip: [10.120.194.64/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.64/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-17-100-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-17-100-0s24"
  description  = "role: pr-n-mgt_ip_10-17-100-0s24, ip: [10.17.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-53-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-53-0-0s24"
  description  = "role: pr-n-mgt_ip_10-53-0-0s24, ip: [10.53.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-144-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-144-0s24"
  description  = "role: pr-n-mgt_ip_10-120-144-0s24, ip: [10.120.144.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.144.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-148-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-148-0s24"
  description  = "role: pr-n-mgt_ip_10-120-148-0s24, ip: [10.120.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-159-192s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-159-192s27"
  description  = "role: pr-n-mgt_ip_10-120-159-192s27, ip: [10.120.159.192/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.192/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-18-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-18-0s24"
  description  = "role: pr-n-mgt_ip_10-1-18-0s24, ip: [10.1.18.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-152-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-152-0s24"
  description  = "role: pr-n-mgt_ip_10-120-152-0s24, ip: [10.120.152.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-22-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-22-0s24"
  description  = "role: pr-n-mgt_ip_10-1-22-0s24, ip: [10.1.22.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-48-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-48-0s20"
  description  = "role: pr-n-mgt_ip_192-168-48-0s20, ip: [192.168.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-82-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-82-0s23"
  description  = "role: pr-n-mgt_ip_10-1-82-0s23, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-160-192s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-160-192s27"
  description  = "role: pr-n-mgt_ip_10-120-160-192s27, ip: [10.120.160.192/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.160.192/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-156-5-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-156-5-0s24"
  description  = "role: pr-n-mgt_ip_10-156-5-0s24, ip: [10.156.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-210-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-210-0-0s16"
  description  = "role: pr-n-mgt_ip_10-210-0-0s16, ip: [10.210.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-180-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-180-0-0s16"
  description  = "role: pr-n-mgt_ip_10-180-0-0s16, ip: [10.180.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-112-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-112-0-0s16"
  description  = "role: pr-n-mgt_ip_10-112-0-0s16, ip: [10.112.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-19-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-19-0-0s16"
  description  = "role: pr-n-mgt_ip_10-19-0-0s16, ip: [10.19.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-14-120s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-14-120s32"
  description  = "role: pr-n-mgt_ip_10-1-14-120s32, ip: [10.1.14.120/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.14.120/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-19s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-19s32"
  description  = "role: pr-n-mgt_ip_10-120-163-19s32, ip: [10.120.163.19/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.19/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-120-163-20s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-120-163-20s32"
  description  = "role: pr-n-mgt_ip_10-120-163-20s32, ip: [10.120.163.20/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.20/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-1-34-10s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-1-34-10s32"
  description  = "role: pr-n-mgt_ip_10-1-34-10s32, ip: [10.1.34.10/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.34.10/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-64-72-10s32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-64-72-10s32"
  description  = "role: pr-n-mgt_ip_10-64-72-10s32, ip: [10.64.72.10/32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.64.72.10/32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-194-20-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-194-20-0s24"
  description  = "role: pr-n-mgt_ip_10-194-20-0s24, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-193-30-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-193-30-0s24"
  description  = "role: pr-n-mgt_ip_10-193-30-0s24, ip: [10.193.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-12-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-12-0s22"
  description  = "role: pr-n-mgt_ip_192-168-12-0s22, ip: [192.168.12.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.12.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-16-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-16-0s22"
  description  = "role: pr-n-mgt_ip_192-168-16-0s22, ip: [192.168.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_192-168-0-0s21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_192-168-0-0s21"
  description  = "role: pr-n-mgt_ip_192-168-0-0s21, ip: [192.168.0.0/21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.0.0/21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-30-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-30-200-0s24"
  description  = "role: pr-n-mgt_ip_10-30-200-0s24, ip: [10.30.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-30-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-30-202-0s24"
  description  = "role: pr-n-mgt_ip_10-30-202-0s24, ip: [10.30.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-200-0s24"
  description  = "role: pr-n-mgt_ip_10-40-200-0s24, ip: [10.40.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-40-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-40-202-0s24"
  description  = "role: pr-n-mgt_ip_10-40-202-0s24, ip: [10.40.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ip_10-130-200-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ip_10-130-200-0s23"
  description  = "role: pr-n-mgt_ip_10-130-200-0s23, ip: [10.130.200.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.200.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-noncde-jumphost-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-noncde-jumphost-lan"
  description  = "role: pr-n-mgt_sc1-noncde-jumphost-lan, ip: [10.120.151.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_inv-cde-mgmt-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_inv-cde-mgmt-lan"
  description  = "role: pr-n-mgt_inv-cde-mgmt-lan, ip: [10.122.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremg02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremg02"
  description  = "role: pr-n-mgt_sc1uxpremg02, ip: [10.120.163.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_pr-cde-front-cx-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_pr-cde-front-cx-mgmt"
  description  = "role: CHG0068990, ip: [10.121.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_git-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_git-prod-williamhill-plc"
  description  = "role: pr-n-mgt_git-prod-williamhill-plc, ip: [10.120.163.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_invxpup06mst001-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_invxpup06mst001-inv-williamhill-plc"
  description  = "role: pr-n-mgt_invxpup06mst001-inv-williamhill-plc, ip: [10.122.10.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.10.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-cx-ncde-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-cx-ncde-nets"
  description  = "role: CHG0068990, ip: [10.121.64.0/18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.64.0/18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-inv-noncde-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-inv-noncde-nets"
  description  = "role: pr-n-mgt_sc1-inv-noncde-nets, ip: [10.122.64.0/18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.64.0/18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bpl-ctl" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bpl-ctl"
  description  = "role: pr-n-mgt_bpl-ctl, ip: [10.121.10.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-pr-cde-api-integration" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-pr-cde-api-integration"
  description  = "role: CHG0071475, ip: [10.121.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-pr-cde-lan01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-pr-cde-lan01"
  description  = "role: CHG0071650, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-pr-cde-internal-presentation" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-pr-cde-internal-presentation"
  description  = "role: CHG0071650, ip: [10.121.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_inv-cde-int-pres-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_inv-cde-int-pres-lan"
  description  = "role: CHG0071650, ip: [10.122.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_inv-cde-api-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_inv-cde-api-lan"
  description  = "role: CHG0071650, ip: [10.122.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_inv-cde-lan01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_inv-cde-lan01"
  description  = "role: CHG0071650, ip: [10.122.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcsc50-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcsc50-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcsc51-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcsc51-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1jump-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1jump-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxpremn002-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxpremn002-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.210.163.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxpremn003-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxpremn003-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.210.163.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn002-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn002-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibappresc20-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibappresc20-prod-williamhill-plc"
  description  = "role: CHG0114581, ip: [10.180.129.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1appresc20-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1appresc20-prod-williamhill-plc"
  description  = "role: CHG0114581, ip: [10.120.129.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsapdresc20-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsapdresc20-prod-williamhill-plc"
  description  = "role: CHG0114581, ip: [10.210.129.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc"
  description  = "role: pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc, ip: [10.120.151.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_prdxjmp28jmp001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_prdxjmp28jmp001-prod-williamhill-plc"
  description  = "role: pr-n-mgt_prdxjmp28jmp001-prod-williamhill-plc, ip: [10.120.151.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-93-0-0_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-93-0-0_16"
  description  = "role: pr-n-mgt_10-93-0-0_16, ip: [10.93.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.93.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-94-0-0_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-94-0-0_16"
  description  = "role: pr-n-mgt_10-94-0-0_16, ip: [10.94.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.94.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-96-0-0_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-96-0-0_16"
  description  = "role: CHG0120024, ip: [10.96.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.96.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_web-tier-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_web-tier-network-24"
  description  = "role: pr-n-mgt_web-tier-network-24, ip: [10.120.145.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sccuxstnmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sccuxstnmg01"
  description  = "role: pr-n-mgt_sccuxstnmg01, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap70"
  description  = "role: pr-n-mgt_sc1uxprnap70, ip: [10.120.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprnwb91" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprnwb91"
  description  = "role: pr-n-mgt_sc1apprnwb91, ip: [10.120.145.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-214-40-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-214-40-59"
  description  = "role: pr-n-mgt_10-120-214-40-59, ip: [10.120.214.40, 10.120.214.41, 10.120.214.42, 10.120.214.43, 10.120.214.44, 10.120.214.45, 10.120.214.46, 10.120.214.47, 10.120.214.48, 10.120.214.49, 10.120.214.50, 10.120.214.51, 10.120.214.52, 10.120.214.53, 10.120.214.54, 10.120.214.55, 10.120.214.56, 10.120.214.57, 10.120.214.58, 10.120.214.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.214.40", "10.120.214.41", "10.120.214.42", "10.120.214.43", "10.120.214.44", "10.120.214.45", "10.120.214.46", "10.120.214.47", "10.120.214.48", "10.120.214.49", "10.120.214.50", "10.120.214.51", "10.120.214.52", "10.120.214.53", "10.120.214.54", "10.120.214.55", "10.120.214.56", "10.120.214.57", "10.120.214.58", "10.120.214.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_app-tier-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_app-tier-network-24"
  description  = "role: pr-n-mgt_app-tier-network-24, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprgdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprgdb05"
  description  = "role: pr-n-mgt_sc1uxprgdb05, ip: [10.120.146.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6-ncde_db-general-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6-ncde_db-general-db"
  description  = "role: pr-n-mgt_ld6-ncde_db-general-db, ip: [10.118.160.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.128/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cde-server-ilo-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cde-server-ilo-network-24"
  description  = "role: CHG0017787, ip: [10.120.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprncp002-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprncp002-mgmt-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnprncp002-mgmt-prod-williamhill-plc, ip: [10.120.146.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-scc-wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-scc-wsus"
  description  = "role: CHG0014573, ip: [10.120.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremg001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremg001-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnpremg001-prod-williamhill-plc, ip: [10.120.194.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb019"
  description  = "role: pr-n-mgt_sc1wnprndb019, ip: [10.120.146.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-enc02-ilo4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-enc02-ilo4"
  description  = "role: pr-n-mgt_sc1-enc02-ilo4, ip: [10.120.130.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-enc04-ilo9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-enc04-ilo9"
  description  = "role: pr-n-mgt_sc1-enc04-ilo9, ip: [10.120.130.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxoemapp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxoemapp01"
  description  = "role: CHG0124796, ip: [10.201.9.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-nas-ip-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-nas-ip-range"
  description  = "role: SCC NAS IP range, ip: [10.120.46.40, 10.120.46.41, 10.120.46.42, 10.120.46.43, 10.120.46.44, 10.120.46.45, 10.120.46.46, 10.120.46.47, 10.120.46.48, 10.120.46.49, 10.120.46.50, 10.120.46.51, 10.120.46.52, 10.120.46.53, 10.120.46.54, 10.120.46.55, 10.120.46.56, 10.120.46.57, 10.120.46.58, 10.120.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.40", "10.120.46.41", "10.120.46.42", "10.120.46.43", "10.120.46.44", "10.120.46.45", "10.120.46.46", "10.120.46.47", "10.120.46.48", "10.120.46.49", "10.120.46.50", "10.120.46.51", "10.120.46.52", "10.120.46.53", "10.120.46.54", "10.120.46.55", "10.120.46.56", "10.120.46.57", "10.120.46.58", "10.120.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprgdb05_clone" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprgdb05_clone"
  description  = "role: pr-n-mgt_sc1uxprgdb05_clone, ip: [10.120.146.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_backoffice-tier-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_backoffice-tier-network-24"
  description  = "role: pr-n-mgt_backoffice-tier-network-24, ip: [10.120.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb11"
  description  = "role: pr-n-mgt_sc1uxprnwb11, ip: [10.120.148.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb12"
  description  = "role: pr-n-mgt_sc1uxprnwb12, ip: [10.120.148.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb05"
  description  = "role: pr-n-mgt_sc1uxprnwb05, ip: [10.120.148.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb06"
  description  = "role: pr-n-mgt_sc1uxprnwb06, ip: [10.120.148.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprncp001-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprncp001-mgmt-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnprncp001-mgmt-prod-williamhill-plc, ip: [10.120.148.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprncp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprncp001"
  description  = "role: pr-n-mgt_sc1wnprncp001, ip: [10.120.148.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_prod-misvr1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_prod-misvr1"
  description  = "role: pr-n-mgt_prod-misvr1, ip: [10.120.148.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_prod-misvr1-brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_prod-misvr1-brs"
  description  = "role: pr-n-mgt_prod-misvr1-brs, ip: [10.210.148.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.148.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ods-mgmt-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ods-mgmt-network-24"
  description  = "role: pr-n-mgt_ods-mgmt-network-24, ip: [10.120.149.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1nsml01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1nsml01"
  description  = "role: pr-n-mgt_sc1nsml01, ip: [10.120.193.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb002"
  description  = "role: pr-n-mgt_sc1wnprndb002, ip: [10.120.149.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibwnprefs01-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibwnprefs01-group-williamhill-plc"
  description  = "role: pr-n-mgt_gibwnprefs01-group-williamhill-plc, ip: [10.180.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dmtestbench-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dmtestbench-prod"
  description  = "role: pr-n-mgt_dmtestbench-prod, ip: [10.120.149.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-10-120-153-0_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-10-120-153-0_24"
  description  = "role: pr-n-mgt_net-10-120-153-0_24, ip: [10.120.153.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibux208-williamhill-remote" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibux208-williamhill-remote"
  description  = "role: pr-n-mgt_gibux208-williamhill-remote, ip: [10.180.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprein14-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprein14-prod-williamhill-plc"
  description  = "role: CHG0140307, ip: [10.120.145.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibux950" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibux950"
  description  = "role: pr-n-mgt_gibux950, ip: [10.180.163.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ob-vpn-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ob-vpn-range"
  description  = "role: pr-n-mgt_ob-vpn-range, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb81"
  description  = "role: pr-n-mgt_sc1wnprndb81, ip: [10.120.149.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap024-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap024-mgmt-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnprnap024-mgmt-prod-williamhill-plc, ip: [10.120.149.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnmg020" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnmg020"
  description  = "role: pr-n-mgt_sc1wnprnmg020, ip: [10.120.149.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-netbrain01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-netbrain01"
  description  = "role: CHG0056829, ip: [10.120.163.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_edge-mgmt-network-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_edge-mgmt-network-27"
  description  = "role: pr-n-mgt_edge-mgmt-network-27, ip: [10.120.159.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-nessus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-nessus"
  description  = "role: pr-n-mgt_scc-nessus, ip: [10.120.143.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprecp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprecp01"
  description  = "role: pr-n-mgt_sc1wnprecp01, ip: [10.120.146.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxprein02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxprein02"
  description  = "role: CHG0030409, ip: [10.210.163.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprein12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprein12"
  description  = "role: pr-n-mgt_sc1uxprein12, ip: [10.120.163.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-wn-prg-db01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-wn-prg-db01"
  description  = "role: CHG0018025, ip: [10.120.146.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_trs_vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_trs_vip"
  description  = "role: pr-n-mgt_trs_vip, ip: [10.120.146.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-10-1-74-0_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-10-1-74-0_24"
  description  = "role: pr-n-mgt_net-10-1-74-0_24, ip: [10.1.74.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_rod-merrick-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_rod-merrick-pc"
  description  = "role: pr-n-mgt_rod-merrick-pc, ip: [10.3.20.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap100"
  description  = "role: pr-n-mgt_sc1uxprnap100, ip: [10.120.153.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpresc13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpresc13"
  description  = "role: SEPM DMZ Server, ip: [10.120.159.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprgdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprgdb01"
  description  = "role: pr-n-mgt_sc1uxprgdb01, ip: [10.120.146.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjux073" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjux073"
  description  = "role: pr-n-mgt_stjux073, ip: [10.100.9.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc, ip: [10.120.163.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap62"
  description  = "role: pr-n-mgt_sc1uxprnap62, ip: [10.120.146.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnft001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnft001"
  description  = "role: CHG0116707, ip: [10.120.145.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_st_johns_finance_team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_st_johns_finance_team"
  description  = "role: pr-n-mgt_st_johns_finance_team, ip: [10.1.71.101, 10.1.71.102, 10.1.71.103, 10.1.71.104, 10.1.71.105, 10.1.71.106, 10.1.71.107, 10.1.71.108, 10.1.71.109, 10.1.71.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.71.101", "10.1.71.102", "10.1.71.103", "10.1.71.104", "10.1.71.105", "10.1.71.106", "10.1.71.107", "10.1.71.108", "10.1.71.109", "10.1.71.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb51"
  description  = "role: pr-n-mgt_sc1uxprnwb51, ip: [10.120.145.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jabber-brs-vcse-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jabber-brs-vcse-mgmt"
  description  = "role: pr-n-mgt_jabber-brs-vcse-mgmt, ip: [10.210.159.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.159.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jabber-scc-vcse-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jabber-scc-vcse-mgmt"
  description  = "role: CHG0132148, ip: [10.120.159.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibux998" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibux998"
  description  = "role: pr-n-mgt_gibux998, ip: [10.180.163.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsapprcmg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsapprcmg002"
  description  = "role: pr-n-mgt_brsapprcmg002, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5002156" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5002156"
  description  = "role: pr-n-mgt_wh5002156, ip: [10.123.12.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_javier-luna-labrador-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_javier-luna-labrador-pc1"
  description  = "role: RITM0121054, ip: [10.180.27.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-michalsadowski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-michalsadowski"
  description  = "role: CHG0138734, ip: [10.55.15.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sofwnprefs01-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sofwnprefs01-group-williamhill-plc"
  description  = "role: CHG0110410, ip: [10.53.98.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb046" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb046"
  description  = "role: pr-n-mgt_sc1uxprnwb046, ip: [10.120.145.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ntt-vpn-nat-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ntt-vpn-nat-range"
  description  = "role: nat range from brs vpn firewall - CHG0146337, ip: [172.16.100.96/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.100.96/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jabber-uc-vcse-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jabber-uc-vcse-mgmt"
  description  = "role: CHG0113737, ip: [10.120.159.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpromn012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpromn012"
  description  = "role: pr-n-mgt_sc1uxpromn012, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc_snow_collector" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc_snow_collector"
  description  = "role: pr-n-mgt_scc_snow_collector, ip: [10.120.163.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_classa-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_classa-8"
  description  = "role: pr-n-mgt_classa-8, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brs-proofpoint" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brs-proofpoint"
  description  = "role: pr-n-mgt_brs-proofpoint, ip: [10.210.168.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.168.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-proofpoint" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-proofpoint"
  description  = "role: pr-n-mgt_stj-proofpoint, ip: [10.110.168.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.168.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn01"
  description  = "role: pr-n-mgt_sc1wnpremn01, ip: [10.120.163.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpresc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpresc03"
  description  = "role: pr-n-mgt_sc1wnpresc03, ip: [10.120.194.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpresc04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpresc04"
  description  = "role: pr-n-mgt_sc1wnpresc04, ip: [10.120.194.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap43"
  description  = "role: pr-n-mgt_sc1uxprnap43, ip: [10.120.146.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap44"
  description  = "role: pr-n-mgt_sc1uxprnap44, ip: [10.120.146.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrdb04"
  description  = "role: pr-n-mgt_sc1uxprrdb04, ip: [10.120.146.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrdb05"
  description  = "role: pr-n-mgt_sc1uxprrdb05, ip: [10.120.146.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb037" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb037"
  description  = "role: pr-n-mgt_sc1uxprndb037, ip: [10.120.146.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgap02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgap02"
  description  = "role: CHG0022611, ip: [10.120.146.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb037_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb037_ilo"
  description  = "role: pr-n-mgt_sc1uxprndb037_ilo, ip: [10.120.80.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb038_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb038_ilo"
  description  = "role: pr-n-mgt_sc1uxprndb038_ilo, ip: [10.120.80.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-corp-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-corp-tier"
  description  = "role: pr-n-mgt_gib-corp-tier, ip: [10.180.24.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.24.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-ncde-db-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-ncde-db-tier"
  description  = "role: pr-n-mgt_gib-ncde-db-tier, ip: [10.180.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-ncde-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-ncde-mgmt-tier"
  description  = "role: pr-n-mgt_gib-ncde-mgmt-tier, ip: [10.180.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-cde-frontend-hdr-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-cde-frontend-hdr-tier"
  description  = "role: pr-n-mgt_sc1-cde-frontend-hdr-tier, ip: [10.120.48.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-ncde-app-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-ncde-app-tier"
  description  = "role: pr-n-mgt_sc1-ncde-app-tier, ip: [10.120.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-ncde-frontend-ods-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-ncde-frontend-ods-tier"
  description  = "role: pr-n-mgt_sc1-ncde-frontend-ods-tier, ip: [10.120.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-ncde-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-ncde-mgmt-tier"
  description  = "role: pr-n-mgt_sc1-ncde-mgmt-tier, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1-retail-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1-retail-mgmt-tier"
  description  = "role: pr-n-mgt_sc1-retail-mgmt-tier, ip: [10.120.180.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprodb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprodb001"
  description  = "role: CHG0112168, ip: [10.120.146.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprodb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprodb002"
  description  = "role: CHG0112168, ip: [10.120.146.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprodb001_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprodb001_ilo"
  description  = "role: CHG0112168, ip: [10.120.130.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprodb002_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprodb002_ilo"
  description  = "role: CHG0112168, ip: [10.120.130.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsm7001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsm7001"
  description  = "role: pr-n-mgt_brsm7001, ip: [10.210.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sccm7001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sccm7001"
  description  = "role: pr-n-mgt_sccm7001, ip: [10.120.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb05"
  description  = "role: pr-n-mgt_sc1uxprndb05, ip: [10.120.146.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-cheque-troy-printer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-cheque-troy-printer"
  description  = "role: pr-n-mgt_gsh-cheque-troy-printer, ip: [10.3.20.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-cheque-troy-printer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-cheque-troy-printer"
  description  = "role: pr-n-mgt_stj-cheque-troy-printer, ip: [10.1.71.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.71.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb51"
  description  = "role: pr-n-mgt_sc1wnprndb51, ip: [10.120.149.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb52"
  description  = "role: pr-n-mgt_sc1wnprndb52, ip: [10.120.149.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1acprgcp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1acprgcp01"
  description  = "role: CHG0146120, ip: [10.120.194.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1acprgcp01-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1acprgcp01-vmc"
  description  = "role: CHG0146120, ip: [10.120.192.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.170"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1acprgcp01-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1acprgcp01-aci"
  description  = "role: CHG0146120, ip: [10.19.2.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcucm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcucm01"
  description  = "role: CHG0146120, ip: [10.120.194.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcucm01-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcucm01-aci"
  description  = "role: CHG0146120, ip: [10.19.2.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10"
  description  = "role: CHG0146120, ip: [10.120.194.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10-aci"
  description  = "role: CHG0146120, ip: [10.19.2.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10-vip"
  description  = "role: CHG0146120, ip: [10.120.194.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10-vip-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10-vip-aci"
  description  = "role: CHG0146120, ip: [10.19.2.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11"
  description  = "role: CHG0146120, ip: [10.120.194.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11-aci"
  description  = "role: CHG0146120, ip: [10.19.2.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11-vip"
  description  = "role: CHG0146120, ip: [10.120.194.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11-vip-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11-vip-aci"
  description  = "role: CHG0146120, ip: [10.19.2.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo03"
  description  = "role: CHG0146120, ip: [10.120.194.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo03-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo03-aci"
  description  = "role: CHG0146120, ip: [10.19.2.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo04"
  description  = "role: CHG0146120, ip: [10.120.194.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo04-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo04-aci"
  description  = "role: CHG0146120, ip: [10.19.2.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo06"
  description  = "role: CHG0146120, ip: [10.120.194.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo06-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo06-aci"
  description  = "role: CHG0146120, ip: [10.19.2.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnvgprgin06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnvgprgin06"
  description  = "role: CHG0146120, ip: [10.120.194.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnvgprgin06-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnvgprgin06-aci"
  description  = "role: CHG0146120, ip: [10.19.2.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprgcj01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprgcj01"
  description  = "role: CHG0146120, ip: [10.120.194.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprgcj01-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprgcj01-aci"
  description  = "role: CHG0146120, ip: [10.19.2.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo01"
  description  = "role: CHG0146120, ip: [10.120.194.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo01-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo01-aci"
  description  = "role: CHG0146120, ip: [10.19.2.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo02"
  description  = "role: CHG0146120, ip: [10.120.194.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo02-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo02-aci"
  description  = "role: CHG0146120, ip: [10.19.2.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo03"
  description  = "role: CHG0146120, ip: [10.120.194.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo03-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo03-aci"
  description  = "role: CHG0146120, ip: [10.19.2.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo04"
  description  = "role: CHG0146120, ip: [10.120.194.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo04-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo04-aci"
  description  = "role: CHG0146120, ip: [10.19.2.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo05"
  description  = "role: CHG0146120, ip: [10.120.194.86]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.86"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo05-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo05-aci"
  description  = "role: CHG0146120, ip: [10.19.2.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo07" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo07"
  description  = "role: CHG0146120, ip: [10.120.194.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprevo07-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprevo07-aci"
  description  = "role: CHG0146120, ip: [10.19.2.149]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.149"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo08"
  description  = "role: CHG0146120, ip: [10.120.194.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo08-aci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo08-aci"
  description  = "role: CHG0146120, ip: [10.19.2.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ireuxprevo01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ireuxprevo01"
  description  = "role: CHG0146689, ip: [10.120.194.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ireuxprevo01-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ireuxprevo01-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.195]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.195"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo10-vip-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo10-vip-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprevo11-vip-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprevo11-vip-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo06-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo06-vmc"
  description  = "role: CHG0146689, ip: [10.120.192.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_w7d-dbjump" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_w7d-dbjump"
  description  = "role: pr-n-mgt_w7d-dbjump, ip: [10.120.149.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb003_ip_10-120-149-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb003_ip_10-120-149-25"
  description  = "role: pr-n-mgt_sc1wnprndb003_ip_10-120-149-25, ip: [10.120.149.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb004"
  description  = "role: pr-n-mgt_sc1wnprndb004, ip: [10.120.149.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb005_ip_10-120-149-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb005_ip_10-120-149-27"
  description  = "role: pr-n-mgt_sc1wnprndb005_ip_10-120-149-27, ip: [10.120.149.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb006_ip_10-120-149-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb006_ip_10-120-149-28"
  description  = "role: pr-n-mgt_sc1wnprndb006_ip_10-120-149-28, ip: [10.120.149.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap003"
  description  = "role: pr-n-mgt_sc1wnprnap003, ip: [10.120.149.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswnpredc02_ip_10-210-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswnpredc02_ip_10-210-194-12"
  description  = "role: pr-n-mgt_brswnpredc02_ip_10-210-194-12, ip: [10.210.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswnpredc03_ip_10-210-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswnpredc03_ip_10-210-194-13"
  description  = "role: pr-n-mgt_brswnpredc03_ip_10-210-194-13, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc03_ip_10-120-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc03_ip_10-120-194-13"
  description  = "role: pr-n-mgt_sc1wnpredc03_ip_10-120-194-13, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc04_ip_10-120-194-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc04_ip_10-120-194-14"
  description  = "role: pr-n-mgt_sc1wnpredc04_ip_10-120-194-14, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc05_ip_10-120-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc05_ip_10-120-194-15"
  description  = "role: pr-n-mgt_sc1wnpredc05_ip_10-120-194-15, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc08_ip_10-120-194-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc08_ip_10-120-194-18"
  description  = "role: pr-n-mgt_sc1wnpredc08_ip_10-120-194-18, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswndrndb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswndrndb003"
  description  = "role: pr-n-mgt_brswndrndb003, ip: [10.210.149.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.149.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswndrndb004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswndrndb004"
  description  = "role: pr-n-mgt_brswndrndb004, ip: [10.210.149.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.149.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_new-sc1wnprefs03-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_new-sc1wnprefs03-group-williamhill-plc"
  description  = "role: CHG0145624, ip: [10.120.192.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprefs03-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprefs03-group-williamhill-plc"
  description  = "role: pr-n-mgt_sc1wnprefs03-group-williamhill-plc, ip: [10.120.194.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-163-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-163-36"
  description  = "role: pr-n-mgt_10-120-163-36, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc57-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc57-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1uxprntc57-prod-williamhill-plc, ip: [10.120.153.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc58-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc58-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1uxprntc58-prod-williamhill-plc, ip: [10.120.153.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnmq35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnmq35"
  description  = "role: pr-n-mgt_sc1uxprnmq35, ip: [10.120.153.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnmq36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnmq36"
  description  = "role: pr-n-mgt_sc1uxprnmq36, ip: [10.120.153.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn10"
  description  = "role: pr-n-mgt_sc1uxpremn10, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn11"
  description  = "role: pr-n-mgt_sc1uxpremn11, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn12"
  description  = "role: pr-n-mgt_sc1uxpremn12, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn13"
  description  = "role: pr-n-mgt_sc1uxpremn13, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn15"
  description  = "role: pr-n-mgt_sc1uxpremn15, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_adp-host-170-146-243-252" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_adp-host-170-146-243-252"
  description  = "role: CHG0140904, ip: [170.146.243.252]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["170.146.243.252"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net10"
  description  = "role: CHG0142650, ip: [34.250.140.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["34.250.140.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net7"
  description  = "role: CHG0142650, ip: [18.203.225.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["18.203.225.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net8"
  description  = "role: CHG0142650, ip: [18.203.122.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["18.203.122.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net9"
  description  = "role: CHG0142650, ip: [54.76.90.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["54.76.90.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-adp_sftp_access_host1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-adp_sftp_access_host1"
  description  = "role: CHG0139430, ip: [24.234.184.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["24.234.184.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_host1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_host1"
  description  = "role: CHG0139389, ip: [51.163.163.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["51.163.163.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-clearmile_sftp_access_host1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-clearmile_sftp_access_host1"
  description  = "role: CHG0139389, ip: [188.166.212.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["188.166.212.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-evolution_sftp_access_host1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-evolution_sftp_access_host1"
  description  = "role: CHG0139389, ip: [212.38.90.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["212.38.90.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-successfactors_sftp_access_host1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-successfactors_sftp_access_host1"
  description  = "role: CHG0139430, ip: [213.52.186.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["213.52.186.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net1"
  description  = "role: CHG0141789, ip: [51.163.160.176/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["51.163.160.176/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net2"
  description  = "role: CHG0141789, ip: [51.163.163.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["51.163.163.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net3"
  description  = "role: CHG0141789, ip: [149.29.0.152/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["149.29.0.152/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net4"
  description  = "role: CHG0141789, ip: [95.172.67.112/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["95.172.67.112/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net5"
  description  = "role: CHG0141789, ip: [95.172.66.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["95.172.66.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ext-avature_sftp_access_net6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ext-avature_sftp_access_net6"
  description  = "role: CHG0141789, ip: [149.14.158.152/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["149.14.158.152/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb05_06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb05_06"
  description  = "role: pr-n-mgt_sc1wnprgdb05_06, ip: [10.120.146.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb11"
  description  = "role: pr-n-mgt_sc1uxprndb11, ip: [10.120.147.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb12"
  description  = "role: pr-n-mgt_sc1uxprndb12, ip: [10.120.147.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb13"
  description  = "role: pr-n-mgt_sc1uxprndb13, ip: [10.120.147.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb14"
  description  = "role: pr-n-mgt_sc1uxprndb14, ip: [10.120.147.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb15"
  description  = "role: pr-n-mgt_sc1uxprndb15, ip: [10.120.147.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb16"
  description  = "role: pr-n-mgt_sc1uxprndb16, ip: [10.120.147.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-1183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-1183"
  description  = "role: CHG0140307, ip: [10.130.90.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.90.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-2930" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-2930"
  description  = "role: CHG0140307, ip: [10.120.70.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-2931" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-2931"
  description  = "role: CHG0140307, ip: [10.118.208.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.208.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-2947" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-2947"
  description  = "role: CHG0140307, ip: [10.170.18.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.170.18.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-2949" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-2949"
  description  = "role: CHG0140307, ip: [10.170.97.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.170.97.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-3615" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-3615"
  description  = "role: 10.130.90.24, ip: [10.130.90.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.90.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-986" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-986"
  description  = "role: CHG0140307, ip: [10.118.208.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.208.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-987" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-987"
  description  = "role: CHG0140307, ip: [10.120.70.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-990" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-990"
  description  = "role: CHG0140307, ip: [10.170.18.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.170.18.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_va-991" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_va-991"
  description  = "role: CHG0140307, ip: [10.170.97.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.170.97.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap71"
  description  = "role: pr-n-mgt_sc1uxprnap71, ip: [10.120.146.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap72"
  description  = "role: pr-n-mgt_sc1uxprnap72, ip: [10.120.146.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap73"
  description  = "role: pr-n-mgt_sc1uxprnap73, ip: [10.120.146.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brs-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brs-vpn-pool"
  description  = "role: pr-n-mgt_brs-vpn-pool, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-monika-newbound" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-monika-newbound"
  description  = "role: pr-n-mgt_who-monika-newbound, ip: [192.168.9.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilwright" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilwright"
  description  = "role: pr-n-mgt_who-neilwright, ip: [10.180.21.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rocio-jimenez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rocio-jimenez"
  description  = "role: pr-n-mgt_who-rocio-jimenez, ip: [10.1.15.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.15.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-karol-szeplewicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-karol-szeplewicz"
  description  = "role: pr-n-mgt_who-karol-szeplewicz, ip: [10.180.20.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamessturdy_ip_10-17-100-164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamessturdy_ip_10-17-100-164"
  description  = "role: pr-n-mgt_who-jamessturdy_ip_10-17-100-164, ip: [10.17.100.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-sergeymangov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-sergeymangov"
  description  = "role: pr-n-mgt_gib-sergeymangov, ip: [10.180.19.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5002470" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5002470"
  description  = "role: pr-n-mgt_wh5002470, ip: [10.123.13.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp003"
  description  = "role: pr-n-mgt_whtemp003, ip: [10.123.13.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp027" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp027"
  description  = "role: pr-n-mgt_whtemp027, ip: [10.123.12.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp037" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp037"
  description  = "role: pr-n-mgt_whtemp037, ip: [10.123.13.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp055" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp055"
  description  = "role: pr-n-mgt_whtemp055, ip: [10.123.12.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp058" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp058"
  description  = "role: pr-n-mgt_whtemp058, ip: [10.123.13.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp059" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp059"
  description  = "role: pr-n-mgt_whtemp059, ip: [10.123.12.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp060" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp060"
  description  = "role: pr-n-mgt_whtemp060, ip: [10.123.12.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp062" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp062"
  description  = "role: pr-n-mgt_whtemp062, ip: [10.123.12.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp080" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp080"
  description  = "role: pr-n-mgt_whtemp080, ip: [10.123.12.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.161"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp086" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp086"
  description  = "role: pr-n-mgt_whtemp086, ip: [10.123.13.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp089"
  description  = "role: pr-n-mgt_whtemp089, ip: [10.123.13.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-samcarrera" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-samcarrera"
  description  = "role: CHG0093640, ip: [10.1.6.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.6.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-aliebrahim" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-aliebrahim"
  description  = "role: CHG0093640, ip: [10.17.100.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-dionbonner" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-dionbonner"
  description  = "role: CHG0093640, ip: [10.17.100.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-samcarrara" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-samcarrara"
  description  = "role: pr-n-mgt_who-samcarrara, ip: [10.17.100.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-merrynhelleur" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-merrynhelleur"
  description  = "role: pr-n-mgt_who-merrynhelleur, ip: [10.17.100.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-monikanewbound" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-monikanewbound"
  description  = "role: CHG0094578, ip: [10.180.21.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-hazeldincer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-hazeldincer"
  description  = "role: pr-n-mgt_who-hazeldincer, ip: [10.180.20.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mariagrigorova" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mariagrigorova"
  description  = "role: pr-n-mgt_who-mariagrigorova, ip: [10.180.21.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-slawomirniemiec" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-slawomirniemiec"
  description  = "role: pr-n-mgt_who-slawomirniemiec, ip: [10.180.20.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ellaking2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ellaking2"
  description  = "role: pr-n-mgt_who-ellaking2, ip: [10.17.100.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joshroberts2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joshroberts2"
  description  = "role: pr-n-mgt_who-joshroberts2, ip: [10.17.100.92]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.92"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamessturdy1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamessturdy1"
  description  = "role: pr-n-mgt_who-jamessturdy1, ip: [10.17.100.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-martonscocs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-martonscocs"
  description  = "role: pr-n-mgt_who-martonscocs, ip: [10.180.20.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who_andylidbetter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who_andylidbetter"
  description  = "role: pr-n-mgt_who_andylidbetter, ip: [10.180.18.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-grahamrobertson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-grahamrobertson"
  description  = "role: pr-n-mgt_who-grahamrobertson, ip: [10.1.67.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.67.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfa-vip_users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfa-vip_users"
  description  = "role: CHG0115537, ip: [10.56.10.171, 10.56.10.172, 10.56.10.173, 10.56.10.174, 10.56.10.175, 10.56.10.176, 10.56.10.177, 10.56.10.178, 10.56.10.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.171", "10.56.10.172", "10.56.10.173", "10.56.10.174", "10.56.10.175", "10.56.10.176", "10.56.10.177", "10.56.10.178", "10.56.10.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfa-vip_users_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfa-vip_users_2"
  description  = "role: CHG0115537, ip: [10.56.10.171, 10.56.10.172, 10.56.10.173, 10.56.10.174, 10.56.10.175, 10.56.10.176, 10.56.10.177, 10.56.10.178, 10.56.10.179, 10.56.10.180, 10.56.10.181, 10.56.10.182, 10.56.10.183, 10.56.10.184, 10.56.10.185, 10.56.10.186]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.171", "10.56.10.172", "10.56.10.173", "10.56.10.174", "10.56.10.175", "10.56.10.176", "10.56.10.177", "10.56.10.178", "10.56.10.179", "10.56.10.180", "10.56.10.181", "10.56.10.182", "10.56.10.183", "10.56.10.184", "10.56.10.185", "10.56.10.186"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_do_test" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_do_test"
  description  = "role: pr-n-mgt_do_test, ip: [10.1.82.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_nippun_chopra_test_bfa" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nippun_chopra_test_bfa"
  description  = "role: pr-n-mgt_nippun_chopra_test_bfa, ip: [10.56.10.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-180-19-172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-180-19-172"
  description  = "role: pr-n-mgt_host-10-180-19-172, ip: [10.180.19.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-nerysthomas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-nerysthomas"
  description  = "role: pr-n-mgt_gib-nerysthomas, ip: [10.180.19.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-kathrynkiggins" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-kathrynkiggins"
  description  = "role: pr-n-mgt_gib-kathrynkiggins, ip: [10.17.100.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-kirstymoffat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-kirstymoffat"
  description  = "role: TASK0177655, ip: [10.17.100.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfa-sagilaniado" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfa-sagilaniado"
  description  = "role: pr-n-mgt_bfa-sagilaniado, ip: [10.56.12.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-waclawbargiel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-waclawbargiel"
  description  = "role: pr-n-mgt_who-waclawbargiel, ip: [10.55.15.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-leszekgornik" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-leszekgornik"
  description  = "role: pr-n-mgt_who-leszekgornik, ip: [10.55.15.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-55-15-154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-55-15-154"
  description  = "role: pr-n-mgt_host-10-55-15-154, ip: [10.55.15.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-1-87-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-1-87-45"
  description  = "role: pr-n-mgt_host-10-1-87-45, ip: [10.1.87.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-93"
  description  = "role: pr-n-mgt_10-55-12-93, ip: [10.55.12.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap51"
  description  = "role: pr-n-mgt_sc1wnprnap51, ip: [10.120.148.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap52"
  description  = "role: pr-n-mgt_sc1wnprnap52, ip: [10.120.148.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprndb53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprndb53"
  description  = "role: pr-n-mgt_sc1wnprndb53, ip: [10.120.149.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sas-consultant-temp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sas-consultant-temp"
  description  = "role: pr-n-mgt_sas-consultant-temp, ip: [10.17.8.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap001"
  description  = "role: pr-n-mgt_sc1uxprnap001, ip: [10.120.149.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap002"
  description  = "role: pr-n-mgt_sc1uxprnap002, ip: [10.120.149.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap003"
  description  = "role: pr-n-mgt_sc1uxprnap003, ip: [10.120.149.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-victoriagould" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-victoriagould"
  description  = "role: pr-n-mgt_who-victoriagould, ip: [10.56.12.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-jomitrou" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-jomitrou"
  description  = "role: TASK0155631, ip: [10.56.12.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-apapoulias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-apapoulias"
  description  = "role: pr-n-mgt_who-apapoulias, ip: [10.180.21.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-lewisballantine" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-lewisballantine"
  description  = "role: RITM0094092, ip: [10.1.74.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-davidhotson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-davidhotson"
  description  = "role: TASK0172298, ip: [10.56.12.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-garethnetto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-garethnetto"
  description  = "role: pr-n-mgt_gib-garethnetto, ip: [10.180.21.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-garethnetto-desktop" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-garethnetto-desktop"
  description  = "role: CHG0118139, ip: [10.180.19.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-damiandamianov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-damiandamianov"
  description  = "role: RITM0100229, ip: [10.56.12.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danielstringer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danielstringer"
  description  = "role: pr-n-mgt_who-danielstringer, ip: [10.1.78.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-alanhunter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-alanhunter"
  description  = "role: pr-n-mgt_stj-alanhunter, ip: [10.1.13.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-74-159" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-74-159"
  description  = "role: TASK0193665, ip: [10.1.74.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-pedronucci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-pedronucci"
  description  = "role: pr-n-mgt_who-pedronucci, ip: [10.55.12.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-thomasgrabarczyk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-thomasgrabarczyk"
  description  = "role: TASK0192509, ip: [10.180.21.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-laurablancarte" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-laurablancarte"
  description  = "role: TASK0200832, ip: [10.1.74.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-56-12-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-56-12-50"
  description  = "role: pr-n-mgt_10-56-12-50, ip: [10.56.12.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whg-kamiltumiewicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whg-kamiltumiewicz"
  description  = "role: pr-n-mgt_whg-kamiltumiewicz, ip: [10.180.21.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simonfirth" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simonfirth"
  description  = "role: pr-n-mgt_who-simonfirth, ip: [10.56.10.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whg-gosiaraus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whg-gosiaraus"
  description  = "role: pr-n-mgt_whg-gosiaraus, ip: [10.1.86.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-boglarkabihari" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-boglarkabihari"
  description  = "role: pr-n-mgt_who-boglarkabihari, ip: [10.17.100.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ionutmanea" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ionutmanea"
  description  = "role: pr-n-mgt_who-ionutmanea, ip: [10.180.21.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-panagiotistsiolis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-panagiotistsiolis"
  description  = "role: pr-n-mgt_who-panagiotistsiolis, ip: [10.180.19.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-robertwhitehead" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-robertwhitehead"
  description  = "role: pr-n-mgt_who-robertwhitehead, ip: [10.180.20.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-paula-jedrzejczyk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-paula-jedrzejczyk"
  description  = "role: RITM0120071, ip: [10.180.20.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_anthony-kowaliw-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_anthony-kowaliw-pc1"
  description  = "role: RITM0120094, ip: [10.1.117.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.117.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_theodoros-petanidis-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_theodoros-petanidis-pc1"
  description  = "role: RITM0120174, ip: [10.180.20.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_simon-firth-pc1_ip_10-56-10-191" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_simon-firth-pc1_ip_10-56-10-191"
  description  = "role: RITM0120723, ip: [10.56.10.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_simon-firth-pc2_ip_192-168-2-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_simon-firth-pc2_ip_192-168-2-46"
  description  = "role: RITM0120723, ip: [192.168.2.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vasileia-kouti-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vasileia-kouti-pc1"
  description  = "role: RITM0120548, ip: [10.180.20.92]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.92"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_simon-firth-pc2_ip_192-168-2-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_simon-firth-pc2_ip_192-168-2-14"
  description  = "role: RITM0120445, ip: [192.168.2.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_piotr-snarski-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_piotr-snarski-pc1"
  description  = "role: RITM0120841, ip: [10.55.15.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_pawel-opozda-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_pawel-opozda-pc1"
  description  = "role: RITM0119484, ip: [10.55.227.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.227.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_magdalena-sikotowska-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_magdalena-sikotowska-pc1"
  description  = "role: pr-n-mgt_magdalena-sikotowska-pc1, ip: [10.55.15.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_john-edward-lope-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_john-edward-lope-pc1"
  description  = "role: pr-n-mgt_john-edward-lope-pc1, ip: [10.123.13.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_elzbieta-plesnar-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_elzbieta-plesnar-pc1"
  description  = "role: RITM0122295, ip: [10.55.15.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_david-oxley-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_david-oxley-pc1"
  description  = "role: ritmtest, ip: [10.1.82.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_kseniia-koltsova-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_kseniia-koltsova-pc1"
  description  = "role: RITM0122760, ip: [10.55.15.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_iryna-marchenko-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_iryna-marchenko-pc1"
  description  = "role: RITM0122675, ip: [10.55.224.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_erik-wallen-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_erik-wallen-pc1"
  description  = "role: RITM0122605, ip: [10.180.22.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.22.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_fabien-efaty-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_fabien-efaty-pc1"
  description  = "role: pr-n-mgt_fabien-efaty-pc1, ip: [10.40.10.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_andres-gomez-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_andres-gomez-pc1"
  description  = "role: RITM0123481, ip: [10.40.10.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_chris-purnell-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_chris-purnell-pc1"
  description  = "role: RITM0123875, ip: [10.56.12.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_monika-piatek-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_monika-piatek-pc1"
  description  = "role: RITM0123862, ip: [10.55.224.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_nataliia-romanchuk-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nataliia-romanchuk-pc1"
  description  = "role: RITM0123856, ip: [192.168.66.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.66.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mariel-alcoriza-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mariel-alcoriza-pc1"
  description  = "role: RITM0123899, ip: [10.123.12.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_richard-fletcher-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_richard-fletcher-pc1"
  description  = "role: RITM0124226, ip: [192.168.2.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_marek-grzymala-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_marek-grzymala-pc1"
  description  = "role: RITM0125100, ip: [10.55.227.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.227.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_piotr-migdal-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_piotr-migdal-pc1"
  description  = "role: RITM0125096, ip: [10.55.227.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.227.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_pawel-kicek-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_pawel-kicek-pc1"
  description  = "role: RITM0125088, ip: [192.168.69.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.69.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_kundan-yadav-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_kundan-yadav-pc1"
  description  = "role: RITM0124897, ip: [10.1.116.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.116.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_kenneth-farrugia-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_kenneth-farrugia-pc1"
  description  = "role: RITM0122296, ip: [10.40.10.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_thu-van-lee-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_thu-van-lee-pc1"
  description  = "role: RITM0124681, ip: [10.56.12.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_constancia-sanchez-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_constancia-sanchez-pc1"
  description  = "role: RITM0126535, ip: [10.123.13.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-fernandolago" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-fernandolago"
  description  = "role: pr-n-mgt_who-fernandolago, ip: [10.180.18.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-carmitkleinboxer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-carmitkleinboxer"
  description  = "role: pr-n-mgt_who-carmitkleinboxer, ip: [10.51.49.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-zachcohen" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-zachcohen"
  description  = "role: pr-n-mgt_who-zachcohen, ip: [10.51.50.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.50.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83"
  description  = "role: pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83, ip: [10.51.51.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alexandrospapoulias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alexandrospapoulias"
  description  = "role: pr-n-mgt_who-alexandrospapoulias, ip: [10.180.19.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfd-simonfirth" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfd-simonfirth"
  description  = "role: TASK0225279, ip: [10.56.224.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.224.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-andystogdale" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-andystogdale"
  description  = "role: pr-n-mgt_stj-andystogdale, ip: [10.1.74.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-antonioostios" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-antonioostios"
  description  = "role: pr-n-mgt_stj-antonioostios, ip: [10.1.74.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-dancockerill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-dancockerill"
  description  = "role: pr-n-mgt_stj-dancockerill, ip: [10.1.74.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-gustavljundqvist" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-gustavljundqvist"
  description  = "role: pr-n-mgt_stj-gustavljundqvist, ip: [10.1.74.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-jamessmith" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-jamessmith"
  description  = "role: pr-n-mgt_stj-jamessmith, ip: [10.1.74.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-liammosley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-liammosley"
  description  = "role: pr-n-mgt_stj-liammosley, ip: [10.1.74.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-poppywaterhouse" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-poppywaterhouse"
  description  = "role: pr-n-mgt_stj-poppywaterhouse, ip: [10.1.74.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-tradingr_and_d" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-tradingr_and_d"
  description  = "role: pr-n-mgt_stj-tradingr_and_d, ip: [10.1.74.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-new-trading_r_d_svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-new-trading_r_d_svr"
  description  = "role: pr-n-mgt_stj-new-trading_r_d_svr, ip: [10.1.74.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-40-10-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-40-10-134"
  description  = "role: TASK0229634, ip: [10.40.10.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-40-10-236" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-40-10-236"
  description  = "role: pr-n-mgt_10-40-10-236, ip: [10.40.10.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_orbis-dr-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_orbis-dr-nat"
  description  = "role: INC0442038, ip: [10.194.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-mathewbarrett" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-mathewbarrett"
  description  = "role: pr-n-mgt_gsh-mathewbarrett, ip: [10.3.1.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-matthew-barrett-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-matthew-barrett-2"
  description  = "role: pr-n-mgt_gsh-matthew-barrett-2, ip: [10.3.1.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-vasanti-tailor-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-vasanti-tailor-2"
  description  = "role: pr-n-mgt_gsh-vasanti-tailor-2, ip: [10.3.1.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-vasantitaylor" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-vasantitaylor"
  description  = "role: CHG0020745, ip: [10.3.1.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-cacti01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-cacti01"
  description  = "role: CHG0015230, ip: [10.120.163.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-solarwinds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-solarwinds"
  description  = "role: pr-n-mgt_uk-sc1-solarwinds, ip: [10.120.163.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-wn-pre-in03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-wn-pre-in03"
  description  = "role: CHG0018415, ip: [10.120.163.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn14"
  description  = "role: pr-n-mgt_sc1uxpremn14, ip: [10.120.163.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-ncs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-ncs"
  description  = "role: pr-n-mgt_stj-ncs, ip: [10.50.3.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.50.3.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-28"
  description  = "role: pr-n-mgt_dba-28, ip: [10.1.82.96/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.96/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_infosec-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_infosec-28"
  description  = "role: CHG0024220, ip: [10.1.82.48/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.48/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_netsec-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_netsec-27"
  description  = "role: pr-n-mgt_netsec-27, ip: [10.1.82.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_serveroperations-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_serveroperations-27"
  description  = "role: pr-n-mgt_serveroperations-27, ip: [10.1.82.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_environments-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_environments-26"
  description  = "role: pr-n-mgt_environments-26, ip: [10.1.82.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.192/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_incident-analyst-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_incident-analyst-27"
  description  = "role: CHG0032739, ip: [10.1.82.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.128/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_incident-analyst2-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_incident-analyst2-27"
  description  = "role: CHG0036892, ip: [10.1.83.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-grahameades" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-grahameades"
  description  = "role: CHG0056597, ip: [10.1.74.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-byrongalietta" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-byrongalietta"
  description  = "role: pr-n-mgt_lcw-byrongalietta, ip: [10.1.82.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-billpalfreman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-billpalfreman"
  description  = "role: pr-n-mgt_usr-billpalfreman, ip: [10.1.74.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scr-kamentarlov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scr-kamentarlov"
  description  = "role: pr-n-mgt_scr-kamentarlov, ip: [10.1.145.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.145.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-tobyhenderson3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-tobyhenderson3"
  description  = "role: pr-n-mgt_dba-tobyhenderson3, ip: [10.1.74.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-oliverallan2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-oliverallan2"
  description  = "role: CHG0033734, ip: [10.1.74.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-jamesfryer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-jamesfryer"
  description  = "role: pr-n-mgt_dba-jamesfryer, ip: [10.1.74.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-stevemoyes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-stevemoyes"
  description  = "role: pr-n-mgt_lcw-stevemoyes, ip: [10.1.83.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-wh5002126" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-wh5002126"
  description  = "role: pr-n-mgt_stj-wh5002126, ip: [10.1.112.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-andylunn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-andylunn"
  description  = "role: pr-n-mgt_lcw-andylunn, ip: [10.1.82.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net_10-55-60-0_28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net_10-55-60-0_28"
  description  = "role: pr-n-mgt_net_10-55-60-0_28, ip: [10.55.60.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.60.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_netsec-oncall-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_netsec-oncall-28"
  description  = "role: pr-n-mgt_netsec-oncall-28, ip: [172.16.41.208/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.41.208/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.125]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.125"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpremn79-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpremn79-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jabber-uc-vcsc-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jabber-uc-vcsc-mgmt"
  description  = "role: pr-n-mgt_jabber-uc-vcsc-mgmt, ip: [10.120.194.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vc-vcs-express-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vc-vcs-express-mgmt"
  description  = "role: Cisco VCS Express, ip: [10.120.159.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jkirkwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jkirkwood"
  description  = "role: pr-n-mgt_jkirkwood, ip: [10.1.83.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aitor_ayape" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aitor_ayape"
  description  = "role: pr-n-mgt_aitor_ayape, ip: [10.55.14.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-19-2-128s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-19-2-128s25"
  description  = "role: pr-n-mgt_10-19-2-128s25, ip: [10.19.2.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net_10-120-180-0_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net_10-120-180-0_25"
  description  = "role: pr-n-mgt_net_10-120-180-0_25, ip: [10.120.180.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-leesheard" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-leesheard"
  description  = "role: pr-n-mgt_lsj-leesheard, ip: [10.1.66.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcap31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcap31"
  description  = "role: pr-n-mgt_sc1uxprcap31, ip: [10.120.132.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcap32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcap32"
  description  = "role: pr-n-mgt_sc1uxprcap32, ip: [10.120.132.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcap45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcap45"
  description  = "role: pr-n-mgt_sc1uxprcap45, ip: [10.120.132.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcap46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcap46"
  description  = "role: pr-n-mgt_sc1uxprcap46, ip: [10.120.132.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcwb11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcwb11"
  description  = "role: pr-n-mgt_sc1uxprcwb11, ip: [10.120.137.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcwb12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcwb12"
  description  = "role: pr-n-mgt_sc1uxprcwb12, ip: [10.120.137.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcwb13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcwb13"
  description  = "role: pr-n-mgt_sc1uxprcwb13, ip: [10.120.137.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcwb41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcwb41"
  description  = "role: pr-n-mgt_sc1uxprcwb41, ip: [10.120.131.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcwb42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcwb42"
  description  = "role: pr-n-mgt_sc1uxprcwb42, ip: [10.120.131.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap41"
  description  = "role: pr-n-mgt_sc1uxprnap41, ip: [10.120.146.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap42"
  description  = "role: pr-n-mgt_sc1uxprnap42, ip: [10.120.146.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb47"
  description  = "role: pr-n-mgt_sc1uxprndb47, ip: [10.120.146.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb48"
  description  = "role: pr-n-mgt_sc1uxprndb48, ip: [10.120.146.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-katherinehawes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-katherinehawes"
  description  = "role: CHG0030769, ip: [10.180.18.188]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.188"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_app2-tier-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_app2-tier-network-24"
  description  = "role: pr-n-mgt_app2-tier-network-24, ip: [10.120.147.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gsh-jamiebladd" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gsh-jamiebladd"
  description  = "role: pr-n-mgt_gsh-jamiebladd, ip: [10.3.60.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.60.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-craigjohnson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-craigjohnson"
  description  = "role: pr-n-mgt_who-craigjohnson, ip: [10.1.82.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-georgepetrouis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-georgepetrouis"
  description  = "role: pr-n-mgt_who-georgepetrouis, ip: [10.1.83.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ianrichards" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ianrichards"
  description  = "role: pr-n-mgt_who-ianrichards, ip: [10.1.83.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesgirvan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesgirvan"
  description  = "role: pr-n-mgt_who-jamesgirvan, ip: [10.1.83.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jarrodsmithers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jarrodsmithers"
  description  = "role: pr-n-mgt_who-jarrodsmithers, ip: [10.1.83.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilwilson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilwilson"
  description  = "role: pr-n-mgt_who-neilwilson, ip: [10.1.83.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-patmills" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-patmills"
  description  = "role: pr-n-mgt_who-patmills, ip: [10.17.8.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardsanderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardsanderson"
  description  = "role: pr-n-mgt_who-richardsanderson, ip: [10.1.83.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-johnnoel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-johnnoel"
  description  = "role: pr-n-mgt_lcw-johnnoel, ip: [10.1.83.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_email-mgmt-network-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_email-mgmt-network-27"
  description  = "role: pr-n-mgt_email-mgmt-network-27, ip: [10.120.159.192/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.192/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_server-ilo-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_server-ilo-network-24"
  description  = "role: pr-n-mgt_server-ilo-network-24, ip: [10.120.144.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.144.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vc-mgmt-network-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vc-mgmt-network-27"
  description  = "role: Cisco VCS DMZ, ip: [10.120.159.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_webscreen-mgmt-network-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_webscreen-mgmt-network-27"
  description  = "role: pr-n-mgt_webscreen-mgmt-network-27, ip: [10.120.159.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap74"
  description  = "role: pr-n-mgt_sc1uxprnap74, ip: [10.120.146.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprein30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprein30"
  description  = "role: pr-n-mgt_sc1wnprein30, ip: [10.120.195.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprein31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprein31"
  description  = "role: pr-n-mgt_sc1wnprein31, ip: [10.120.195.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-145-71-78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-145-71-78"
  description  = "role: pr-n-mgt_10-120-145-71-78, ip: [10.120.145.71, 10.120.145.72, 10.120.145.73, 10.120.145.74, 10.120.145.75, 10.120.145.76, 10.120.145.77, 10.120.145.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.71", "10.120.145.72", "10.120.145.73", "10.120.145.74", "10.120.145.75", "10.120.145.76", "10.120.145.77", "10.120.145.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-147-71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-147-71"
  description  = "role: pr-n-mgt_10-120-147-71, ip: [10.120.147.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-147-72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-147-72"
  description  = "role: pr-n-mgt_10-120-147-72, ip: [10.120.147.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap65"
  description  = "role: pr-n-mgt_sc1uxprnap65, ip: [10.120.147.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap66"
  description  = "role: pr-n-mgt_sc1uxprnap66, ip: [10.120.147.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap017" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap017"
  description  = "role: pr-n-mgt_sc1uxprnap017, ip: [10.120.147.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap018" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap018"
  description  = "role: pr-n-mgt_sc1uxprnap018, ip: [10.120.147.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap047" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap047"
  description  = "role: pr-n-mgt_sc1uxprnap047, ip: [10.120.147.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap048" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap048"
  description  = "role: pr-n-mgt_sc1uxprnap048, ip: [10.120.147.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap079" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap079"
  description  = "role: pr-n-mgt_sc1uxprnap079, ip: [10.120.147.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap080" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap080"
  description  = "role: pr-n-mgt_sc1uxprnap080, ip: [10.120.147.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap081" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap081"
  description  = "role: pr-n-mgt_sc1uxprnap081, ip: [10.120.147.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap082" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap082"
  description  = "role: pr-n-mgt_sc1uxprnap082, ip: [10.120.147.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap083" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap083"
  description  = "role: pr-n-mgt_sc1uxprnap083, ip: [10.120.147.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp033" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp033"
  description  = "role: CHG0090927, ip: [10.123.13.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-chriswade" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-chriswade"
  description  = "role: pr-n-mgt_stj-chriswade, ip: [10.1.18.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-traders" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-traders"
  description  = "role: pr-n-mgt_stj-traders, ip: [10.1.112.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-chriswade2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-chriswade2"
  description  = "role: pr-n-mgt_stj-chriswade2, ip: [10.1.18.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrap01-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrap01-mg"
  description  = "role: Liability Viewer PDS app server, ip: [10.120.180.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrap02-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrap02-mg"
  description  = "role: Liability Viewer PDS app server, ip: [10.120.180.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrap03-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrap03-mg"
  description  = "role: Liability Viewer Euthenia app server, ip: [10.120.180.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprrap04-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprrap04-mg"
  description  = "role: Liability Viewer Euthenia server, ip: [10.120.180.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-jw" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-jw"
  description  = "role: pr-n-mgt_lcw-jw, ip: [10.1.82.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-152-21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-152-21"
  description  = "role: pr-n-mgt_10-120-152-21, ip: [10.120.152.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-152-22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-152-22"
  description  = "role: pr-n-mgt_10-120-152-22, ip: [10.120.152.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb21"
  description  = "role: pr-n-mgt_sc1uxprnwb21, ip: [10.120.152.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb22"
  description  = "role: pr-n-mgt_sc1uxprnwb22, ip: [10.120.152.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-paulmartin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-paulmartin"
  description  = "role: pr-n-mgt_dba-paulmartin, ip: [10.1.74.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-timwilkinson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-timwilkinson"
  description  = "role: pr-n-mgt_dba-timwilkinson, ip: [10.1.74.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-farukhshah" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-farukhshah"
  description  = "role: pr-n-mgt_who-farukhshah, ip: [10.1.83.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswnstrdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswnstrdb001"
  description  = "role: pr-n-mgt_brswnstrdb001, ip: [10.1.28.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-3-20-112" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-3-20-112"
  description  = "role: CHG0091339, ip: [10.3.20.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-3-20-113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-3-20-113"
  description  = "role: CHG0091339, ip: [10.3.20.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-maggierolls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-maggierolls"
  description  = "role: pr-n-mgt_stj-maggierolls, ip: [10.1.58.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-kejautouray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-kejautouray"
  description  = "role: CHG0124290, ip: [10.1.82.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5001700" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5001700"
  description  = "role: CHG0129845, ip: [10.118.194.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.194.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-kundanyadav" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-kundanyadav"
  description  = "role: pr-n-mgt_stj-kundanyadav, ip: [10.1.74.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-richardniland" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-richardniland"
  description  = "role: pr-n-mgt_usr-richardniland, ip: [10.1.18.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-richardniland2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-richardniland2"
  description  = "role: pr-n-mgt_usr-richardniland2, ip: [10.1.18.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alb-kejautouray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alb-kejautouray"
  description  = "role: CHG0124657, ip: [10.1.59.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.59.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_davidemagni_sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_davidemagni_sslvpn"
  description  = "role: pr-n-mgt_davidemagni_sslvpn, ip: [192.168.200.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lorenarodriguez_sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lorenarodriguez_sslvpn"
  description  = "role: pr-n-mgt_lorenarodriguez_sslvpn, ip: [192.168.200.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mattiascagliola_sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mattiascagliola_sslvpn"
  description  = "role: pr-n-mgt_mattiascagliola_sslvpn, ip: [192.168.200.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marktrotter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marktrotter"
  description  = "role: pr-n-mgt_who-marktrotter, ip: [10.1.30.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-andrewtibet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-andrewtibet"
  description  = "role: pr-n-mgt_who-andrewtibet, ip: [10.180.19.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-151"
  description  = "role: pr-n-mgt_10-1-30-151, ip: [10.1.30.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-62-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-62-30"
  description  = "role: pr-n-mgt_10-1-62-30, ip: [10.1.62.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.62.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-alanhunter2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-alanhunter2"
  description  = "role: pr-n-mgt_stj-alanhunter2, ip: [10.1.112.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5004012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5004012"
  description  = "role: RITM0097099, ip: [10.123.12.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5004034" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5004034"
  description  = "role: RITM0097099, ip: [10.123.12.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5004076" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5004076"
  description  = "role: RITM0097099, ip: [10.123.12.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-155" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-155"
  description  = "role: pr-n-mgt_10-1-18-155, ip: [10.1.18.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-shoreditch01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-shoreditch01"
  description  = "role: pr-n-mgt_cxb41-0-shoreditch01, ip: [10.17.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-citywalk01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-citywalk01"
  description  = "role: pr-n-mgt_cxb41-0-citywalk01, ip: [10.17.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-citywalk02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-citywalk02"
  description  = "role: pr-n-mgt_cxb41-0-citywalk02, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-citywalk03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-citywalk03"
  description  = "role: pr-n-mgt_cxb41-0-citywalk03, ip: [10.1.86.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-stjohns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-stjohns01"
  description  = "role: pr-n-mgt_cxb41-0-stjohns01, ip: [10.1.22.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-stjohns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-stjohns02"
  description  = "role: pr-n-mgt_cxb41-0-stjohns02, ip: [10.1.74.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-stjohns03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-stjohns03"
  description  = "role: pr-n-mgt_cxb41-0-stjohns03, ip: [10.1.112.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-greenside01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-greenside01"
  description  = "role: pr-n-mgt_cxb41-0-greenside01, ip: [10.3.60.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.60.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-gibraltar01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-gibraltar01"
  description  = "role: pr-n-mgt_cxb41-0-gibraltar01, ip: [10.180.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-gibraltar02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-gibraltar02"
  description  = "role: pr-n-mgt_cxb41-0-gibraltar02, ip: [10.180.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-gibraltar03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-gibraltar03"
  description  = "role: pr-n-mgt_cxb41-0-gibraltar03, ip: [10.17.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-ra01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-ra01"
  description  = "role: pr-n-mgt_cxb41-0-ra01, ip: [192.168.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-ra02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-ra02"
  description  = "role: pr-n-mgt_cxb41-0-ra02, ip: [192.168.201.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-ra03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-ra03"
  description  = "role: pr-n-mgt_cxb41-0-ra03, ip: [192.168.3.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-tel-aviv-lan-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-tel-aviv-lan-nat"
  description  = "role: pr-n-mgt_cxb41-0-tel-aviv-lan-nat, ip: [10.51.48.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_shoreditch03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_shoreditch03"
  description  = "role: CHG0092029, ip: [10.1.144.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.144.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cxb41-0-stjohns04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cxb41-0-stjohns04"
  description  = "role: pr-n-mgt_cxb41-0-stjohns04, ip: [10.1.58.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_shoreditch01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_shoreditch01"
  description  = "role: pr-n-mgt_shoreditch01, ip: [10.17.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_citywalk01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_citywalk01"
  description  = "role: pr-n-mgt_citywalk01, ip: [10.17.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_citywalk02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_citywalk02"
  description  = "role: pr-n-mgt_citywalk02, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_citywalk03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_citywalk03"
  description  = "role: pr-n-mgt_citywalk03, ip: [10.1.86.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjohns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjohns01"
  description  = "role: pr-n-mgt_stjohns01, ip: [10.1.22.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjohns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjohns02"
  description  = "role: pr-n-mgt_stjohns02, ip: [10.1.74.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjohns03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjohns03"
  description  = "role: pr-n-mgt_stjohns03, ip: [10.1.112.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_greenside01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_greenside01"
  description  = "role: pr-n-mgt_greenside01, ip: [10.3.60.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.60.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibraltar01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibraltar01"
  description  = "role: pr-n-mgt_gibraltar01, ip: [10.180.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibraltar02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibraltar02"
  description  = "role: pr-n-mgt_gibraltar02, ip: [10.180.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibraltar03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibraltar03"
  description  = "role: pr-n-mgt_gibraltar03, ip: [10.17.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-vpn"
  description  = "role: pr-n-mgt_gib-vpn, ip: [192.168.200.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tel-aviv-lan-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tel-aviv-lan-nat"
  description  = "role: pr-n-mgt_tel-aviv-lan-nat, ip: [10.51.48.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brs-vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brs-vpn"
  description  = "role: pr-n-mgt_brs-vpn, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_citywalk78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_citywalk78"
  description  = "role: CHG0091835, ip: [10.1.78.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjohns79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjohns79"
  description  = "role: CHG0091835, ip: [10.1.79.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.79.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_net-10-1-30-0_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_net-10-1-30-0_24"
  description  = "role: pr-n-mgt_net-10-1-30-0_24, ip: [10.1.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb26"
  description  = "role: pr-n-mgt_sc1uxprnwb26, ip: [10.120.72.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.72.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb27"
  description  = "role: pr-n-mgt_sc1uxprnwb27, ip: [10.120.72.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.72.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb26mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb26mgmt"
  description  = "role: pr-n-mgt_sc1uxprnwb26mgmt, ip: [10.120.152.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb27mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb27mgmt"
  description  = "role: pr-n-mgt_sc1uxprnwb27mgmt, ip: [10.120.152.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb28"
  description  = "role: pr-n-mgt_sc1uxprnwb28, ip: [10.120.152.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-cx-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-cx-network"
  description  = "role: pr-n-mgt_scc-cx-network, ip: [10.121.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-cx-inv-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-cx-inv-network"
  description  = "role: pr-n-mgt_scc-cx-inv-network, ip: [10.122.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow_user_lan_tempoffice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow_user_lan_tempoffice"
  description  = "role: pr-n-mgt_krakow_user_lan_tempoffice, ip: [10.55.252.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.252.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-wifi-core" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-wifi-core"
  description  = "role: pr-n-mgt_krk-wifi-core, range: [10.55.224.2-10.55.224.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.2", "10.55.224.3", "10.55.224.4", "10.55.224.5", "10.55.224.6", "10.55.224.7", "10.55.224.8", "10.55.224.9", "10.55.224.10", "10.55.224.11", "10.55.224.12", "10.55.224.13", "10.55.224.14", "10.55.224.15", "10.55.224.16", "10.55.224.17", "10.55.224.18", "10.55.224.19", "10.55.224.20", "10.55.224.21", "10.55.224.22", "10.55.224.23", "10.55.224.24", "10.55.224.25", "10.55.224.26", "10.55.224.27", "10.55.224.28", "10.55.224.29", "10.55.224.30", "10.55.224.31", "10.55.224.32", "10.55.224.33", "10.55.224.34", "10.55.224.35", "10.55.224.36", "10.55.224.37", "10.55.224.38", "10.55.224.39", "10.55.224.40", "10.55.224.41", "10.55.224.42", "10.55.224.43", "10.55.224.44", "10.55.224.45", "10.55.224.46", "10.55.224.47", "10.55.224.48", "10.55.224.49", "10.55.224.50", "10.55.224.51", "10.55.224.52", "10.55.224.53", "10.55.224.54", "10.55.224.55", "10.55.224.56", "10.55.224.57", "10.55.224.58", "10.55.224.59", "10.55.224.60", "10.55.224.61", "10.55.224.62", "10.55.224.63", "10.55.224.64", "10.55.224.65", "10.55.224.66", "10.55.224.67", "10.55.224.68", "10.55.224.69", "10.55.224.70", "10.55.224.71", "10.55.224.72", "10.55.224.73", "10.55.224.74", "10.55.224.75", "10.55.224.76", "10.55.224.77", "10.55.224.78", "10.55.224.79", "10.55.224.80", "10.55.224.81", "10.55.224.82", "10.55.224.83", "10.55.224.84", "10.55.224.85", "10.55.224.86", "10.55.224.87", "10.55.224.88", "10.55.224.89", "10.55.224.90", "10.55.224.91", "10.55.224.92", "10.55.224.93", "10.55.224.94", "10.55.224.95", "10.55.224.96", "10.55.224.97", "10.55.224.98", "10.55.224.99", "10.55.224.100", "10.55.224.101", "10.55.224.102", "10.55.224.103", "10.55.224.104", "10.55.224.105", "10.55.224.106", "10.55.224.107", "10.55.224.108", "10.55.224.109", "10.55.224.110", "10.55.224.111", "10.55.224.112", "10.55.224.113", "10.55.224.114", "10.55.224.115", "10.55.224.116", "10.55.224.117", "10.55.224.118", "10.55.224.119", "10.55.224.120", "10.55.224.121", "10.55.224.122", "10.55.224.123", "10.55.224.124", "10.55.224.125", "10.55.224.126", "10.55.224.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alb-jiridokoupil" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alb-jiridokoupil"
  description  = "role: CHG0119343, ip: [10.1.58.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alb-nickabbott" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alb-nickabbott"
  description  = "role: CHG0119370, ip: [10.1.58.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alb-danferry" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alb-danferry"
  description  = "role: CHG0117628, ip: [10.1.58.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-maciejpiekos" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-maciejpiekos"
  description  = "role: CHG0119306, ip: [10.55.14.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk_wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk_wifi"
  description  = "role: RITM0093036, ip: [10.55.226.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_prdxjmp23hst001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_prdxjmp23hst001-prod-williamhill-plc"
  description  = "role: pr-n-mgt_prdxjmp23hst001-prod-williamhill-plc, ip: [10.120.151.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremg26-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremg26-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1uxpremg26-prod-williamhill-plc, ip: [10.120.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxpremg25-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxpremg25-prod-williamhill-plc"
  description  = "role: pr-n-mgt_brsuxpremg25-prod-williamhill-plc, ip: [10.210.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremg27-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremg27-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1uxpremg27-prod-williamhill-plc, ip: [10.120.163.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxpremg01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxpremg01-prod-williamhill-plc"
  description  = "role: pr-n-mgt_ld6uxpremg01-prod-williamhill-plc, ip: [10.112.11.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.11.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_labuxpremg01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_labuxpremg01-prod-williamhill-plc"
  description  = "role: pr-n-mgt_labuxpremg01-prod-williamhill-plc, ip: [10.61.11.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.11.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb03"
  description  = "role: CHG0020745, ip: [10.120.146.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb02"
  description  = "role: pr-n-mgt_sc1wnprgdb02, ip: [10.120.146.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb01a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb01a"
  description  = "role: pr-n-mgt_sc1wnprgdb01a, ip: [10.120.146.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-146-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-146-51"
  description  = "role: pr-n-mgt_10-120-146-51, ip: [10.120.146.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-146-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-146-52"
  description  = "role: pr-n-mgt_10-120-146-52, ip: [10.120.146.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-180-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-180-142"
  description  = "role: pr-n-mgt_10-120-180-142, ip: [10.120.180.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_cessql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cessql"
  description  = "role: pr-n-mgt_cessql, ip: [10.120.180.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredb01"
  description  = "role: pr-n-mgt_sc1wnpredb01, ip: [10.120.134.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprevo01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprevo01"
  description  = "role: pr-n-mgt_sc1wnprevo01, ip: [10.120.194.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb06"
  description  = "role: pr-n-mgt_sc1wnprgdb06, ip: [10.120.99.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprrto01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprrto01"
  description  = "role: pr-n-mgt_sc1wnprrto01, ip: [10.120.180.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprrto02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprrto02"
  description  = "role: pr-n-mgt_sc1wnprrto02, ip: [10.120.180.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb05"
  description  = "role: CHG0146032, ip: [10.120.99.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb05-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb05-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprgdb06-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprgdb06-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_corpservicessql-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_corpservicessql-prod-williamhill-plc"
  description  = "role: CHG0146032, ip: [10.120.99.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_corpservicessql-prod-williamhill-plc-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_corpservicessql-prod-williamhill-plc-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_corpservices-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_corpservices-prod-williamhill-plc"
  description  = "role: CHG0146032, ip: [10.120.99.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_corpservices-prod-williamhill-plc-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_corpservices-prod-williamhill-plc-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-garethnetto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-garethnetto"
  description  = "role: CHG0116423, ip: [10.180.21.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-nerysthomas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-nerysthomas"
  description  = "role: pr-n-mgt_who-nerysthomas, ip: [10.180.19.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-anthonykowaliw" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-anthonykowaliw"
  description  = "role: TASK0226806, ip: [10.1.71.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.71.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_raphael-sammut-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_raphael-sammut-pc1"
  description  = "role: ritm, ip: [10.40.10.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jan-paroan-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jan-paroan-pc1"
  description  = "role: RITM0128752, ip: [10.123.116.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.116.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn20a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn20a"
  description  = "role: pr-n-mgt_sc1wnpremn20a, ip: [10.120.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpromn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpromn001"
  description  = "role: chg0061618, ip: [10.120.163.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn15"
  description  = "role: CHG0067823, ip: [10.120.163.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn21a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn21a"
  description  = "role: pr-n-mgt_sc1wnpremn21a, ip: [10.120.163.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-solarwinds-netflow" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-solarwinds-netflow"
  description  = "role: pr-n-mgt_uk-sc1-solarwinds-netflow, ip: [10.120.163.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprbkms01"
  description  = "role: CHG0112231, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprbkms02"
  description  = "role: CHG0112231, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-93"
  description  = "role: pr-n-mgt_10-55-224-93, ip: [10.55.224.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ardenta-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ardenta-dr"
  description  = "role: CHG0115728, ip: [10.196.201.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.196.201.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ardenta-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ardenta-net"
  description  = "role: CHG0115728, ip: [10.195.201.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.201.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_orbis-live-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_orbis-live-dr"
  description  = "role: CHG0115728, ip: [10.193.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_orbis-live-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_orbis-live-net"
  description  = "role: CHG0115728, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-42"
  description  = "role: pr-n-mgt_10-55-12-42, ip: [10.55.12.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-43"
  description  = "role: pr-n-mgt_10-55-12-43, ip: [10.55.12.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-46"
  description  = "role: pr-n-mgt_10-55-12-46, ip: [10.55.12.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-47"
  description  = "role: pr-n-mgt_10-55-12-47, ip: [10.55.12.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-50"
  description  = "role: pr-n-mgt_10-55-12-50, ip: [10.55.12.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-42"
  description  = "role: pr-n-mgt_10-55-224-42, ip: [10.55.224.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-43"
  description  = "role: pr-n-mgt_10-55-224-43, ip: [10.55.224.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-46"
  description  = "role: pr-n-mgt_10-55-224-46, ip: [10.55.224.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-47"
  description  = "role: pr-n-mgt_10-55-224-47, ip: [10.55.224.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-50"
  description  = "role: pr-n-mgt_10-55-224-50, ip: [10.55.224.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj_danferry_ip_10-1-74-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj_danferry_ip_10-1-74-181"
  description  = "role: CHG0108079, ip: [10.1.74.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-samsonkarnikoti" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-samsonkarnikoti"
  description  = "role: pr-n-mgt_stj-samsonkarnikoti, ip: [10.1.58.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_retail-main-sonar-runner-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_retail-main-sonar-runner-1"
  description  = "role: CHG0125636, ip: [10.210.201.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.201.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-emmafletcher" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-emmafletcher"
  description  = "role: TASK0202903, ip: [10.1.56.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-hannahslinger" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-hannahslinger"
  description  = "role: pr-n-mgt_lsj-hannahslinger, ip: [10.1.56.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-0"
  description  = "role: CHG0119660, ip: [10.55.14.0]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.0"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-1"
  description  = "role: CHG0119660, ip: [10.55.14.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-10"
  description  = "role: CHG0119660, ip: [10.55.14.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-11"
  description  = "role: CHG0119660, ip: [10.55.14.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-12"
  description  = "role: CHG0119660, ip: [10.55.14.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-13"
  description  = "role: CHG0119660, ip: [10.55.14.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-14"
  description  = "role: CHG0119660, ip: [10.55.14.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-15"
  description  = "role: CHG0119660, ip: [10.55.14.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-16"
  description  = "role: CHG0119660, ip: [10.55.14.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-17"
  description  = "role: CHG0119660, ip: [10.55.14.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-2"
  description  = "role: CHG0119660, ip: [10.55.14.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-3"
  description  = "role: CHG0119660, ip: [10.55.14.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-4"
  description  = "role: CHG0119660, ip: [10.55.14.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-5"
  description  = "role: CHG0119660, ip: [10.55.14.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-6"
  description  = "role: CHG0119660, ip: [10.55.14.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-7"
  description  = "role: CHG0119660, ip: [10.55.14.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-8"
  description  = "role: CHG0119660, ip: [10.55.14.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-14-9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-14-9"
  description  = "role: CHG0119660, ip: [10.55.14.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-44"
  description  = "role: pr-n-mgt_10-55-12-44, ip: [10.55.12.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-12-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-12-99"
  description  = "role: pr-n-mgt_10-55-12-99, ip: [10.55.12.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-44"
  description  = "role: pr-n-mgt_10-55-224-44, ip: [10.55.224.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-224-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-224-99"
  description  = "role: pr-n-mgt_10-55-224-99, ip: [10.55.224.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brs-pr-citrix-vlan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brs-pr-citrix-vlan"
  description  = "role: pr-n-mgt_brs-pr-citrix-vlan, ip: [10.210.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-pr-citrix-vlan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-pr-citrix-vlan"
  description  = "role: pr-n-mgt_scc-pr-citrix-vlan, ip: [10.120.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wxprnwb31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wxprnwb31"
  description  = "role: pr-n-mgt_sc1wxprnwb31, ip: [10.120.145.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-145-32slash29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-145-32slash29"
  description  = "role: pr-n-mgt_10-120-145-32slash29, ip: [10.120.145.32/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.32/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc15"
  description  = "role: Group RODC, ip: [10.120.159.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc17"
  description  = "role: pr-n-mgt_sc1wnpredc17, ip: [10.120.159.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc15-fe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc15-fe"
  description  = "role: pr-n-mgt_sc1wnpredc15-fe, ip: [10.120.69.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-0-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-0-0s23"
  description  = "role: pr-n-mgt_aws-100-79-0-0s23, ip: [100.79.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-2-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-2-0s23"
  description  = "role: pr-n-mgt_aws-100-79-2-0s23, ip: [100.79.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-4-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-4-0s23"
  description  = "role: pr-n-mgt_aws-100-79-4-0s23, ip: [100.79.4.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.4.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-6-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-6-0s23"
  description  = "role: pr-n-mgt_aws-100-79-6-0s23, ip: [100.79.6.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.6.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-8-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-8-0s23"
  description  = "role: pr-n-mgt_aws-100-79-8-0s23, ip: [100.79.8.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.8.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-10-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-10-0s23"
  description  = "role: pr-n-mgt_aws-100-79-10-0s23, ip: [100.79.10.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.10.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-12-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-12-0s23"
  description  = "role: pr-n-mgt_aws-100-79-12-0s23, ip: [100.79.12.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.12.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-14-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-14-0s23"
  description  = "role: pr-n-mgt_aws-100-79-14-0s23, ip: [100.79.14.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.14.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-16-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-16-0s23"
  description  = "role: pr-n-mgt_aws-100-79-16-0s23, ip: [100.79.16.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.16.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-18-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-18-0s23"
  description  = "role: pr-n-mgt_aws-100-79-18-0s23, ip: [100.79.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-20-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-20-0s23"
  description  = "role: pr-n-mgt_aws-100-79-20-0s23, ip: [100.79.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-22-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-22-0s23"
  description  = "role: pr-n-mgt_aws-100-79-22-0s23, ip: [100.79.22.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.22.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-24-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-24-0s23"
  description  = "role: pr-n-mgt_aws-100-79-24-0s23, ip: [100.79.24.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.24.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-26-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-26-0s23"
  description  = "role: pr-n-mgt_aws-100-79-26-0s23, ip: [100.79.26.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.26.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-28-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-28-0s23"
  description  = "role: pr-n-mgt_aws-100-79-28-0s23, ip: [100.79.28.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.28.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-30-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-30-0s23"
  description  = "role: pr-n-mgt_aws-100-79-30-0s23, ip: [100.79.30.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.30.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-32-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-32-0s23"
  description  = "role: pr-n-mgt_aws-100-79-32-0s23, ip: [100.79.32.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.32.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-34-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-34-0s23"
  description  = "role: pr-n-mgt_aws-100-79-34-0s23, ip: [100.79.34.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.34.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-36-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-36-0s23"
  description  = "role: pr-n-mgt_aws-100-79-36-0s23, ip: [100.79.36.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.36.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-38-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-38-0s23"
  description  = "role: pr-n-mgt_aws-100-79-38-0s23, ip: [100.79.38.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.38.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-40-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-40-0s23"
  description  = "role: pr-n-mgt_aws-100-79-40-0s23, ip: [100.79.40.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.40.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-42-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-42-0s23"
  description  = "role: pr-n-mgt_aws-100-79-42-0s23, ip: [100.79.42.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.42.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-44-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-44-0s23"
  description  = "role: pr-n-mgt_aws-100-79-44-0s23, ip: [100.79.44.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.44.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-46-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-46-0s23"
  description  = "role: pr-n-mgt_aws-100-79-46-0s23, ip: [100.79.46.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.46.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-48-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-48-0s23"
  description  = "role: pr-n-mgt_aws-100-79-48-0s23, ip: [100.79.48.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.48.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-50-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-50-0s23"
  description  = "role: pr-n-mgt_aws-100-79-50-0s23, ip: [100.79.50.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.50.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-52-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-52-0s23"
  description  = "role: pr-n-mgt_aws-100-79-52-0s23, ip: [100.79.52.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.52.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-54-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-54-0s23"
  description  = "role: pr-n-mgt_aws-100-79-54-0s23, ip: [100.79.54.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.54.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-56-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-56-0s23"
  description  = "role: pr-n-mgt_aws-100-79-56-0s23, ip: [100.79.56.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.56.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-58-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-58-0s23"
  description  = "role: pr-n-mgt_aws-100-79-58-0s23, ip: [100.79.58.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.58.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-60-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-60-0s23"
  description  = "role: pr-n-mgt_aws-100-79-60-0s23, ip: [100.79.60.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.60.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-62-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-62-0s23"
  description  = "role: pr-n-mgt_aws-100-79-62-0s23, ip: [100.79.62.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.62.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-64-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-64-0s23"
  description  = "role: pr-n-mgt_aws-100-79-64-0s23, ip: [100.79.64.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.64.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-66-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-66-0s23"
  description  = "role: pr-n-mgt_aws-100-79-66-0s23, ip: [100.79.66.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.66.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-68-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-68-0s23"
  description  = "role: pr-n-mgt_aws-100-79-68-0s23, ip: [100.79.68.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.68.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-70-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-70-0s23"
  description  = "role: pr-n-mgt_aws-100-79-70-0s23, ip: [100.79.70.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.70.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-72-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-72-0s23"
  description  = "role: pr-n-mgt_aws-100-79-72-0s23, ip: [100.79.72.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.72.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-74-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-74-0s23"
  description  = "role: pr-n-mgt_aws-100-79-74-0s23, ip: [100.79.74.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.74.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-76-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-76-0s23"
  description  = "role: pr-n-mgt_aws-100-79-76-0s23, ip: [100.79.76.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.76.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-78-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-78-0s23"
  description  = "role: pr-n-mgt_aws-100-79-78-0s23, ip: [100.79.78.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.78.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-80-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-80-0s23"
  description  = "role: pr-n-mgt_aws-100-79-80-0s23, ip: [100.79.80.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.80.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-82-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-82-0s23"
  description  = "role: pr-n-mgt_aws-100-79-82-0s23, ip: [100.79.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-84-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-84-0s23"
  description  = "role: pr-n-mgt_aws-100-79-84-0s23, ip: [100.79.84.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.84.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-86-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-86-0s23"
  description  = "role: pr-n-mgt_aws-100-79-86-0s23, ip: [100.79.86.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.86.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-88-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-88-0s23"
  description  = "role: pr-n-mgt_aws-100-79-88-0s23, ip: [100.79.88.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.88.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-90-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-90-0s23"
  description  = "role: pr-n-mgt_aws-100-79-90-0s23, ip: [100.79.90.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.90.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-92-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-92-0s23"
  description  = "role: pr-n-mgt_aws-100-79-92-0s23, ip: [100.79.92.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.92.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-94-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-94-0s23"
  description  = "role: pr-n-mgt_aws-100-79-94-0s23, ip: [100.79.94.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.94.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-96-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-96-0s23"
  description  = "role: pr-n-mgt_aws-100-79-96-0s23, ip: [100.79.96.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.96.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-98-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-98-0s23"
  description  = "role: pr-n-mgt_aws-100-79-98-0s23, ip: [100.79.98.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.98.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-100-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-100-0s23"
  description  = "role: pr-n-mgt_aws-100-79-100-0s23, ip: [100.79.100.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.100.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-102-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-102-0s23"
  description  = "role: pr-n-mgt_aws-100-79-102-0s23, ip: [100.79.102.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.102.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-104-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-104-0s23"
  description  = "role: pr-n-mgt_aws-100-79-104-0s23, ip: [100.79.104.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.104.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-106-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-106-0s23"
  description  = "role: pr-n-mgt_aws-100-79-106-0s23, ip: [100.79.106.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.106.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-108-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-108-0s23"
  description  = "role: pr-n-mgt_aws-100-79-108-0s23, ip: [100.79.108.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.108.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-110-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-110-0s23"
  description  = "role: pr-n-mgt_aws-100-79-110-0s23, ip: [100.79.110.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.110.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-112-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-112-0s23"
  description  = "role: pr-n-mgt_aws-100-79-112-0s23, ip: [100.79.112.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.112.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-114-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-114-0s23"
  description  = "role: pr-n-mgt_aws-100-79-114-0s23, ip: [100.79.114.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.114.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-116-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-116-0s23"
  description  = "role: pr-n-mgt_aws-100-79-116-0s23, ip: [100.79.116.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.116.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-118-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-118-0s23"
  description  = "role: pr-n-mgt_aws-100-79-118-0s23, ip: [100.79.118.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.118.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-120-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-120-0s23"
  description  = "role: pr-n-mgt_aws-100-79-120-0s23, ip: [100.79.120.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.120.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-122-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-122-0s23"
  description  = "role: pr-n-mgt_aws-100-79-122-0s23, ip: [100.79.122.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.122.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-124-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-124-0s23"
  description  = "role: pr-n-mgt_aws-100-79-124-0s23, ip: [100.79.124.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.124.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-100-79-126-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-100-79-126-0s23"
  description  = "role: pr-n-mgt_aws-100-79-126-0s23, ip: [100.79.126.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.126.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-er01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-er01"
  description  = "role: pr-n-mgt_uk-sc1-er01, ip: [10.120.159.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-er02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-er02"
  description  = "role: pr-n-mgt_uk-sc1-er02, ip: [10.120.159.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-es01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-es01"
  description  = "role: pr-n-mgt_uk-sc1-es01, ip: [10.120.159.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-es02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-es02"
  description  = "role: pr-n-mgt_uk-sc1-es02, ip: [10.120.159.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-er-01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-er-01"
  description  = "role: CHG0132371, ip: [10.120.159.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-techservices-nonprod-vpc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-techservices-nonprod-vpc"
  description  = "role: pr-n-mgt_aws-techservices-nonprod-vpc, ip: [100.79.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_aws-techservices-prod-vpc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_aws-techservices-prod-vpc"
  description  = "role: pr-n-mgt_aws-techservices-prod-vpc, ip: [100.79.16.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.16.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-226" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-226"
  description  = "role: pr-n-mgt_10-1-18-226, ip: [10.1.18.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_manila-subnet-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_manila-subnet-1"
  description  = "role: pr-n-mgt_manila-subnet-1, ip: [10.123.10.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.10.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_manila-subnet-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_manila-subnet-2"
  description  = "role: pr-n-mgt_manila-subnet-2, ip: [10.123.12.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-aws-prod-vpc-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-aws-prod-vpc-1"
  description  = "role: pr-n-mgt_dm-aws-prod-vpc-1, ip: [100.76.16.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.16.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-aws-prod-vpc-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-aws-prod-vpc-2"
  description  = "role: pr-n-mgt_dm-aws-prod-vpc-2, ip: [100.76.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-aws-prod-vpc-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-aws-prod-vpc-3"
  description  = "role: pr-n-mgt_dm-aws-prod-vpc-3, ip: [100.76.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnppeiam01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnppeiam01"
  description  = "role: pr-n-mgt_ld6wnppeiam01, ip: [10.118.208.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.208.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpreiam01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpreiam01"
  description  = "role: pr-n-mgt_ld6wnpreiam01, ip: [10.118.208.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.208.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnppeiam01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnppeiam01"
  description  = "role: pr-n-mgt_sc1wnppeiam01, ip: [10.120.70.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpreiam01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpreiam01"
  description  = "role: pr-n-mgt_sc1wnpreiam01, ip: [10.120.70.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfawnpredc01"
  description  = "role: pr-n-mgt_bfawnpredc01, ip: [10.56.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswnpredc01"
  description  = "role: CHG0138309, ip: [10.210.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibwnpredc02"
  description  = "role: pr-n-mgt_gibwnpredc02, ip: [10.180.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibwnpredc03"
  description  = "role: pr-n-mgt_gibwnpredc03, ip: [10.180.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_irewnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_irewnprdc01"
  description  = "role: CHG0141790, ip: [100.72.225.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_irewnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_irewnprdc02"
  description  = "role: CHG0141790, ip: [100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_nvawnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nvawnprdc01"
  description  = "role: CHG0144834, ip: [100.97.1.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_nvawnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nvawnprdc02"
  description  = "role: CHG0144834, ip: [100.97.1.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krawnpredc01"
  description  = "role: pr-n-mgt_krawnpredc01, ip: [10.55.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krawnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krawnpredc02"
  description  = "role: pr-n-mgt_krawnpredc02, ip: [10.55.9.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpredc01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpredc01-new"
  description  = "role: CHG0141790, ip: [10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnpredc02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnpredc02-new"
  description  = "role: CHG0141790, ip: [10.19.2.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnlwnpredc02_ip_10-123-197-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnlwnpredc02_ip_10-123-197-11"
  description  = "role: pr-n-mgt_mnlwnpredc02_ip_10-123-197-11, ip: [10.123.197.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnlwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnlwnpredc03"
  description  = "role: pr-n-mgt_mnlwnpredc03, ip: [10.123.197.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc01"
  description  = "role: CHG0138309, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpredc02"
  description  = "role: CHG0138309, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sofwnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sofwnpredc01"
  description  = "role: pr-n-mgt_sofwnpredc01, ip: [10.53.98.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sofwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sofwnpredc02"
  description  = "role: pr-n-mgt_sofwnpredc02, ip: [10.53.98.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsapprcmg002-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsapprcmg002-group-williamhill-plc"
  description  = "role: CHG0142765, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_splunkdeployment-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_splunkdeployment-sc1-prod-williamhill-plc"
  description  = "role: CHG0142763, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-ise02-pre-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-ise02-pre-vmc"
  description  = "role: CHG0137261, ip: [10.120.194.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-brs-ise02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-brs-ise02"
  description  = "role: CHG0137261, ip: [10.210.194.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gi-mpl-ise01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gi-mpl-ise01"
  description  = "role: CHG0137261, ip: [10.180.194.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-ise02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-ise02"
  description  = "role: CHG0145266, ip: [10.120.192.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.112.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxprbkms03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxprbkms03"
  description  = "role: CHG0112231, ip: [10.112.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxprbkms04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxprbkms04"
  description  = "role: CHG0112231, ip: [10.112.46.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxprbkms01"
  description  = "role: CHG0112231, ip: [10.112.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxprbkms02"
  description  = "role: CHG0112231, ip: [10.112.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibuxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibuxprbkms01"
  description  = "role: CHG0112231, ip: [10.180.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibuxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibuxprbkms02"
  description  = "role: CHG0112231, ip: [10.180.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn003-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn003-prod-williamhill-plc"
  description  = "role: pr-n-mgt_sc1uxpremn003-prod-williamhill-plc, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpreap237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpreap237"
  description  = "role: pr-n-mgt_sc1uxpreap237, ip: [10.120.163.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpreap238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpreap238"
  description  = "role: pr-n-mgt_sc1uxpreap238, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpreap239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpreap239"
  description  = "role: pr-n-mgt_sc1uxpreap239, ip: [10.120.163.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpreap242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpreap242"
  description  = "role: pr-n-mgt_sc1uxpreap242, ip: [10.120.163.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxrdk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxrdk"
  description  = "role: pr-n-mgt_sc1uxrdk, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-121-5-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-121-5-0slash24"
  description  = "role: pr-n-mgt_10-121-5-0slash24, ip: [10.121.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-121-7-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-121-7-0slash24"
  description  = "role: pr-n-mgt_10-121-7-0slash24, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsux910"
  description  = "role: pr-n-mgt_brsux910, ip: [10.1.28.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibux910"
  description  = "role: pr-n-mgt_gibux910, ip: [10.180.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxpreds01"
  description  = "role: pr-n-mgt_ld6uxpreds01, ip: [10.112.12.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpreds01"
  description  = "role: pr-n-mgt_sc1uxpreds01, ip: [10.120.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost01"
  description  = "role: pr-n-mgt_emailhost01, ip: [10.120.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost02"
  description  = "role: pr-n-mgt_emailhost02, ip: [10.120.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost03"
  description  = "role: pr-n-mgt_emailhost03, ip: [10.210.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost04"
  description  = "role: pr-n-mgt_emailhost04, ip: [10.210.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost05"
  description  = "role: pr-n-mgt_emailhost05, ip: [10.180.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_emailhost06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_emailhost06"
  description  = "role: pr-n-mgt_emailhost06, ip: [10.180.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprcmn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprcmn001"
  description  = "role: pr-n-mgt_sc1uxprcmn001, ip: [10.120.163.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6predc01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6predc01-new"
  description  = "role: pr-n-mgt_ld6predc01-new, ip: [10.19.2.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6predc02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6predc02-new"
  description  = "role: pr-n-mgt_ld6predc02-new, ip: [10.19.2.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsns01"
  description  = "role: pr-n-mgt_brsns01, ip: [10.210.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsns02"
  description  = "role: pr-n-mgt_brsns02, ip: [10.210.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibns01"
  description  = "role: pr-n-mgt_gibns01, ip: [10.180.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gibns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gibns02"
  description  = "role: pr-n-mgt_gibns02, ip: [10.180.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sccns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sccns01"
  description  = "role: pr-n-mgt_sccns01, ip: [10.120.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sccns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sccns02"
  description  = "role: pr-n-mgt_sccns02, ip: [10.120.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6ns01"
  description  = "role: pr-n-mgt_ld6ns01, ip: [10.112.208.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6ns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6ns02"
  description  = "role: pr-n-mgt_ld6ns02, ip: [10.112.208.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-wsus"
  description  = "role: pr-n-mgt_stj-wsus, ip: [10.110.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-sm02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-sm02"
  description  = "role: pr-n-mgt_uk-sc1-sm02, ip: [10.120.163.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-wn-pre-mn15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-wn-pre-mn15"
  description  = "role: CHG0021037, ip: [10.120.163.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremn21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremn21"
  description  = "role: pr-n-mgt_sc1wnpremn21, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremg30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremg30"
  description  = "role: pr-n-mgt_sc1uxpremg30, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprein12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprein12"
  description  = "role: pr-n-mgt_sc1wnprein12, ip: [10.120.163.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_scc-mail" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-mail"
  description  = "role: pr-n-mgt_scc-mail, ip: [10.120.67.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxpremn65"
  description  = "role: CHG0079749, ip: [10.210.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brsuxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brsuxpremn66"
  description  = "role: CHG0079749, ip: [10.210.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn65"
  description  = "role: CHG0079749, ip: [10.120.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn66"
  description  = "role: CHG0079749, ip: [10.120.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ld6uxpremn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ld6uxpremn13"
  description  = "role: pr-n-mgt_ld6uxpremn13, ip: [10.112.12.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn74"
  description  = "role: CHG0067511, ip: [10.120.163.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_brswndremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_brswndremg002"
  description  = "role: pr-n-mgt_brswndremg002, ip: [10.210.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnpremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnpremg002"
  description  = "role: pr-n-mgt_sc1wnpremg002, ip: [10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1appresc02-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1appresc02-data"
  description  = "role: CHG0122435, ip: [10.120.163.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1appresc03-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1appresc03-data"
  description  = "role: CHG0122435, ip: [10.120.163.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wxprnwb32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wxprnwb32"
  description  = "role: pr-n-mgt_sc1wxprnwb32, ip: [10.120.145.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wxprnwb33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wxprnwb33"
  description  = "role: pr-n-mgt_sc1wxprnwb33, ip: [10.120.145.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wxprnwb34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wxprnwb34"
  description  = "role: pr-n-mgt_sc1wxprnwb34, ip: [10.120.145.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb35"
  description  = "role: pr-n-mgt_sc1uxprnwb35, ip: [10.120.145.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb36"
  description  = "role: pr-n-mgt_sc1uxprnwb36, ip: [10.120.145.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-brs-dns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-brs-dns"
  description  = "role: CHG0018025, ip: [10.210.193.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_uk-sc1-dns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_uk-sc1-dns"
  description  = "role: CHG0018398, ip: [10.120.193.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-120-149-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-120-149-52"
  description  = "role: pr-n-mgt_10-120-149-52, ip: [10.120.149.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap87"
  description  = "role: pr-n-mgt_sc1wnprnap87, ip: [10.120.149.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap88"
  description  = "role: pr-n-mgt_sc1wnprnap88, ip: [10.120.149.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc49"
  description  = "role: pr-n-mgt_sc1uxprntc49, ip: [10.120.153.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc50"
  description  = "role: pr-n-mgt_sc1uxprntc50, ip: [10.120.153.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnrk21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnrk21"
  description  = "role: pr-n-mgt_sc1uxprnrk21, ip: [10.120.153.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnrk22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnrk22"
  description  = "role: pr-n-mgt_sc1uxprnrk22, ip: [10.120.153.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnrk23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnrk23"
  description  = "role: pr-n-mgt_sc1uxprnrk23, ip: [10.120.153.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnrk24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnrk24"
  description  = "role: pr-n-mgt_sc1uxprnrk24, ip: [10.120.153.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnrk25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnrk25"
  description  = "role: pr-n-mgt_sc1uxprnrk25, ip: [10.120.153.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnmq31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnmq31"
  description  = "role: pr-n-mgt_sc1uxprnmq31, ip: [10.120.153.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnmq32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnmq32"
  description  = "role: pr-n-mgt_sc1uxprnmq32, ip: [10.120.153.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc41"
  description  = "role: pr-n-mgt_sc1uxprntc41, ip: [10.120.153.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc42"
  description  = "role: pr-n-mgt_sc1uxprntc42, ip: [10.120.153.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap53"
  description  = "role: pr-n-mgt_sc1wnprnap53, ip: [10.120.153.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1wnprnap54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1wnprnap54"
  description  = "role: pr-n-mgt_sc1wnprnap54, ip: [10.120.153.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc55"
  description  = "role: pr-n-mgt_sc1uxprntc55, ip: [10.120.153.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprntc56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprntc56"
  description  = "role: pr-n-mgt_sc1uxprntc56, ip: [10.120.153.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap101"
  description  = "role: pr-n-mgt_sc1uxprnap101, ip: [10.120.153.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-jayakumarperrikrishnaiah" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-jayakumarperrikrishnaiah"
  description  = "role: pr-n-mgt_dba-jayakumarperrikrishnaiah, ip: [10.1.82.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-keithbrailey" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-keithbrailey"
  description  = "role: pr-n-mgt_dba-keithbrailey, ip: [10.1.82.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-mattprice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-mattprice"
  description  = "role: pr-n-mgt_dba-mattprice, ip: [10.1.82.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-nickhowe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-nickhowe"
  description  = "role: pr-n-mgt_dba-nickhowe, ip: [10.1.82.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-oliverallan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-oliverallan"
  description  = "role: pr-n-mgt_dba-oliverallan, ip: [10.1.82.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-oliverallan2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-oliverallan2"
  description  = "role: pr-n-mgt_dba-oliverallan2, ip: [10.1.74.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-philhinchcliffe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-philhinchcliffe"
  description  = "role: pr-n-mgt_dba-philhinchcliffe, ip: [10.1.82.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-piotradamiak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-piotradamiak"
  description  = "role: pr-n-mgt_dba-piotradamiak, ip: [10.1.82.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-richardanthony" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-richardanthony"
  description  = "role: pr-n-mgt_dba-richardanthony, ip: [10.1.82.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-richardanthony2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-richardanthony2"
  description  = "role: pr-n-mgt_dba-richardanthony2, ip: [10.1.74.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-simoneaster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-simoneaster"
  description  = "role: pr-n-mgt_dba-simoneaster, ip: [10.17.8.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-simoneaster2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-simoneaster2"
  description  = "role: pr-n-mgt_dba-simoneaster2, ip: [10.180.18.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-simoneaster3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-simoneaster3"
  description  = "role: pr-n-mgt_dba-simoneaster3, ip: [10.17.8.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-simoneaster4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-simoneaster4"
  description  = "role: pr-n-mgt_dba-simoneaster4, ip: [10.180.19.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-stephenwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-stephenwood"
  description  = "role: pr-n-mgt_dba-stephenwood, ip: [10.1.82.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-tobyhenderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-tobyhenderson"
  description  = "role: pr-n-mgt_dba-tobyhenderson, ip: [10.1.82.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-tobyhenderson4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-tobyhenderson4"
  description  = "role: pr-n-mgt_dba-tobyhenderson4, ip: [10.1.74.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-amarbarot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-amarbarot"
  description  = "role: pr-n-mgt_dba-amarbarot, ip: [10.1.82.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-jamesgibson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-jamesgibson"
  description  = "role: pr-n-mgt_dba-jamesgibson, ip: [10.1.74.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adriansugden" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adriansugden"
  description  = "role: pr-n-mgt_who-adriansugden, ip: [10.1.82.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-gary-dennis-ip1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-gary-dennis-ip1"
  description  = "role: pr-n-mgt_dba-gary-dennis-ip1, ip: [10.1.82.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-gary-dennis-ip2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-gary-dennis-ip2"
  description  = "role: pr-n-mgt_dba-gary-dennis-ip2, ip: [10.1.70.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.70.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-keithbrailey" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-keithbrailey"
  description  = "role: CHG0033734, ip: [10.1.82.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mattprice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mattprice"
  description  = "role: CHG0033734, ip: [10.1.82.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-oliverallan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-oliverallan"
  description  = "role: CHG0033734, ip: [10.1.82.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-piotradamiak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-piotradamiak"
  description  = "role: CHG0033734, ip: [10.1.82.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simoneaster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simoneaster"
  description  = "role: CHG0033734, ip: [10.180.18.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.224"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simoneaster2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simoneaster2"
  description  = "role: CHG0033734, ip: [10.180.18.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simoneaster3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simoneaster3"
  description  = "role: CHG0033734, ip: [10.17.8.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-stephenwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-stephenwood"
  description  = "role: CHG0033734, ip: [10.1.82.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-tobyhenderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-tobyhenderson"
  description  = "role: CHG0033734, ip: [10.1.82.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-tobyhenderson2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-tobyhenderson2"
  description  = "role: CHG0033734, ip: [10.1.82.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-tobyhenderson3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-tobyhenderson3"
  description  = "role: CHG0033734, ip: [10.1.74.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-annaventuras" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-annaventuras"
  description  = "role: pr-n-mgt_who-annaventuras, ip: [10.180.21.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-fabrizioorsini" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-fabrizioorsini"
  description  = "role: pr-n-mgt_lcw-fabrizioorsini, ip: [10.1.82.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-nickyjones" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-nickyjones"
  description  = "role: pr-n-mgt_who-nickyjones, ip: [10.180.20.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-lev-ankudinov-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-lev-ankudinov-pc1"
  description  = "role: TASK0221382, ip: [10.55.13.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-lev-ankudinov-pc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-lev-ankudinov-pc2"
  description  = "role: TASK0221382, ip: [192.168.2.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-dimitrikosoy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-dimitrikosoy"
  description  = "role: pr-n-mgt_dba-dimitrikosoy, ip: [10.51.49.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-dimitrikosoy2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-dimitrikosoy2"
  description  = "role: pr-n-mgt_dba-dimitrikosoy2, ip: [10.51.49.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-ofiritzhaki" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-ofiritzhaki"
  description  = "role: pr-n-mgt_dba-ofiritzhaki, ip: [10.51.49.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dba-markpugh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dba-markpugh"
  description  = "role: pr-n-mgt_dba-markpugh, ip: [10.1.82.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vijaytumati" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vijaytumati"
  description  = "role: pr-n-mgt_vijaytumati, ip: [10.17.8.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vijaytumati2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vijaytumati2"
  description  = "role: pr-n-mgt_vijaytumati2, ip: [10.17.8.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vincenzodeconcilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vincenzodeconcilo"
  description  = "role: pr-n-mgt_vincenzodeconcilo, ip: [10.17.8.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mariaroytshenker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mariaroytshenker"
  description  = "role: pr-n-mgt_mariaroytshenker, ip: [10.51.48.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mansingh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mansingh"
  description  = "role: pr-n-mgt_who-mansingh, ip: [10.17.8.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardnoland" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardnoland"
  description  = "role: pr-n-mgt_who-richardnoland, ip: [10.17.8.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-markalderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-markalderson"
  description  = "role: pr-n-mgt_who-markalderson, ip: [10.17.8.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-roberttokarski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-roberttokarski"
  description  = "role: pr-n-mgt_who-roberttokarski, ip: [10.17.8.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marcfitzgerald" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marcfitzgerald"
  description  = "role: pr-n-mgt_who-marcfitzgerald, ip: [10.17.8.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-davidday" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-davidday"
  description  = "role: pr-n-mgt_who-davidday, ip: [10.17.8.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesgornell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesgornell"
  description  = "role: pr-n-mgt_who-jamesgornell, ip: [10.17.8.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-talvindersahota" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-talvindersahota"
  description  = "role: pr-n-mgt_who-talvindersahota, ip: [10.17.8.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simonthompson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simonthompson"
  description  = "role: pr-n-mgt_who-simonthompson, ip: [10.17.8.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilunderwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilunderwood"
  description  = "role: pr-n-mgt_who-neilunderwood, ip: [10.17.8.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-kevinbrownhill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-kevinbrownhill"
  description  = "role: pr-n-mgt_who-kevinbrownhill, ip: [10.17.8.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-shahzadrehman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-shahzadrehman"
  description  = "role: pr-n-mgt_who-shahzadrehman, ip: [10.17.8.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whoalexandraasulin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whoalexandraasulin"
  description  = "role: pr-n-mgt_whoalexandraasulin, ip: [10.51.51.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rossfleming" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rossfleming"
  description  = "role: pr-n-mgt_who-rossfleming, ip: [10.1.86.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jordanbrear" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jordanbrear"
  description  = "role: pr-n-mgt_who-jordanbrear, ip: [10.1.86.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mansingh2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mansingh2"
  description  = "role: CHG0092029, ip: [10.1.78.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-andrewknight" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-andrewknight"
  description  = "role: pr-n-mgt_who-andrewknight, ip: [10.17.8.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simonthompson2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simonthompson2"
  description  = "role: CHG0092029, ip: [10.1.78.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilunderwood2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilunderwood2"
  description  = "role: CHG0092029, ip: [10.1.78.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-kevinbrownhill2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-kevinbrownhill2"
  description  = "role: CHG0092029, ip: [10.1.78.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-talvindersahota2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-talvindersahota2"
  description  = "role: CHG0092029, ip: [10.1.78.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-vicenzodeconcilo2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-vicenzodeconcilo2"
  description  = "role: CHG0092029, ip: [10.1.78.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-roberttokarski2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-roberttokarski2"
  description  = "role: CHG0092029, ip: [10.1.78.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-davidday2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-davidday2"
  description  = "role: CHG0092029, ip: [10.1.78.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesgornall2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesgornall2"
  description  = "role: CHG0092029, ip: [10.1.78.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marcfitz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marcfitz"
  description  = "role: CHG0092029, ip: [10.1.78.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-vijaytumati2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-vijaytumati2"
  description  = "role: CHG0092029, ip: [10.1.78.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-andydavis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-andydavis"
  description  = "role: pr-n-mgt_who-andydavis, ip: [10.1.78.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mattlister" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mattlister"
  description  = "role: pr-n-mgt_who-mattlister, ip: [10.1.78.187]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.187"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-stuartconnor" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-stuartconnor"
  description  = "role: pr-n-mgt_who-stuartconnor, ip: [10.1.87.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mattspencernoble" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mattspencernoble"
  description  = "role: pr-n-mgt_who-mattspencernoble, ip: [10.1.86.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-markchrystyn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-markchrystyn"
  description  = "role: pr-n-mgt_usr-cwk-markchrystyn, ip: [10.1.82.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-colinpearson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-colinpearson"
  description  = "role: pr-n-mgt_who-colinpearson, ip: [10.1.86.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-briankitchen" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-briankitchen"
  description  = "role: pr-n-mgt_who-briankitchen, ip: [10.1.86.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-llandosnunez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-llandosnunez"
  description  = "role: pr-n-mgt_who-llandosnunez, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-llanosnunez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-llanosnunez"
  description  = "role: pr-n-mgt_who-llanosnunez, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-andrewdonachie" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-andrewdonachie"
  description  = "role: pr-n-mgt_lcw-andrewdonachie, ip: [10.1.82.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-chriswren" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-chriswren"
  description  = "role: pr-n-mgt_lcw-chriswren, ip: [10.1.82.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-chriswren2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-chriswren2"
  description  = "role: pr-n-mgt_lcw-chriswren2, ip: [10.1.82.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-danferry" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-danferry"
  description  = "role: pr-n-mgt_lcw-danferry, ip: [10.1.82.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-garethsephton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-garethsephton"
  description  = "role: pr-n-mgt_lcw-garethsephton, ip: [10.1.82.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-markpetrie" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-markpetrie"
  description  = "role: pr-n-mgt_lcw-markpetrie, ip: [10.1.82.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-ravisingh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-ravisingh"
  description  = "role: pr-n-mgt_lcw-ravisingh, ip: [10.1.83.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-richardhampshire" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-richardhampshire"
  description  = "role: pr-n-mgt_lcw-richardhampshire, ip: [10.1.82.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-richardscott" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-richardscott"
  description  = "role: pr-n-mgt_lcw-richardscott, ip: [10.1.82.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-roblewis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-roblewis"
  description  = "role: pr-n-mgt_lcw-roblewis, ip: [10.1.82.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-stevewilson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-stevewilson"
  description  = "role: pr-n-mgt_lcw-stevewilson, ip: [10.1.82.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-tomfield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-tomfield"
  description  = "role: pr-n-mgt_lcw-tomfield, ip: [10.1.82.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joncandlin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joncandlin"
  description  = "role: pr-n-mgt_who-joncandlin, ip: [10.1.74.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marcuscampbell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marcuscampbell"
  description  = "role: pr-n-mgt_who-marcuscampbell, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilbellamy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilbellamy"
  description  = "role: pr-n-mgt_who-neilbellamy, ip: [10.180.19.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilbellamy2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilbellamy2"
  description  = "role: pr-n-mgt_who-neilbellamy2, ip: [10.180.18.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-vpn-llanosnunez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-vpn-llanosnunez"
  description  = "role: pr-n-mgt_who-vpn-llanosnunez, ip: [192.168.200.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-vpn-neilbellamy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-vpn-neilbellamy"
  description  = "role: pr-n-mgt_who-vpn-neilbellamy, ip: [192.168.201.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alastairmontgomery" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alastairmontgomery"
  description  = "role: pr-n-mgt_who-alastairmontgomery, ip: [10.1.74.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-davidbarszczak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-davidbarszczak"
  description  = "role: pr-n-mgt_lcw-davidbarszczak, ip: [10.1.82.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-wpp-agalindo2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-wpp-agalindo2"
  description  = "role: pr-n-mgt_usr-wpp-agalindo2, ip: [10.180.20.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-wpp-agalindo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-wpp-agalindo"
  description  = "role: pr-n-mgt_usr-wpp-agalindo, ip: [10.180.20.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joseescanciano" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joseescanciano"
  description  = "role: pr-n-mgt_who-joseescanciano, ip: [10.180.19.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-patrickdiloreto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-patrickdiloreto"
  description  = "role: pr-n-mgt_who-patrickdiloreto, ip: [10.180.18.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesmoody" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesmoody"
  description  = "role: pr-n-mgt_who-jamesmoody, ip: [10.180.18.169]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.169"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-pedrogutirrez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-pedrogutirrez"
  description  = "role: pr-n-mgt_who-pedrogutirrez, ip: [10.180.18.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-miguelpoyatos" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-miguelpoyatos"
  description  = "role: pr-n-mgt_who-miguelpoyatos, ip: [10.180.19.217]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.217"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-petrutodoran" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-petrutodoran"
  description  = "role: pr-n-mgt_who-petrutodoran, ip: [10.180.18.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-istvanpapp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-istvanpapp"
  description  = "role: pr-n-mgt_who-istvanpapp, ip: [10.180.19.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-billpalfreman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-billpalfreman"
  description  = "role: pr-n-mgt_lcw-billpalfreman, ip: [10.1.74.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj_danferry_ip_10-1-74-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj_danferry_ip_10-1-74-25"
  description  = "role: pr-n-mgt_stj_danferry_ip_10-1-74-25, ip: [10.1.74.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_nickchrzanowski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nickchrzanowski"
  description  = "role: pr-n-mgt_nickchrzanowski, ip: [10.1.83.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_niklambev" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_niklambev"
  description  = "role: pr-n-mgt_niklambev, ip: [10.1.88.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.88.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_peterwaithe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_peterwaithe"
  description  = "role: pr-n-mgt_peterwaithe, ip: [10.180.18.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_piotrmozdzynski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_piotrmozdzynski"
  description  = "role: pr-n-mgt_piotrmozdzynski, ip: [10.180.19.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mauroarnoldi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mauroarnoldi"
  description  = "role: pr-n-mgt_who-mauroarnoldi, ip: [10.17.8.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_se_nathanflynn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_se_nathanflynn"
  description  = "role: pr-n-mgt_se_nathanflynn, ip: [10.1.74.119]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.119"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-alancatto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-alancatto"
  description  = "role: INC0401046, ip: [10.1.87.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-mauroarnoldi2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-mauroarnoldi2"
  description  = "role: CHG0092029, ip: [10.1.78.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-andrewglass" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-andrewglass"
  description  = "role: pr-n-mgt_stj-andrewglass, ip: [10.1.74.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-amarbarot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-amarbarot"
  description  = "role: pr-n-mgt_stj-amarbarot, ip: [10.1.74.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alanchristie-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alanchristie-sslvpn"
  description  = "role: pr-n-mgt_alanchristie-sslvpn, ip: [192.168.200.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jarrodsmithers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jarrodsmithers"
  description  = "role: pr-n-mgt_jarrodsmithers, ip: [10.1.83.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_doriangordon" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_doriangordon"
  description  = "role: pr-n-mgt_doriangordon, ip: [10.180.18.173]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.173"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_andrewthompson-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_andrewthompson-sslvpn"
  description  = "role: pr-n-mgt_andrewthompson-sslvpn, ip: [192.168.200.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-giladlandau" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-giladlandau"
  description  = "role: pr-n-mgt_tlv-giladlandau, ip: [10.51.48.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-gavinmarshall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-gavinmarshall"
  description  = "role: pr-n-mgt_who-gavinmarshall, ip: [10.1.87.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alanchristie-desktop" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alanchristie-desktop"
  description  = "role: pr-n-mgt_who-alanchristie-desktop, ip: [10.180.18.90]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.90"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alanchristie-laptop" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alanchristie-laptop"
  description  = "role: pr-n-mgt_who-alanchristie-laptop, ip: [10.180.18.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_andrewthompson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_andrewthompson"
  description  = "role: pr-n-mgt_andrewthompson, ip: [10.180.20.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-glyniswalsh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-glyniswalsh"
  description  = "role: pr-n-mgt_who-glyniswalsh, ip: [10.1.78.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-tester-rahulsogani" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-tester-rahulsogani"
  description  = "role: pr-n-mgt_dm-tester-rahulsogani, ip: [10.17.8.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-tester-grahamhoyle" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-tester-grahamhoyle"
  description  = "role: pr-n-mgt_dm-tester-grahamhoyle, ip: [10.17.8.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-tester-adeellis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-tester-adeellis"
  description  = "role: pr-n-mgt_dm-tester-adeellis, ip: [10.17.8.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_dm-tester-grahamhoyle-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dm-tester-grahamhoyle-sslvpn"
  description  = "role: pr-n-mgt_dm-tester-grahamhoyle-sslvpn, ip: [192.168.200.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-trimsejdiu" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-trimsejdiu"
  description  = "role: pr-n-mgt_who-trimsejdiu, ip: [10.17.8.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adeellisdesktop" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adeellisdesktop"
  description  = "role: pr-n-mgt_who-adeellisdesktop, ip: [10.17.8.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-grahamhoyle2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-grahamhoyle2"
  description  = "role: CHG0092029, ip: [10.1.78.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-trimsejdiu2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-trimsejdiu2"
  description  = "role: CHG0092029, ip: [10.1.78.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adeellis2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adeellis2"
  description  = "role: pr-n-mgt_who-adeellis2, ip: [10.1.78.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-philellis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-philellis"
  description  = "role: pr-n-mgt_who-philellis, ip: [10.1.87.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rahulsogani2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rahulsogani2"
  description  = "role: CHG0092029, ip: [10.1.78.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-aellis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-aellis"
  description  = "role: CHG0092029, ip: [10.1.78.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rameshkrishna" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rameshkrishna"
  description  = "role: INC0598880, ip: [10.1.78.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-deborahmoore" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-deborahmoore"
  description  = "role: pr-n-mgt_who-deborahmoore, ip: [10.1.86.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-soumyasamal" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-soumyasamal"
  description  = "role: pr-n-mgt_who-soumyasamal, ip: [10.1.78.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-satyabhat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-satyabhat"
  description  = "role: pr-n-mgt_who-satyabhat, ip: [10.1.86.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardshields" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardshields"
  description  = "role: pr-n-mgt_who-richardshields, ip: [10.1.78.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.170"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw_dorothy_hawley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw_dorothy_hawley"
  description  = "role: pr-n-mgt_lcw_dorothy_hawley, ip: [10.1.78.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-1-86-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-1-86-56"
  description  = "role: INC0762011, ip: [10.1.86.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bi-sarahhadley-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bi-sarahhadley-pc"
  description  = "role: pr-n-mgt_bi-sarahhadley-pc, ip: [10.180.18.188]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.188"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bi-woutervanzutphen-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bi-woutervanzutphen-pc"
  description  = "role: pr-n-mgt_bi-woutervanzutphen-pc, ip: [10.180.18.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-waynefield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-waynefield"
  description  = "role: pr-n-mgt_gib-waynefield, ip: [10.180.20.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-oamrbahaya" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-oamrbahaya"
  description  = "role: pr-n-mgt_who-oamrbahaya, ip: [10.180.21.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-waynefield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-waynefield"
  description  = "role: pr-n-mgt_who-waynefield, ip: [10.17.8.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-ayalawaiechman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-ayalawaiechman"
  description  = "role: pr-n-mgt_tlv-ayalawaiechman, ip: [10.51.50.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.50.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-78-155" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-78-155"
  description  = "role: CHG0092029, ip: [10.1.78.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-piotrsmolinski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-piotrsmolinski"
  description  = "role: pr-n-mgt_gib-piotrsmolinski, ip: [10.180.18.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_laurablancarte" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_laurablancarte"
  description  = "role: pr-n-mgt_laurablancarte, ip: [10.1.79.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.79.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-piotr-nurkowski-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-piotr-nurkowski-pc1"
  description  = "role: TASK0221378, ip: [10.55.15.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-piotr-nurkowski-pc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-piotr-nurkowski-pc2"
  description  = "role: TASK0221378, ip: [192.168.2.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_woutervanzutphen-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_woutervanzutphen-sslvpn"
  description  = "role: pr-n-mgt_woutervanzutphen-sslvpn, ip: [192.168.201.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sarahhadley-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sarahhadley-sslvpn"
  description  = "role: pr-n-mgt_sarahhadley-sslvpn, ip: [192.168.200.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tobiemuir" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tobiemuir"
  description  = "role: pr-n-mgt_tobiemuir, ip: [10.180.18.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bi-skyemartin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bi-skyemartin"
  description  = "role: pr-n-mgt_bi-skyemartin, ip: [10.180.18.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_waynefield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_waynefield"
  description  = "role: pr-n-mgt_waynefield, ip: [10.180.20.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_waynefield-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_waynefield-sslvpn"
  description  = "role: pr-n-mgt_waynefield-sslvpn, ip: [192.168.200.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_robertsadler" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_robertsadler"
  description  = "role: CHG0069501, ip: [10.180.21.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-natalijazvokelj" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-natalijazvokelj"
  description  = "role: pr-n-mgt_who-natalijazvokelj, ip: [10.180.21.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-omarbahaya" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-omarbahaya"
  description  = "role: pr-n-mgt_who-omarbahaya, ip: [10.180.21.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesmakepeace" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesmakepeace"
  description  = "role: pr-n-mgt_who-jamesmakepeace, ip: [10.1.66.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danieldodita" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danieldodita"
  description  = "role: pr-n-mgt_who-danieldodita, ip: [10.180.18.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-simongatenby" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-simongatenby"
  description  = "role: pr-n-mgt_gib-simongatenby, ip: [10.180.18.193]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.193"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-adamfrench" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-adamfrench"
  description  = "role: pr-n-mgt_gib-adamfrench, ip: [10.180.21.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-laurenwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-laurenwood"
  description  = "role: pr-n-mgt_gib-laurenwood, ip: [10.180.18.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rayforrester" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rayforrester"
  description  = "role: pr-n-mgt_who-rayforrester, ip: [10.180.18.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-adamkynastonsmith" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-adamkynastonsmith"
  description  = "role: pr-n-mgt_gib-adamkynastonsmith, ip: [10.180.18.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bg-wh5000589" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bg-wh5000589"
  description  = "role: pr-n-mgt_bg-wh5000589, ip: [10.53.32.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bg-wh5001302" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bg-wh5001302"
  description  = "role: pr-n-mgt_bg-wh5001302, ip: [10.53.32.119]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.119"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bg-wh5001303" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bg-wh5001303"
  description  = "role: pr-n-mgt_bg-wh5001303, ip: [10.53.32.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-idanbril" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-idanbril"
  description  = "role: pr-n-mgt_tlv-idanbril, ip: [10.51.48.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-marinashoyhedbrod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-marinashoyhedbrod"
  description  = "role: pr-n-mgt_tlv-marinashoyhedbrod, ip: [10.51.51.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-nat-mariaroytshenker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-nat-mariaroytshenker"
  description  = "role: pr-n-mgt_tlv-nat-mariaroytshenker, ip: [10.51.48.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-nat-rongrossman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-nat-rongrossman"
  description  = "role: pr-n-mgt_tlv-nat-rongrossman, ip: [10.51.51.163]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.163"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-revitalalon" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-revitalalon"
  description  = "role: pr-n-mgt_tlv-revitalalon, ip: [10.51.51.225]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.225"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-omridahan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-omridahan"
  description  = "role: pr-n-mgt_who-omridahan, ip: [10.51.50.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.50.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-oshratashkenazi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-oshratashkenazi"
  description  = "role: pr-n-mgt_who-oshratashkenazi, ip: [10.51.51.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-danieldodita" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-danieldodita"
  description  = "role: pr-n-mgt_lcw-danieldodita, ip: [10.17.8.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-oshratashkenazi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-oshratashkenazi"
  description  = "role: pr-n-mgt_tlv-oshratashkenazi, ip: [10.51.51.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-reutrefaeli" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-reutrefaeli"
  description  = "role: pr-n-mgt_tlv-reutrefaeli, ip: [10.51.50.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.50.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_tlv-yairelitzur" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tlv-yairelitzur"
  description  = "role: pr-n-mgt_tlv-yairelitzur, ip: [10.51.51.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.51.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-laurablancarte" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-laurablancarte"
  description  = "role: pr-n-mgt_who-laurablancarte, ip: [10.17.8.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-martinwray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-martinwray"
  description  = "role: pr-n-mgt_who-martinwray, ip: [10.180.18.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.170"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-martinwraysslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-martinwraysslvpn"
  description  = "role: pr-n-mgt_who-martinwraysslvpn, ip: [192.168.201.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-waynefield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-waynefield"
  description  = "role: pr-n-mgt_stj-waynefield, ip: [10.1.67.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.67.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-laurablancarte2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-laurablancarte2"
  description  = "role: CHG0092029, ip: [10.1.79.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.79.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_danieldodita-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_danieldodita-sslvpn"
  description  = "role: pr-n-mgt_danieldodita-sslvpn, ip: [192.168.201.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_fernandolago-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_fernandolago-sslvpn"
  description  = "role: pr-n-mgt_fernandolago-sslvpn, ip: [192.168.201.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_rayforrester-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_rayforrester-sslvpn"
  description  = "role: pr-n-mgt_rayforrester-sslvpn, ip: [192.168.201.187]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.187"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ssl-samfurby" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ssl-samfurby"
  description  = "role: pr-n-mgt_ssl-samfurby, ip: [192.168.201.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-laurablancarte" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-laurablancarte"
  description  = "role: pr-n-mgt_lsj-laurablancarte, ip: [10.1.113.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfa-marco-purgatori-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfa-marco-purgatori-pc"
  description  = "role: CHG0116277, ip: [10.56.12.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-angelosxypolias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-angelosxypolias"
  description  = "role: pr-n-mgt_who-angelosxypolias, ip: [10.180.19.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfa-kasrarostamkhany" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfa-kasrarostamkhany"
  description  = "role: TASK0198164, ip: [10.56.12.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.12.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-55-15-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-55-15-152"
  description  = "role: pr-n-mgt_host-10-55-15-152, ip: [10.55.15.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-boglarkabihari" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-boglarkabihari"
  description  = "role: TASK0217112, ip: [10.180.20.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-joaofardilha" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-joaofardilha"
  description  = "role: TASK0217403, ip: [10.180.19.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_slm-robertcamilleri" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_slm-robertcamilleri"
  description  = "role: TASK0219315, ip: [10.40.10.149]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.149"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-vasileiakouti" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-vasileiakouti"
  description  = "role: pr-n-mgt_gib-vasileiakouti, ip: [10.180.20.92]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.92"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-theodorospetanidis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-theodorospetanidis"
  description  = "role: pr-n-mgt_gib-theodorospetanidis, ip: [10.180.20.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mal-fabienefaty" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mal-fabienefaty"
  description  = "role: pr-n-mgt_mal-fabienefaty, ip: [10.40.10.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_man-marielalcoriza" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_man-marielalcoriza"
  description  = "role: pr-n-mgt_man-marielalcoriza, ip: [10.123.12.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap61"
  description  = "role: pr-n-mgt_sc1uxprnap61, ip: [10.120.146.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb41"
  description  = "role: pr-n-mgt_sc1uxprnwb41, ip: [10.120.145.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb42"
  description  = "role: pr-n-mgt_sc1uxprnwb42, ip: [10.120.145.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ssc1uxprnwb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ssc1uxprnwb05"
  description  = "role: pr-n-mgt_ssc1uxprnwb05, ip: [10.120.148.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ssc1uxprnwb06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ssc1uxprnwb06"
  description  = "role: pr-n-mgt_ssc1uxprnwb06, ip: [10.120.148.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb001"
  description  = "role: pr-n-mgt_sc1uxprnwb001, ip: [10.120.145.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnwb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnwb002"
  description  = "role: pr-n-mgt_sc1uxprnwb002, ip: [10.120.145.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ia_andygallagher" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ia_andygallagher"
  description  = "role: pr-n-mgt_ia_andygallagher, ip: [10.1.112.249]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.249"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ia_inplaymonitoringpc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ia_inplaymonitoringpc1"
  description  = "role: pr-n-mgt_ia_inplaymonitoringpc1, ip: [10.1.112.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ia_inplaymonitoringpc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ia_inplaymonitoringpc2"
  description  = "role: pr-n-mgt_ia_inplaymonitoringpc2, ip: [10.1.112.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ia_matthayman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ia_matthayman"
  description  = "role: pr-n-mgt_ia_matthayman, ip: [10.1.112.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_ia_vivekvattigunta" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ia_vivekvattigunta"
  description  = "role: pr-n-mgt_ia_vivekvattigunta, ip: [10.1.112.244]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.244"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-byrongalietta" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-byrongalietta"
  description  = "role: pr-n-mgt_stj-byrongalietta, ip: [10.1.112.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-varungundlapalli" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-varungundlapalli"
  description  = "role: pr-n-mgt_stj-varungundlapalli, ip: [10.1.112.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-asimibrahim" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-asimibrahim"
  description  = "role: pr-n-mgt_stj-asimibrahim, ip: [10.1.74.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-nicksimpson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-nicksimpson"
  description  = "role: pr-n-mgt_stj-nicksimpson, ip: [10.1.74.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb01"
  description  = "role: pr-n-mgt_sc1apprcwb01, ip: [10.120.131.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb02"
  description  = "role: pr-n-mgt_sc1apprcwb02, ip: [10.120.131.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb03"
  description  = "role: pr-n-mgt_sc1apprcwb03, ip: [10.120.131.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb04"
  description  = "role: pr-n-mgt_sc1apprcwb04, ip: [10.120.131.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb017" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb017"
  description  = "role: pr-n-mgt_sc1apprcwb017, ip: [10.120.131.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb005"
  description  = "role: pr-n-mgt_sc1apprcwb005, ip: [10.120.131.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb006"
  description  = "role: pr-n-mgt_sc1apprcwb006, ip: [10.120.131.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb007" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb007"
  description  = "role: pr-n-mgt_sc1apprcwb007, ip: [10.120.131.248]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.248"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb008" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb008"
  description  = "role: pr-n-mgt_sc1apprcwb008, ip: [10.120.131.249]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.249"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb009" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb009"
  description  = "role: pr-n-mgt_sc1apprcwb009, ip: [10.120.131.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb010" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb010"
  description  = "role: pr-n-mgt_sc1apprcwb010, ip: [10.120.131.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb011" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb011"
  description  = "role: pr-n-mgt_sc1apprcwb011, ip: [10.120.131.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb012"
  description  = "role: pr-n-mgt_sc1apprcwb012, ip: [10.120.131.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb013" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb013"
  description  = "role: pr-n-mgt_sc1apprcwb013, ip: [10.120.131.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb014" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb014"
  description  = "role: pr-n-mgt_sc1apprcwb014, ip: [10.120.131.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb016" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb016"
  description  = "role: pr-n-mgt_sc1apprcwb016, ip: [10.120.131.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb018" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb018"
  description  = "role: pr-n-mgt_sc1apprcwb018, ip: [10.120.131.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb019"
  description  = "role: pr-n-mgt_sc1apprcwb019, ip: [10.120.131.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb020" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb020"
  description  = "role: pr-n-mgt_sc1apprcwb020, ip: [10.120.131.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb021" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb021"
  description  = "role: pr-n-mgt_sc1apprcwb021, ip: [10.120.131.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb022" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb022"
  description  = "role: pr-n-mgt_sc1apprcwb022, ip: [10.120.131.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb023" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb023"
  description  = "role: pr-n-mgt_sc1apprcwb023, ip: [10.120.131.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1apprcwb024" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1apprcwb024"
  description  = "role: pr-n-mgt_sc1apprcwb024, ip: [10.120.131.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb95"
  description  = "role: pr-n-mgt_sc1uxprndb95, ip: [10.120.146.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprndb96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprndb96"
  description  = "role: pr-n-mgt_sc1uxprndb96, ip: [10.120.146.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap51"
  description  = "role: pr-n-mgt_sc1uxprnap51, ip: [10.120.147.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap52"
  description  = "role: pr-n-mgt_sc1uxprnap52, ip: [10.120.147.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap53"
  description  = "role: pr-n-mgt_sc1uxprnap53, ip: [10.120.147.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap54"
  description  = "role: pr-n-mgt_sc1uxprnap54, ip: [10.120.147.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap63"
  description  = "role: pr-n-mgt_sc1uxprnap63, ip: [10.120.147.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap64"
  description  = "role: pr-n-mgt_sc1uxprnap64, ip: [10.120.147.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap67"
  description  = "role: pr-n-mgt_sc1uxprnap67, ip: [10.120.147.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap68"
  description  = "role: pr-n-mgt_sc1uxprnap68, ip: [10.120.147.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxprnap55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxprnap55"
  description  = "role: chg0061618, ip: [10.120.145.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_birstall_bcp_dr_hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_birstall_bcp_dr_hosts"
  description  = "role: BCP Disaster Site in Birstall host IPs, ip: [10.1.21.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.21.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-daniellomax" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-daniellomax"
  description  = "role: pr-n-mgt_who-daniellomax, ip: [10.17.100.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jameskennedy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jameskennedy"
  description  = "role: pr-n-mgt_who-jameskennedy, ip: [10.17.100.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-kennicol" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-kennicol"
  description  = "role: pr-n-mgt_who-kennicol, ip: [10.17.100.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-martinlayfield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-martinlayfield"
  description  = "role: pr-n-mgt_who-martinlayfield, ip: [10.17.100.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-paulharrington" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-paulharrington"
  description  = "role: pr-n-mgt_who-paulharrington, ip: [10.17.100.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardfieldsend" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardfieldsend"
  description  = "role: pr-n-mgt_who-richardfieldsend, ip: [10.17.100.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.161"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-bryandianon" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-bryandianon"
  description  = "role: CHG0069950, ip: [10.123.13.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-iantalbot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-iantalbot"
  description  = "role: pr-n-mgt_who-iantalbot, ip: [10.180.20.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-luciaramos" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-luciaramos"
  description  = "role: pr-n-mgt_who-luciaramos, ip: [10.180.19.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adrianalonso" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adrianalonso"
  description  = "role: CHG0084605, ip: [10.180.18.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-markhowarth" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-markhowarth"
  description  = "role: pr-n-mgt_who-markhowarth, ip: [10.1.18.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-terrypattinson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-terrypattinson"
  description  = "role: pr-n-mgt_lsj-terrypattinson, ip: [10.1.18.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_client-mgmt-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_client-mgmt-1"
  description  = "role: CHG0083007, ip: [10.1.66.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_client-mgmt-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_client-mgmt-2"
  description  = "role: CHG0083007, ip: [10.1.66.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_client-mgmt-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_client-mgmt-3"
  description  = "role: CHG0083007, ip: [10.1.66.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_client-mgmt-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_client-mgmt-4"
  description  = "role: CHG0083210, ip: [10.1.66.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lsj-markswarbrick" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lsj-markswarbrick"
  description  = "role: pr-n-mgt_lsj-markswarbrick, ip: [10.1.113.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-iangoodin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-iangoodin"
  description  = "role: pr-n-mgt_who-iangoodin, ip: [10.180.19.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mariagrigorova" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mariagrigorova"
  description  = "role: pr-n-mgt_mariagrigorova, ip: [10.180.19.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_silviacecchia" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_silviacecchia"
  description  = "role: pr-n-mgt_silviacecchia, ip: [10.180.19.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stefanodelbeato" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stefanodelbeato"
  description  = "role: pr-n-mgt_stefanodelbeato, ip: [10.180.18.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-massimilianoprimatesta" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-massimilianoprimatesta"
  description  = "role: pr-n-mgt_who-massimilianoprimatesta, ip: [10.180.18.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-massimoscimmi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-massimoscimmi"
  description  = "role: pr-n-mgt_who-massimoscimmi, ip: [10.180.19.86]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.86"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfd-shinnosukekoda" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfd-shinnosukekoda"
  description  = "role: pr-n-mgt_bfd-shinnosukekoda, ip: [10.56.10.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bfd-yukiweston" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bfd-yukiweston"
  description  = "role: pr-n-mgt_bfd-yukiweston, ip: [10.56.10.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.10.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-ivanvera" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-ivanvera"
  description  = "role: pr-n-mgt_gib-ivanvera, ip: [10.180.19.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-lourdeslopez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-lourdeslopez"
  description  = "role: pr-n-mgt_gib-lourdeslopez, ip: [10.180.19.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-raquelperez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-raquelperez"
  description  = "role: pr-n-mgt_gib-raquelperez, ip: [10.180.18.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user1"
  description  = "role: CHG0126190, ip: [10.123.12.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user10"
  description  = "role: CHG0126190, ip: [10.123.12.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user11"
  description  = "role: CHG0126190, ip: [10.123.13.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user12"
  description  = "role: CHG0126190, ip: [10.123.13.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user13"
  description  = "role: CHG0126190, ip: [10.123.13.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user14"
  description  = "role: CHG0126190, ip: [10.123.13.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user2"
  description  = "role: CHG0126190, ip: [10.123.12.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user3"
  description  = "role: CHG0126190, ip: [10.123.12.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user4"
  description  = "role: CHG0126190, ip: [10.123.12.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user5"
  description  = "role: CHG0126190, ip: [10.123.12.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user6"
  description  = "role: CHG0126190, ip: [10.123.12.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user7"
  description  = "role: CHG0126190, ip: [10.123.12.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user8"
  description  = "role: CHG0126190, ip: [10.123.12.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user9"
  description  = "role: CHG0126190, ip: [10.123.12.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user15"
  description  = "role: pr-n-mgt_mnl-user15, ip: [10.123.13.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user16"
  description  = "role: pr-n-mgt_mnl-user16, ip: [10.123.12.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user17"
  description  = "role: pr-n-mgt_mnl-user17, ip: [10.123.12.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user18"
  description  = "role: pr-n-mgt_mnl-user18, ip: [10.123.12.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user19"
  description  = "role: pr-n-mgt_mnl-user19, ip: [10.123.12.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user20"
  description  = "role: pr-n-mgt_mnl-user20, ip: [10.123.13.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user21"
  description  = "role: pr-n-mgt_mnl-user21, ip: [10.123.13.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user22"
  description  = "role: pr-n-mgt_mnl-user22, ip: [10.123.12.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user23"
  description  = "role: pr-n-mgt_mnl-user23, ip: [10.123.12.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user24"
  description  = "role: pr-n-mgt_mnl-user24, ip: [10.123.12.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user25"
  description  = "role: pr-n-mgt_mnl-user25, ip: [10.123.12.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user26"
  description  = "role: pr-n-mgt_mnl-user26, ip: [10.123.13.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user27"
  description  = "role: pr-n-mgt_mnl-user27, ip: [10.123.12.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-user28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-user28"
  description  = "role: pr-n-mgt_mnl-user28, ip: [10.123.13.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adamwalker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adamwalker"
  description  = "role: pr-n-mgt_who-adamwalker, ip: [192.168.9.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-adamwalker1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-adamwalker1"
  description  = "role: pr-n-mgt_who-adamwalker1, ip: [10.180.19.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alanhunter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alanhunter"
  description  = "role: pr-n-mgt_who-alanhunter, ip: [10.1.66.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alanhunter1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alanhunter1"
  description  = "role: pr-n-mgt_who-alanhunter1, ip: [10.180.19.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-andylidbetter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-andylidbetter"
  description  = "role: pr-n-mgt_who-andylidbetter, ip: [10.180.18.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-antonioostios" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-antonioostios"
  description  = "role: pr-n-mgt_who-antonioostios, ip: [10.1.113.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danhall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danhall"
  description  = "role: pr-n-mgt_who-danhall, ip: [10.1.74.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-davidjones" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-davidjones"
  description  = "role: pr-n-mgt_who-davidjones, ip: [10.180.21.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-domhall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-domhall"
  description  = "role: pr-n-mgt_who-domhall, ip: [10.1.74.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-elviratrikova" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-elviratrikova"
  description  = "role: pr-n-mgt_who-elviratrikova, ip: [10.180.18.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ivayloivanov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ivayloivanov"
  description  = "role: pr-n-mgt_who-ivayloivanov, ip: [10.53.32.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesbromwell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesbromwell"
  description  = "role: pr-n-mgt_who-jamesbromwell, ip: [10.17.100.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jameskennedy1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jameskennedy1"
  description  = "role: pr-n-mgt_who-jameskennedy1, ip: [10.180.18.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-manusbonner" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-manusbonner"
  description  = "role: pr-n-mgt_who-manusbonner, ip: [10.17.100.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marcopinnisi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marcopinnisi"
  description  = "role: pr-n-mgt_who-marcopinnisi, ip: [10.180.19.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-michaelrichardson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-michaelrichardson"
  description  = "role: pr-n-mgt_who-michaelrichardson, ip: [10.17.100.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-monika" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-monika"
  description  = "role: pr-n-mgt_who-monika, ip: [10.180.18.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-stefanoscialanca" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-stefanoscialanca"
  description  = "role: pr-n-mgt_who-stefanoscialanca, ip: [10.180.27.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-stephenbrooker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-stephenbrooker"
  description  = "role: pr-n-mgt_who-stephenbrooker, ip: [10.180.19.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-adamchance" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-adamchance"
  description  = "role: CHG0089155, ip: [10.1.30.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-chrisjohnson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-chrisjohnson"
  description  = "role: TASK0175781, ip: [10.1.30.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-chrisohara" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-chrisohara"
  description  = "role: pr-n-mgt_stj-chrisohara, ip: [10.1.18.251]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.251"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-johnkaye" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-johnkaye"
  description  = "role: RITM0093681, ip: [10.1.74.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-leesheard" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-leesheard"
  description  = "role: CHG0071916, ip: [10.1.18.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-olivervickers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-olivervickers"
  description  = "role: TASK0193301, ip: [10.1.67.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.67.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-richardniland" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-richardniland"
  description  = "role: pr-n-mgt_stj-richardniland, ip: [10.1.66.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjmichaelnaughton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjmichaelnaughton"
  description  = "role: pr-n-mgt_stjmichaelnaughton, ip: [10.1.74.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj_nicholasshaw" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj_nicholasshaw"
  description  = "role: pr-n-mgt_stj_nicholasshaw, ip: [10.1.18.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-80"
  description  = "role: CHG0090943, ip: [10.1.113.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-82"
  description  = "role: pr-n-mgt_10-1-113-82, ip: [10.1.113.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-87"
  description  = "role: pr-n-mgt_10-1-113-87, ip: [10.1.113.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-54"
  description  = "role: pr-n-mgt_10-1-18-54, ip: [10.1.18.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-59"
  description  = "role: CHG0090943, ip: [10.1.66.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-67-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-67-213"
  description  = "role: CHG0090943, ip: [10.1.67.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.67.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-74-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-74-144"
  description  = "role: CHG0090943, ip: [10.1.74.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-74-75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-74-75"
  description  = "role: CHG0090943, ip: [10.1.74.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-227-243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-227-243"
  description  = "role: pr-n-mgt_10-53-227-243, ip: [10.53.227.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.227.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-32-217" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-32-217"
  description  = "role: pr-n-mgt_10-53-32-217, ip: [10.53.32.217]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.217"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-32-219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-32-219"
  description  = "role: pr-n-mgt_10-53-32-219, ip: [10.53.32.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-32-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-32-220"
  description  = "role: pr-n-mgt_10-53-32-220, ip: [10.53.32.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-32-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-32-47"
  description  = "role: pr-n-mgt_10-53-32-47, ip: [10.53.32.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-53-32-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-53-32-57"
  description  = "role: pr-n-mgt_10-53-32-57, ip: [10.53.32.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alanhunter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alanhunter"
  description  = "role: pr-n-mgt_alanhunter, ip: [10.1.18.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-alanhunter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-alanhunter"
  description  = "role: pr-n-mgt_gib-alanhunter, ip: [10.180.19.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-nicktrevett" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-nicktrevett"
  description  = "role: TASK0169407, ip: [10.1.180.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.180.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-robcoleman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-robcoleman"
  description  = "role: pr-n-mgt_gib-robcoleman, ip: [10.180.19.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-sherwinjarvand" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-sherwinjarvand"
  description  = "role: CHG0105415, ip: [10.180.19.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-tombedson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-tombedson"
  description  = "role: pr-n-mgt_gib-tombedson, ip: [10.180.19.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_man-tonykennerly" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_man-tonykennerly"
  description  = "role: pr-n-mgt_man-tonykennerly, ip: [10.123.13.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-kringmoran" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-kringmoran"
  description  = "role: pr-n-mgt_mnl-kringmoran, ip: [10.123.12.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-1-113-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-1-113-45"
  description  = "role: pr-n-mgt_host-10-1-113-45, ip: [10.1.113.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-1-113-55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-1-113-55"
  description  = "role: pr-n-mgt_host-10-1-113-55, ip: [10.1.113.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_host-10-1-18-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_host-10-1-18-83"
  description  = "role: pr-n-mgt_host-10-1-18-83, ip: [10.1.18.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-180-119-138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-180-119-138"
  description  = "role: TASK0200536, ip: [10.180.119.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.119.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-180-19-234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-180-19-234"
  description  = "role: TASK0208415, ip: [10.180.19.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjchristopherdack" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjchristopherdack"
  description  = "role: pr-n-mgt_stjchristopherdack, ip: [10.1.53.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.53.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-aldenaquino" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-aldenaquino"
  description  = "role: CHG0071116, ip: [10.123.12.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-desireesunga" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-desireesunga"
  description  = "role: CHG0071116, ip: [10.123.12.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-joanamarielerum" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-joanamarielerum"
  description  = "role: CHG0071116, ip: [10.123.12.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-maryanndeleon" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-maryanndeleon"
  description  = "role: CHG0071116, ip: [10.123.12.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-marygracedionisio" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-marygracedionisio"
  description  = "role: CHG0071116, ip: [10.123.12.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-myrielvaldivia" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-myrielvaldivia"
  description  = "role: CHG0071116, ip: [10.123.12.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_mnl-pearlyjao" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mnl-pearlyjao"
  description  = "role: CHG0071116, ip: [10.123.12.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-20"
  description  = "role: CHG0132256, ip: [10.123.12.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp019"
  description  = "role: CHG0082152, ip: [10.123.13.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp025" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp025"
  description  = "role: CHG0082152, ip: [10.123.13.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp045" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp045"
  description  = "role: CHG0082152, ip: [10.123.12.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp092" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp092"
  description  = "role: CHG0082152, ip: [10.123.12.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5001137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5001137"
  description  = "role: pr-n-mgt_wh5001137, ip: [10.123.12.192]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.192"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_wh5002720" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wh5002720"
  description  = "role: pr-n-mgt_wh5002720, ip: [10.123.13.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_whtemp076" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whtemp076"
  description  = "role: pr-n-mgt_whtemp076, ip: [10.123.13.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-172"
  description  = "role: pr-n-mgt_10-123-13-172, ip: [10.123.13.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-204"
  description  = "role: pr-n-mgt_10-123-13-204, ip: [10.123.13.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-224" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-224"
  description  = "role: pr-n-mgt_10-123-13-224, ip: [10.123.13.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.224"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-66"
  description  = "role: CHG0116429, ip: [10.1.30.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-67"
  description  = "role: CHG0116429, ip: [10.1.30.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-101"
  description  = "role: CHG0129506, ip: [10.123.12.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-106"
  description  = "role: CHG0129506, ip: [10.123.12.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-133" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-133"
  description  = "role: CHG0129506, ip: [10.123.12.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-5"
  description  = "role: CHG0129506, ip: [10.123.12.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-50"
  description  = "role: CHG0129506, ip: [10.123.12.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-12-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-12-93"
  description  = "role: CHG0129506, ip: [10.123.12.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.12.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-116"
  description  = "role: pr-n-mgt_10-123-13-116, ip: [10.123.13.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-142"
  description  = "role: pr-n-mgt_10-123-13-142, ip: [10.123.13.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-153" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-153"
  description  = "role: pr-n-mgt_10-123-13-153, ip: [10.123.13.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-26"
  description  = "role: pr-n-mgt_10-123-13-26, ip: [10.123.13.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-13-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-13-36"
  description  = "role: pr-n-mgt_10-123-13-36, ip: [10.123.13.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.13.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-140-59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-140-59"
  description  = "role: pr-n-mgt_10-123-140-59, ip: [10.123.140.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-140-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-140-81"
  description  = "role: pr-n-mgt_10-123-140-81, ip: [10.123.140.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-123-140-86" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-123-140-86"
  description  = "role: pr-n-mgt_10-123-140-86, ip: [10.123.140.86]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.86"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-1"
  description  = "role: CHG0139968, ip: [10.123.140.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-2"
  description  = "role: CHG0139968, ip: [10.123.140.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-3"
  description  = "role: CHG0139968, ip: [10.123.140.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-4"
  description  = "role: CHG0139968, ip: [10.123.140.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-5"
  description  = "role: CHG0139968, ip: [10.123.140.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_makati-trading-6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_makati-trading-6"
  description  = "role: CHG0139968, ip: [10.123.140.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.140.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-piotradamiak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-piotradamiak"
  description  = "role: pr-n-mgt_usr-cwk-piotradamiak, ip: [192.168.3.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-keithbrailey" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-keithbrailey"
  description  = "role: pr-n-mgt_usr-cwk-keithbrailey, ip: [10.1.82.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-keithbrailey_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-keithbrailey_vpn"
  description  = "role: pr-n-mgt_usr-cwk-keithbrailey_vpn, ip: [192.168.3.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-mattprice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-mattprice"
  description  = "role: pr-n-mgt_usr-cwk-mattprice, ip: [10.1.82.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-mattprice_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-mattprice_vpn"
  description  = "role: pr-n-mgt_usr-cwk-mattprice_vpn, ip: [192.168.3.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-nickhowe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-nickhowe"
  description  = "role: pr-n-mgt_usr-cwk-nickhowe, ip: [10.1.82.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-nickhowe_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-nickhowe_vpn"
  description  = "role: pr-n-mgt_usr-cwk-nickhowe_vpn, ip: [192.168.3.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_on_call_laptop_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_on_call_laptop_vpn"
  description  = "role: pr-n-mgt_on_call_laptop_vpn, ip: [192.168.3.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-jamesgibson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-jamesgibson"
  description  = "role: pr-n-mgt_usr-cwk-jamesgibson, ip: [10.1.74.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-jamesgibson_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-jamesgibson_vpn"
  description  = "role: pr-n-mgt_usr-cwk-jamesgibson_vpn, ip: [192.168.3.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-stephenwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-stephenwood"
  description  = "role: pr-n-mgt_usr-cwk-stephenwood, ip: [10.1.82.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-stephenwood_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-stephenwood_vpn"
  description  = "role: pr-n-mgt_usr-cwk-stephenwood_vpn, ip: [192.168.3.195]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.195"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-tobyhenderson_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-tobyhenderson_2"
  description  = "role: pr-n-mgt_usr-cwk-tobyhenderson_2, ip: [10.1.74.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-tobyhenderson_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-tobyhenderson_vpn"
  description  = "role: pr-n-mgt_usr-cwk-tobyhenderson_vpn, ip: [192.168.3.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-tobyhenderson_vpn_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-tobyhenderson_vpn_2"
  description  = "role: pr-n-mgt_usr-cwk-tobyhenderson_vpn_2, ip: [192.168.3.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-oliverallan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-oliverallan"
  description  = "role: pr-n-mgt_usr-cwk-oliverallan, ip: [10.1.82.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-oliverallan_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-oliverallan_2"
  description  = "role: pr-n-mgt_usr-cwk-oliverallan_2, ip: [10.1.74.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-oliverallan_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-oliverallan_vpn"
  description  = "role: pr-n-mgt_usr-cwk-oliverallan_vpn, ip: [192.168.3.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-jayakumarperrikrishnaiah" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-jayakumarperrikrishnaiah"
  description  = "role: pr-n-mgt_usr-cwk-jayakumarperrikrishnaiah, ip: [10.1.82.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-amarbarot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-amarbarot"
  description  = "role: pr-n-mgt_usr-cwk-amarbarot, ip: [10.1.82.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-piotradamiak_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-piotradamiak_vpn"
  description  = "role: pr-n-mgt_usr-cwk-piotradamiak_vpn, ip: [192.168.3.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_usr-cwk-amarbarot2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_usr-cwk-amarbarot2"
  description  = "role: CHG0071317, ip: [10.1.74.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_kotlarska_cloudteam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_kotlarska_cloudteam"
  description  = "role: pr-n-mgt_kotlarska_cloudteam, ip: [10.55.13.240/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.240/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_kotlarska_cloudteam-wireless" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_kotlarska_cloudteam-wireless"
  description  = "role: pr-n-mgt_kotlarska_cloudteam-wireless, ip: [10.55.225.240/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.240/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-stefangarczynski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-stefangarczynski"
  description  = "role: pr-n-mgt_lcw-stefangarczynski, ip: [10.1.82.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danmarsden" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danmarsden"
  description  = "role: pr-n-mgt_who-danmarsden, ip: [10.180.18.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesbarr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesbarr"
  description  = "role: pr-n-mgt_who-jamesbarr, ip: [10.180.18.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilbancroft-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilbancroft-sslvpn"
  description  = "role: pr-n-mgt_who-neilbancroft-sslvpn, ip: [192.168.200.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilmcdonald" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilmcdonald"
  description  = "role: pr-n-mgt_who-neilmcdonald, ip: [10.180.18.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilmcdonald-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilmcdonald-sslvpn"
  description  = "role: pr-n-mgt_who-neilmcdonald-sslvpn, ip: [192.168.200.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-robwalton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-robwalton"
  description  = "role: pr-n-mgt_who-robwalton, ip: [10.1.82.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simongatenby" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simongatenby"
  description  = "role: pr-n-mgt_who-simongatenby, ip: [10.180.21.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_il-webapptool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_il-webapptool"
  description  = "role: pr-n-mgt_il-webapptool, ip: [10.51.49.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-sarithammer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-sarithammer"
  description  = "role: pr-n-mgt_who-sarithammer, ip: [10.1.50.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.50.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bi-cristinapostolache-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bi-cristinapostolache-pc"
  description  = "role: pr-n-mgt_bi-cristinapostolache-pc, ip: [10.180.19.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_bi-cristinapostolache-sslvpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_bi-cristinapostolache-sslvpn"
  description  = "role: pr-n-mgt_bi-cristinapostolache-sslvpn, ip: [192.168.200.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_simoneaster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_simoneaster"
  description  = "role: pr-n-mgt_simoneaster, ip: [10.180.18.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-antoniomunoz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-antoniomunoz"
  description  = "role: pr-n-mgt_who-antoniomunoz, ip: [10.180.19.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-guisepperoma" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-guisepperoma"
  description  = "role: pr-n-mgt_who-guisepperoma, ip: [10.180.19.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-caroleherbert" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-caroleherbert"
  description  = "role: pr-n-mgt_who-caroleherbert, ip: [10.17.100.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-helenhanley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-helenhanley"
  description  = "role: pr-n-mgt_who-helenhanley, ip: [10.17.100.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-veronicalopezmonroy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-veronicalopezmonroy"
  description  = "role: pr-n-mgt_who-veronicalopezmonroy, ip: [10.17.100.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jameskelly" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jameskelly"
  description  = "role: pr-n-mgt_who-jameskelly, ip: [10.17.100.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ashleyheaton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ashleyheaton"
  description  = "role: pr-n-mgt_who-ashleyheaton, ip: [10.17.100.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-timlawrenson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-timlawrenson"
  description  = "role: pr-n-mgt_who-timlawrenson, ip: [10.17.100.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simonesswood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simonesswood"
  description  = "role: pr-n-mgt_who-simonesswood, ip: [10.17.100.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-janeslowey" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-janeslowey"
  description  = "role: pr-n-mgt_who-janeslowey, ip: [10.17.100.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.170"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-melanieenrile" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-melanieenrile"
  description  = "role: pr-n-mgt_who-melanieenrile, ip: [10.17.100.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rhiannongoodall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rhiannongoodall"
  description  = "role: pr-n-mgt_who-rhiannongoodall, ip: [10.17.100.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamessturdy_ip_10-17-100-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamessturdy_ip_10-17-100-69"
  description  = "role: pr-n-mgt_who-jamessturdy_ip_10-17-100-69, ip: [10.17.100.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-tanyafrancis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-tanyafrancis"
  description  = "role: pr-n-mgt_who-tanyafrancis, ip: [10.17.100.163]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.163"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardatkinson_ip_10-17-100-162" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardatkinson_ip_10-17-100-162"
  description  = "role: pr-n-mgt_who-richardatkinson_ip_10-17-100-162, ip: [10.17.100.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesstephenson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesstephenson"
  description  = "role: pr-n-mgt_who-jamesstephenson, ip: [10.17.100.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danieldavis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danieldavis"
  description  = "role: pr-n-mgt_who-danieldavis, ip: [10.17.100.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.175"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-omarbahayavpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-omarbahayavpn"
  description  = "role: pr-n-mgt_who-omarbahayavpn, ip: [192.168.200.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-stefanodelbeato" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-stefanodelbeato"
  description  = "role: pr-n-mgt_who-stefanodelbeato, ip: [10.180.18.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_remybarthomeuf" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_remybarthomeuf"
  description  = "role: pr-n-mgt_remybarthomeuf, ip: [10.180.19.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_alexrutherford" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_alexrutherford"
  description  = "role: pr-n-mgt_alexrutherford, ip: [10.180.20.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_chrispaye" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_chrispaye"
  description  = "role: pr-n-mgt_chrispaye, ip: [10.180.19.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_jonathanhoward" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_jonathanhoward"
  description  = "role: pr-n-mgt_jonathanhoward, ip: [10.180.21.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilbancroft_ip_192-168-10-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilbancroft_ip_192-168-10-24"
  description  = "role: pr-n-mgt_who-neilbancroft_ip_192-168-10-24, ip: [192.168.10.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.10.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-woutervanzutphenssl" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-woutervanzutphenssl"
  description  = "role: pr-n-mgt_who-woutervanzutphenssl, ip: [192.168.9.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jennabrown_ip_192-168-9-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jennabrown_ip_192-168-9-97"
  description  = "role: pr-n-mgt_who-jennabrown_ip_192-168-9-97, ip: [192.168.9.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-craigconnelly" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-craigconnelly"
  description  = "role: CHG0072309, ip: [10.17.8.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-richardatkinson_ip_10-180-21-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-richardatkinson_ip_10-180-21-39"
  description  = "role: pr-n-mgt_who-richardatkinson_ip_10-180-21-39, ip: [10.180.21.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-slawekmackowiak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-slawekmackowiak"
  description  = "role: pr-n-mgt_who-slawekmackowiak, ip: [10.180.21.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-dominichammond" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-dominichammond"
  description  = "role: pr-n-mgt_who-dominichammond, ip: [10.180.18.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-paulkozlowski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-paulkozlowski"
  description  = "role: pr-n-mgt_who-paulkozlowski, ip: [10.180.18.186]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.186"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-russellmottram" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-russellmottram"
  description  = "role: pr-n-mgt_who-russellmottram, ip: [10.180.18.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-valeriomiccio" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-valeriomiccio"
  description  = "role: pr-n-mgt_who-valeriomiccio, ip: [10.180.19.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-valeriomicciovpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-valeriomicciovpn"
  description  = "role: pr-n-mgt_who-valeriomicciovpn, ip: [192.168.200.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-ellaking" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-ellaking"
  description  = "role: pr-n-mgt_who-ellaking, ip: [10.180.19.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-benjones" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-benjones"
  description  = "role: pr-n-mgt_who-benjones, ip: [10.180.20.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-leostewart" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-leostewart"
  description  = "role: pr-n-mgt_who-leostewart, ip: [10.17.100.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-davidhill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-davidhill"
  description  = "role: pr-n-mgt_who-davidhill, ip: [10.180.19.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-simonkew" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-simonkew"
  description  = "role: pr-n-mgt_who-simonkew, ip: [10.180.19.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.224"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-michaeltaylor" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-michaeltaylor"
  description  = "role: pr-n-mgt_who-michaeltaylor, ip: [10.180.19.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-michailpalagkas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-michailpalagkas"
  description  = "role: pr-n-mgt_who-michailpalagkas, ip: [10.180.19.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-przemekkawa" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-przemekkawa"
  description  = "role: pr-n-mgt_who-przemekkawa, ip: [10.180.19.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-terryzhang" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-terryzhang"
  description  = "role: pr-n-mgt_who-terryzhang, ip: [10.180.19.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-vladimirslegkovskis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-vladimirslegkovskis"
  description  = "role: pr-n-mgt_who-vladimirslegkovskis, ip: [10.180.19.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-mohammedahmed" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-mohammedahmed"
  description  = "role: CHG0074403, ip: [10.1.83.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-simonpierce" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-simonpierce"
  description  = "role: CHG0074403, ip: [10.1.83.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-bernhardstorhas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-bernhardstorhas"
  description  = "role: pr-n-mgt_who-bernhardstorhas, ip: [10.180.19.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jennabrown1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jennabrown1"
  description  = "role: pr-n-mgt_who-jennabrown1, ip: [10.180.19.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jennabrown_ip_10-150-19-176" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jennabrown_ip_10-150-19-176"
  description  = "role: pr-n-mgt_who-jennabrown_ip_10-150-19-176, ip: [10.150.19.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.150.19.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-heatherfaulkner" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-heatherfaulkner"
  description  = "role: pr-n-mgt_who-heatherfaulkner, ip: [10.1.13.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-alvarogonzalez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-alvarogonzalez"
  description  = "role: pr-n-mgt_who-alvarogonzalez, ip: [192.168.200.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-marcosanta" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-marcosanta"
  description  = "role: pr-n-mgt_who-marcosanta, ip: [192.168.200.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-fabiomarchi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-fabiomarchi"
  description  = "role: pr-n-mgt_who-fabiomarchi, ip: [192.168.200.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.200.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rosefinan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rosefinan"
  description  = "role: pr-n-mgt_who-rosefinan, ip: [10.180.21.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danieldavies" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danieldavies"
  description  = "role: pr-n-mgt_who-danieldavies, ip: [10.17.100.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-neilbancroft_ip_192-168-9-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-neilbancroft_ip_192-168-9-143"
  description  = "role: pr-n-mgt_who-neilbancroft_ip_192-168-9-143, ip: [192.168.9.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.9.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-allyflynn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-allyflynn"
  description  = "role: pr-n-mgt_who-allyflynn, ip: [10.180.18.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-daleoldham" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-daleoldham"
  description  = "role: pr-n-mgt_who-daleoldham, ip: [10.180.27.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-sarahmcglue" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-sarahmcglue"
  description  = "role: pr-n-mgt_who-sarahmcglue, ip: [10.180.21.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-nicktrevett" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-nicktrevett"
  description  = "role: pr-n-mgt_who-nicktrevett, ip: [10.100.18.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.18.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joshuawalker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joshuawalker"
  description  = "role: CHG0078082, ip: [10.180.20.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamiecollings" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamiecollings"
  description  = "role: pr-n-mgt_who-jamiecollings, ip: [10.180.18.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joshroberts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joshroberts"
  description  = "role: pr-n-mgt_who-joshroberts, ip: [10.180.19.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-philmanwaring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-philmanwaring"
  description  = "role: pr-n-mgt_who-philmanwaring, ip: [10.180.19.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-christinabacani" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-christinabacani"
  description  = "role: pr-n-mgt_who-christinabacani, ip: [10.17.100.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-danmarsden2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-danmarsden2"
  description  = "role: pr-n-mgt_who-danmarsden2, ip: [10.17.100.90]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.90"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamesbarr2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamesbarr2"
  description  = "role: pr-n-mgt_who-jamesbarr2, ip: [10.17.100.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jamiecollings2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jamiecollings2"
  description  = "role: pr-n-mgt_who-jamiecollings2, ip: [10.17.100.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-jekynvilenna" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-jekynvilenna"
  description  = "role: pr-n-mgt_who-jekynvilenna, ip: [10.17.100.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-joshuawalker2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-joshuawalker2"
  description  = "role: pr-n-mgt_who-joshuawalker2, ip: [10.17.100.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-philmanwaring2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-philmanwaring2"
  description  = "role: pr-n-mgt_who-philmanwaring2, ip: [10.17.100.91]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.91"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_gib-andrewtowills" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_gib-andrewtowills"
  description  = "role: pr-n-mgt_gib-andrewtowills, ip: [10.180.20.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-callumjones" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-callumjones"
  description  = "role: pr-n-mgt_who-callumjones, ip: [10.180.19.252]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.252"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-markcheeswright" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-markcheeswright"
  description  = "role: pr-n-mgt_who-markcheeswright, ip: [10.180.21.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-susanasanchez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-susanasanchez"
  description  = "role: pr-n-mgt_who-susanasanchez, ip: [10.180.21.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-richardnolan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-richardnolan"
  description  = "role: CHG0082262, ip: [10.1.66.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-78-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-78-147"
  description  = "role: CHG0092029, ip: [10.1.78.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-paultait" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-paultait"
  description  = "role: pr-n-mgt_who-paultait, ip: [10.17.100.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_who-rachelpalmer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_who-rachelpalmer"
  description  = "role: pr-n-mgt_who-rachelpalmer, ip: [10.17.100.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lcw-peteredwards" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lcw-peteredwards"
  description  = "role: CHG0074403, ip: [10.1.82.91]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.91"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow-gaming-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow-gaming-wifi"
  description  = "role: pr-n-mgt_krakow-gaming-wifi, range: [10.55.226.128-10.55.226.255]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.128", "10.55.226.129", "10.55.226.130", "10.55.226.131", "10.55.226.132", "10.55.226.133", "10.55.226.134", "10.55.226.135", "10.55.226.136", "10.55.226.137", "10.55.226.138", "10.55.226.139", "10.55.226.140", "10.55.226.141", "10.55.226.142", "10.55.226.143", "10.55.226.144", "10.55.226.145", "10.55.226.146", "10.55.226.147", "10.55.226.148", "10.55.226.149", "10.55.226.150", "10.55.226.151", "10.55.226.152", "10.55.226.153", "10.55.226.154", "10.55.226.155", "10.55.226.156", "10.55.226.157", "10.55.226.158", "10.55.226.159", "10.55.226.160", "10.55.226.161", "10.55.226.162", "10.55.226.163", "10.55.226.164", "10.55.226.165", "10.55.226.166", "10.55.226.167", "10.55.226.168", "10.55.226.169", "10.55.226.170", "10.55.226.171", "10.55.226.172", "10.55.226.173", "10.55.226.174", "10.55.226.175", "10.55.226.176", "10.55.226.177", "10.55.226.178", "10.55.226.179", "10.55.226.180", "10.55.226.181", "10.55.226.182", "10.55.226.183", "10.55.226.184", "10.55.226.185", "10.55.226.186", "10.55.226.187", "10.55.226.188", "10.55.226.189", "10.55.226.190", "10.55.226.191", "10.55.226.192", "10.55.226.193", "10.55.226.194", "10.55.226.195", "10.55.226.196", "10.55.226.197", "10.55.226.198", "10.55.226.199", "10.55.226.200", "10.55.226.201", "10.55.226.202", "10.55.226.203", "10.55.226.204", "10.55.226.205", "10.55.226.206", "10.55.226.207", "10.55.226.208", "10.55.226.209", "10.55.226.210", "10.55.226.211", "10.55.226.212", "10.55.226.213", "10.55.226.214", "10.55.226.215", "10.55.226.216", "10.55.226.217", "10.55.226.218", "10.55.226.219", "10.55.226.220", "10.55.226.221", "10.55.226.222", "10.55.226.223", "10.55.226.224", "10.55.226.225", "10.55.226.226", "10.55.226.227", "10.55.226.228", "10.55.226.229", "10.55.226.230", "10.55.226.231", "10.55.226.232", "10.55.226.233", "10.55.226.234", "10.55.226.235", "10.55.226.236", "10.55.226.237", "10.55.226.238", "10.55.226.239", "10.55.226.240", "10.55.226.241", "10.55.226.242", "10.55.226.243", "10.55.226.244", "10.55.226.245", "10.55.226.246", "10.55.226.247", "10.55.226.248", "10.55.226.249", "10.55.226.250", "10.55.226.251", "10.55.226.252", "10.55.226.253", "10.55.226.254", "10.55.226.255"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow-gaming-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow-gaming-lan"
  description  = "role: pr-n-mgt_krakow-gaming-lan, range: [10.55.14.128-10.55.14.255]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.128", "10.55.14.129", "10.55.14.130", "10.55.14.131", "10.55.14.132", "10.55.14.133", "10.55.14.134", "10.55.14.135", "10.55.14.136", "10.55.14.137", "10.55.14.138", "10.55.14.139", "10.55.14.140", "10.55.14.141", "10.55.14.142", "10.55.14.143", "10.55.14.144", "10.55.14.145", "10.55.14.146", "10.55.14.147", "10.55.14.148", "10.55.14.149", "10.55.14.150", "10.55.14.151", "10.55.14.152", "10.55.14.153", "10.55.14.154", "10.55.14.155", "10.55.14.156", "10.55.14.157", "10.55.14.158", "10.55.14.159", "10.55.14.160", "10.55.14.161", "10.55.14.162", "10.55.14.163", "10.55.14.164", "10.55.14.165", "10.55.14.166", "10.55.14.167", "10.55.14.168", "10.55.14.169", "10.55.14.170", "10.55.14.171", "10.55.14.172", "10.55.14.173", "10.55.14.174", "10.55.14.175", "10.55.14.176", "10.55.14.177", "10.55.14.178", "10.55.14.179", "10.55.14.180", "10.55.14.181", "10.55.14.182", "10.55.14.183", "10.55.14.184", "10.55.14.185", "10.55.14.186", "10.55.14.187", "10.55.14.188", "10.55.14.189", "10.55.14.190", "10.55.14.191", "10.55.14.192", "10.55.14.193", "10.55.14.194", "10.55.14.195", "10.55.14.196", "10.55.14.197", "10.55.14.198", "10.55.14.199", "10.55.14.200", "10.55.14.201", "10.55.14.202", "10.55.14.203", "10.55.14.204", "10.55.14.205", "10.55.14.206", "10.55.14.207", "10.55.14.208", "10.55.14.209", "10.55.14.210", "10.55.14.211", "10.55.14.212", "10.55.14.213", "10.55.14.214", "10.55.14.215", "10.55.14.216", "10.55.14.217", "10.55.14.218", "10.55.14.219", "10.55.14.220", "10.55.14.221", "10.55.14.222", "10.55.14.223", "10.55.14.224", "10.55.14.225", "10.55.14.226", "10.55.14.227", "10.55.14.228", "10.55.14.229", "10.55.14.230", "10.55.14.231", "10.55.14.232", "10.55.14.233", "10.55.14.234", "10.55.14.235", "10.55.14.236", "10.55.14.237", "10.55.14.238", "10.55.14.239", "10.55.14.240", "10.55.14.241", "10.55.14.242", "10.55.14.243", "10.55.14.244", "10.55.14.245", "10.55.14.246", "10.55.14.247", "10.55.14.248", "10.55.14.249", "10.55.14.250", "10.55.14.251", "10.55.14.252", "10.55.14.253", "10.55.14.254", "10.55.14.255"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow-sports-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow-sports-lan"
  description  = "role: pr-n-mgt_krakow-sports-lan, ip: [10.55.15.64, 10.55.15.65, 10.55.15.66, 10.55.15.67, 10.55.15.68, 10.55.15.69, 10.55.15.70, 10.55.15.71, 10.55.15.72, 10.55.15.73, 10.55.15.74, 10.55.15.75, 10.55.15.76, 10.55.15.77, 10.55.15.78, 10.55.15.79, 10.55.15.80, 10.55.15.81, 10.55.15.82, 10.55.15.83, 10.55.15.84, 10.55.15.85, 10.55.15.86, 10.55.15.87, 10.55.15.88, 10.55.15.89, 10.55.15.90, 10.55.15.91, 10.55.15.92, 10.55.15.93, 10.55.15.94, 10.55.15.95, 10.55.15.96, 10.55.15.97, 10.55.15.98, 10.55.15.99, 10.55.15.100, 10.55.15.101, 10.55.15.102, 10.55.15.103, 10.55.15.104, 10.55.15.105, 10.55.15.106, 10.55.15.107, 10.55.15.108, 10.55.15.109, 10.55.15.110, 10.55.15.111, 10.55.15.112, 10.55.15.113, 10.55.15.114, 10.55.15.115, 10.55.15.116, 10.55.15.117, 10.55.15.118, 10.55.15.119, 10.55.15.120, 10.55.15.121, 10.55.15.122, 10.55.15.123, 10.55.15.124, 10.55.15.125, 10.55.15.126, 10.55.15.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.15.64", "10.55.15.65", "10.55.15.66", "10.55.15.67", "10.55.15.68", "10.55.15.69", "10.55.15.70", "10.55.15.71", "10.55.15.72", "10.55.15.73", "10.55.15.74", "10.55.15.75", "10.55.15.76", "10.55.15.77", "10.55.15.78", "10.55.15.79", "10.55.15.80", "10.55.15.81", "10.55.15.82", "10.55.15.83", "10.55.15.84", "10.55.15.85", "10.55.15.86", "10.55.15.87", "10.55.15.88", "10.55.15.89", "10.55.15.90", "10.55.15.91", "10.55.15.92", "10.55.15.93", "10.55.15.94", "10.55.15.95", "10.55.15.96", "10.55.15.97", "10.55.15.98", "10.55.15.99", "10.55.15.100", "10.55.15.101", "10.55.15.102", "10.55.15.103", "10.55.15.104", "10.55.15.105", "10.55.15.106", "10.55.15.107", "10.55.15.108", "10.55.15.109", "10.55.15.110", "10.55.15.111", "10.55.15.112", "10.55.15.113", "10.55.15.114", "10.55.15.115", "10.55.15.116", "10.55.15.117", "10.55.15.118", "10.55.15.119", "10.55.15.120", "10.55.15.121", "10.55.15.122", "10.55.15.123", "10.55.15.124", "10.55.15.125", "10.55.15.126", "10.55.15.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow-sports-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow-sports-wifi"
  description  = "role: pr-n-mgt_krakow-sports-wifi, ip: [10.55.227.64, 10.55.227.65, 10.55.227.66, 10.55.227.67, 10.55.227.68, 10.55.227.69, 10.55.227.70, 10.55.227.71, 10.55.227.72, 10.55.227.73, 10.55.227.74, 10.55.227.75, 10.55.227.76, 10.55.227.77, 10.55.227.78, 10.55.227.79, 10.55.227.80, 10.55.227.81, 10.55.227.82, 10.55.227.83, 10.55.227.84, 10.55.227.85, 10.55.227.86, 10.55.227.87, 10.55.227.88, 10.55.227.89, 10.55.227.90, 10.55.227.91, 10.55.227.92, 10.55.227.93, 10.55.227.94, 10.55.227.95, 10.55.227.96, 10.55.227.97, 10.55.227.98, 10.55.227.99, 10.55.227.100, 10.55.227.101, 10.55.227.102, 10.55.227.103, 10.55.227.104, 10.55.227.105, 10.55.227.106, 10.55.227.107, 10.55.227.108, 10.55.227.109, 10.55.227.110, 10.55.227.111, 10.55.227.112, 10.55.227.113, 10.55.227.114, 10.55.227.115, 10.55.227.116, 10.55.227.117, 10.55.227.118, 10.55.227.119, 10.55.227.120, 10.55.227.121, 10.55.227.122, 10.55.227.123, 10.55.227.124, 10.55.227.125, 10.55.227.126, 10.55.227.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.227.64", "10.55.227.65", "10.55.227.66", "10.55.227.67", "10.55.227.68", "10.55.227.69", "10.55.227.70", "10.55.227.71", "10.55.227.72", "10.55.227.73", "10.55.227.74", "10.55.227.75", "10.55.227.76", "10.55.227.77", "10.55.227.78", "10.55.227.79", "10.55.227.80", "10.55.227.81", "10.55.227.82", "10.55.227.83", "10.55.227.84", "10.55.227.85", "10.55.227.86", "10.55.227.87", "10.55.227.88", "10.55.227.89", "10.55.227.90", "10.55.227.91", "10.55.227.92", "10.55.227.93", "10.55.227.94", "10.55.227.95", "10.55.227.96", "10.55.227.97", "10.55.227.98", "10.55.227.99", "10.55.227.100", "10.55.227.101", "10.55.227.102", "10.55.227.103", "10.55.227.104", "10.55.227.105", "10.55.227.106", "10.55.227.107", "10.55.227.108", "10.55.227.109", "10.55.227.110", "10.55.227.111", "10.55.227.112", "10.55.227.113", "10.55.227.114", "10.55.227.115", "10.55.227.116", "10.55.227.117", "10.55.227.118", "10.55.227.119", "10.55.227.120", "10.55.227.121", "10.55.227.122", "10.55.227.123", "10.55.227.124", "10.55.227.125", "10.55.227.126", "10.55.227.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krakow_user_lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krakow_user_lan"
  description  = "role: pr-n-mgt_krakow_user_lan, ip: [10.55.0.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-wifi"
  description  = "role: pr-n-mgt_krk-wifi, ip: [10.55.224.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_krk-core" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_krk-core"
  description  = "role: pr-n-mgt_krk-core, range: [10.55.12.2-10.55.12.127]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.2", "10.55.12.3", "10.55.12.4", "10.55.12.5", "10.55.12.6", "10.55.12.7", "10.55.12.8", "10.55.12.9", "10.55.12.10", "10.55.12.11", "10.55.12.12", "10.55.12.13", "10.55.12.14", "10.55.12.15", "10.55.12.16", "10.55.12.17", "10.55.12.18", "10.55.12.19", "10.55.12.20", "10.55.12.21", "10.55.12.22", "10.55.12.23", "10.55.12.24", "10.55.12.25", "10.55.12.26", "10.55.12.27", "10.55.12.28", "10.55.12.29", "10.55.12.30", "10.55.12.31", "10.55.12.32", "10.55.12.33", "10.55.12.34", "10.55.12.35", "10.55.12.36", "10.55.12.37", "10.55.12.38", "10.55.12.39", "10.55.12.40", "10.55.12.41", "10.55.12.42", "10.55.12.43", "10.55.12.44", "10.55.12.45", "10.55.12.46", "10.55.12.47", "10.55.12.48", "10.55.12.49", "10.55.12.50", "10.55.12.51", "10.55.12.52", "10.55.12.53", "10.55.12.54", "10.55.12.55", "10.55.12.56", "10.55.12.57", "10.55.12.58", "10.55.12.59", "10.55.12.60", "10.55.12.61", "10.55.12.62", "10.55.12.63", "10.55.12.64", "10.55.12.65", "10.55.12.66", "10.55.12.67", "10.55.12.68", "10.55.12.69", "10.55.12.70", "10.55.12.71", "10.55.12.72", "10.55.12.73", "10.55.12.74", "10.55.12.75", "10.55.12.76", "10.55.12.77", "10.55.12.78", "10.55.12.79", "10.55.12.80", "10.55.12.81", "10.55.12.82", "10.55.12.83", "10.55.12.84", "10.55.12.85", "10.55.12.86", "10.55.12.87", "10.55.12.88", "10.55.12.89", "10.55.12.90", "10.55.12.91", "10.55.12.92", "10.55.12.93", "10.55.12.94", "10.55.12.95", "10.55.12.96", "10.55.12.97", "10.55.12.98", "10.55.12.99", "10.55.12.100", "10.55.12.101", "10.55.12.102", "10.55.12.103", "10.55.12.104", "10.55.12.105", "10.55.12.106", "10.55.12.107", "10.55.12.108", "10.55.12.109", "10.55.12.110", "10.55.12.111", "10.55.12.112", "10.55.12.113", "10.55.12.114", "10.55.12.115", "10.55.12.116", "10.55.12.117", "10.55.12.118", "10.55.12.119", "10.55.12.120", "10.55.12.121", "10.55.12.122", "10.55.12.123", "10.55.12.124", "10.55.12.125", "10.55.12.126", "10.55.12.127"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp-net-ardenta-vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp-net-ardenta-vpn"
  description  = "role: pr-n-mgt_grp-net-ardenta-vpn, ip: [172.17.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.17.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp-net-ardenta-vpn-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp-net-ardenta-vpn-dr"
  description  = "role: pr-n-mgt_grp-net-ardenta-vpn-dr, ip: [172.17.81.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.17.81.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-134"
  description  = "role: pr-n-mgt_10-1-56-134, ip: [10.1.56.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-160" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-160"
  description  = "role: pr-n-mgt_10-1-56-160, ip: [10.1.56.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.160"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-179"
  description  = "role: pr-n-mgt_10-1-56-179, ip: [10.1.56.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-226" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-226"
  description  = "role: pr-n-mgt_10-1-56-226, ip: [10.1.56.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-248" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-248"
  description  = "role: pr-n-mgt_10-1-56-248, ip: [10.1.56.248]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.248"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-56-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-56-8"
  description  = "role: pr-n-mgt_10-1-56-8, ip: [10.1.56.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.56.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-21"
  description  = "role: CHG0127893, ip: [10.55.226.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-22"
  description  = "role: CHG0127893, ip: [10.55.226.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-23"
  description  = "role: CHG0127893, ip: [10.55.226.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-24"
  description  = "role: CHG0127893, ip: [10.55.226.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-25"
  description  = "role: CHG0127893, ip: [10.55.226.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-26"
  description  = "role: CHG0127893, ip: [10.55.226.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-27"
  description  = "role: CHG0127893, ip: [10.55.226.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-28"
  description  = "role: CHG0127893, ip: [10.55.226.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-29"
  description  = "role: CHG0127893, ip: [10.55.226.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-30"
  description  = "role: CHG0127893, ip: [10.55.226.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-31"
  description  = "role: CHG0127893, ip: [10.55.226.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-55-226-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-55-226-32"
  description  = "role: CHG0127893, ip: [10.55.226.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_lan-krakow-inc-prb-rls-subnet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_lan-krakow-inc-prb-rls-subnet"
  description  = "role: CHG0127851, ip: [10.55.14.21, 10.55.14.22, 10.55.14.23, 10.55.14.24, 10.55.14.25, 10.55.14.26, 10.55.14.27, 10.55.14.28, 10.55.14.29, 10.55.14.30, 10.55.14.31, 10.55.14.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.21", "10.55.14.22", "10.55.14.23", "10.55.14.24", "10.55.14.25", "10.55.14.26", "10.55.14.27", "10.55.14.28", "10.55.14.29", "10.55.14.30", "10.55.14.31", "10.55.14.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vmc-retail-production-vsphere-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vmc-retail-production-vsphere-mgmt"
  description  = "role: pr-n-mgt_vmc-retail-production-vsphere-mgmt, ip: [10.126.32.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.32.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vmc-retail-production-10-233-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vmc-retail-production-10-233-0-0s24"
  description  = "role: pr-n-mgt_vmc-retail-production-10-233-0-0s24, ip: [10.233.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_vmc-retail-production-services-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_vmc-retail-production-services-mgmt"
  description  = "role: pr-n-mgt_vmc-retail-production-services-mgmt, ip: [10.156.1.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.1.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn105"
  description  = "role: pr-n-mgt_sc1uxpremn105, ip: [10.120.163.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn106"
  description  = "role: pr-n-mgt_sc1uxpremn106, ip: [10.120.163.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn107"
  description  = "role: pr-n-mgt_sc1uxpremn107, ip: [10.120.163.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn108"
  description  = "role: pr-n-mgt_sc1uxpremn108, ip: [10.120.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn120"
  description  = "role: pr-n-mgt_sc1uxpremn120, ip: [10.120.163.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_sc1uxpremn121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sc1uxpremn121"
  description  = "role: pr-n-mgt_sc1uxpremn121, ip: [10.120.163.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-124"
  description  = "role: pr-n-mgt_10-1-18-124, ip: [10.1.18.124]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.124"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-228" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-228"
  description  = "role: pr-n-mgt_10-1-18-228, ip: [10.1.18.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-28"
  description  = "role: pr-n-mgt_10-1-18-28, ip: [10.1.18.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-45"
  description  = "role: pr-n-mgt_10-1-66-45, ip: [10.1.66.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-159" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-159"
  description  = "role: pr-n-mgt_10-1-18-159, ip: [10.1.18.159]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.159"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-19"
  description  = "role: pr-n-mgt_10-1-18-19, ip: [10.1.18.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-69"
  description  = "role: pr-n-mgt_10-1-18-69, ip: [10.1.18.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-122"
  description  = "role: pr-n-mgt_10-1-13-122, ip: [10.1.13.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-150" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-150"
  description  = "role: pr-n-mgt_10-1-13-150, ip: [10.1.13.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-211"
  description  = "role: pr-n-mgt_10-1-13-211, ip: [10.1.13.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-216" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-216"
  description  = "role: pr-n-mgt_10-1-13-216, ip: [10.1.13.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-30"
  description  = "role: pr-n-mgt_10-1-13-30, ip: [10.1.13.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-54"
  description  = "role: pr-n-mgt_10-1-13-54, ip: [10.1.13.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-84"
  description  = "role: pr-n-mgt_10-1-13-84, ip: [10.1.13.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-13-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-13-98"
  description  = "role: pr-n-mgt_10-1-13-98, ip: [10.1.13.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-156" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-156"
  description  = "role: pr-n-mgt_10-1-18-156, ip: [10.1.18.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-203"
  description  = "role: pr-n-mgt_10-1-18-203, ip: [10.1.18.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-75"
  description  = "role: pr-n-mgt_10-1-18-75, ip: [10.1.18.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-154"
  description  = "role: pr-n-mgt_10-1-30-154, ip: [10.1.30.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-179"
  description  = "role: pr-n-mgt_10-1-30-179, ip: [10.1.30.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.179"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-194" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-194"
  description  = "role: pr-n-mgt_10-1-30-194, ip: [10.1.30.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-196" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-196"
  description  = "role: pr-n-mgt_10-1-30-196, ip: [10.1.30.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-246"
  description  = "role: pr-n-mgt_10-1-30-246, ip: [10.1.30.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-77"
  description  = "role: pr-n-mgt_10-1-30-77, ip: [10.1.30.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-80"
  description  = "role: pr-n-mgt_10-1-30-80, ip: [10.1.30.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-88"
  description  = "role: pr-n-mgt_10-1-30-88, ip: [10.1.30.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-94" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-94"
  description  = "role: pr-n-mgt_10-1-30-94, ip: [10.1.30.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-30-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-30-95"
  description  = "role: pr-n-mgt_10-1-30-95, ip: [10.1.30.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.30.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-33"
  description  = "role: pr-n-mgt_10-1-66-33, ip: [10.1.66.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-34"
  description  = "role: pr-n-mgt_10-1-66-34, ip: [10.1.66.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-58"
  description  = "role: pr-n-mgt_10-1-66-58, ip: [10.1.66.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-60" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-60"
  description  = "role: pr-n-mgt_10-1-66-60, ip: [10.1.66.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-137"
  description  = "role: pr-n-mgt_10-1-18-137, ip: [10.1.18.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-162" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-162"
  description  = "role: pr-n-mgt_10-1-18-162, ip: [10.1.18.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-17"
  description  = "role: pr-n-mgt_10-1-18-17, ip: [10.1.18.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-31"
  description  = "role: pr-n-mgt_10-1-18-31, ip: [10.1.18.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-66-63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-66-63"
  description  = "role: pr-n-mgt_10-1-66-63, ip: [10.1.66.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-107"
  description  = "role: pr-n-mgt_10-1-18-107, ip: [10.1.18.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-113"
  description  = "role: pr-n-mgt_10-1-18-113, ip: [10.1.18.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-114" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-114"
  description  = "role: pr-n-mgt_10-1-18-114, ip: [10.1.18.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-148"
  description  = "role: pr-n-mgt_10-1-18-148, ip: [10.1.18.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-15"
  description  = "role: pr-n-mgt_10-1-18-15, ip: [10.1.18.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-161" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-161"
  description  = "role: pr-n-mgt_10-1-18-161, ip: [10.1.18.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.161"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-164"
  description  = "role: pr-n-mgt_10-1-18-164, ip: [10.1.18.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-167" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-167"
  description  = "role: pr-n-mgt_10-1-18-167, ip: [10.1.18.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-219"
  description  = "role: pr-n-mgt_10-1-18-219, ip: [10.1.18.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-24"
  description  = "role: pr-n-mgt_10-1-18-24, ip: [10.1.18.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-25"
  description  = "role: pr-n-mgt_10-1-18-25, ip: [10.1.18.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-29"
  description  = "role: pr-n-mgt_10-1-18-29, ip: [10.1.18.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-51"
  description  = "role: pr-n-mgt_10-1-18-51, ip: [10.1.18.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-53"
  description  = "role: pr-n-mgt_10-1-18-53, ip: [10.1.18.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-76"
  description  = "role: pr-n-mgt_10-1-18-76, ip: [10.1.18.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-82"
  description  = "role: pr-n-mgt_10-1-18-82, ip: [10.1.18.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-112-237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-112-237"
  description  = "role: pr-n-mgt_10-1-112-237, ip: [10.1.112.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-75"
  description  = "role: pr-n-mgt_10-1-113-75, ip: [10.1.113.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-77"
  description  = "role: pr-n-mgt_10-1-113-77, ip: [10.1.113.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-78"
  description  = "role: pr-n-mgt_10-1-113-78, ip: [10.1.113.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-79"
  description  = "role: pr-n-mgt_10-1-113-79, ip: [10.1.113.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-113-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-113-81"
  description  = "role: pr-n-mgt_10-1-113-81, ip: [10.1.113.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.113.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stj-trading-randd-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stj-trading-randd-svr"
  description  = "role: pr-n-mgt_stj-trading-randd-svr, ip: [10.1.74.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjdancockerill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjdancockerill"
  description  = "role: pr-n-mgt_stjdancockerill, ip: [10.1.74.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjgustavljundqvist" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjgustavljundqvist"
  description  = "role: pr-n-mgt_stjgustavljundqvist, ip: [10.1.74.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjjamessmith" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjjamessmith"
  description  = "role: pr-n-mgt_stjjamessmith, ip: [10.1.74.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjliammosley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjliammosley"
  description  = "role: pr-n-mgt_stjliammosley, ip: [10.1.74.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjpoppywaterhouse" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjpoppywaterhouse"
  description  = "role: pr-n-mgt_stjpoppywaterhouse, ip: [10.1.74.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjantonioostios" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjantonioostios"
  description  = "role: pr-n-mgt_stjantonioostios, ip: [10.1.74.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_stjandystogdale" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stjandystogdale"
  description  = "role: pr-n-mgt_stjandystogdale, ip: [10.1.74.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-100"
  description  = "role: pr-n-mgt_10-1-18-100, ip: [10.1.18.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-139"
  description  = "role: pr-n-mgt_10-1-18-139, ip: [10.1.18.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-147"
  description  = "role: pr-n-mgt_10-1-18-147, ip: [10.1.18.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-166"
  description  = "role: pr-n-mgt_10-1-18-166, ip: [10.1.18.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-190" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-190"
  description  = "role: pr-n-mgt_10-1-18-190, ip: [10.1.18.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.190"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-193" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-193"
  description  = "role: pr-n-mgt_10-1-18-193, ip: [10.1.18.193]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.193"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-198" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-198"
  description  = "role: pr-n-mgt_10-1-18-198, ip: [10.1.18.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-208" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-208"
  description  = "role: pr-n-mgt_10-1-18-208, ip: [10.1.18.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-215" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-215"
  description  = "role: pr-n-mgt_10-1-18-215, ip: [10.1.18.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-223" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-223"
  description  = "role: pr-n-mgt_10-1-18-223, ip: [10.1.18.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-242"
  description  = "role: pr-n-mgt_10-1-18-242, ip: [10.1.18.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-48"
  description  = "role: pr-n-mgt_10-1-18-48, ip: [10.1.18.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-50"
  description  = "role: pr-n-mgt_10-1-18-50, ip: [10.1.18.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-66"
  description  = "role: pr-n-mgt_10-1-18-66, ip: [10.1.18.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-1-18-74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-1-18-74"
  description  = "role: pr-n-mgt_10-1-18-74, ip: [10.1.18.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-3-1-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-3-1-81"
  description  = "role: pr-n-mgt_10-3-1-81, ip: [10.3.1.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_10-3-1-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_10-3-1-83"
  description  = "role: pr-n-mgt_10-3-1-83, ip: [10.3.1.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.1.83"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_238"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_238"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1-cx-ncde-nets.path, nsxt_policy_group.pr-n-mgt_sc1-inv-noncde-nets.path, nsxt_policy_group.pr-n-mgt_bpl-ctl.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wh-ntp-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wh-ntp-servers"
  description  = "role: CHG0067823"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-210-193-235.path, nsxt_policy_group.pr-n-mgt_ip_10-210-193-236.path, nsxt_policy_group.pr-n-mgt_ip_10-180-193-235.path, nsxt_policy_group.pr-n-mgt_ip_10-180-193-236.path, nsxt_policy_group.pr-n-mgt_ip_10-120-193-235.path, nsxt_policy_group.pr-n-mgt_ip_10-120-193-236.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_pr-cde-stingray-dest-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_pr-cde-stingray-dest-nets"
  description  = "role: CHG0071650"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_net-pr-cde-api-integration.path, nsxt_policy_group.pr-n-mgt_net-pr-cde-lan01.path, nsxt_policy_group.pr-n-mgt_net-pr-cde-internal-presentation.path, nsxt_policy_group.pr-n-mgt_inv-cde-int-pres-lan.path, nsxt_policy_group.pr-n-mgt_inv-cde-api-lan.path, nsxt_policy_group.pr-n-mgt_inv-cde-lan01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-sc1-bomgar-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-sc1-bomgar-appliances"
  description  = "role: CHG0114418"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1apprcsc50-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1apprcsc51-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1jump-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-syslog-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-syslog-svrs"
  description  = "role: CHG0114077"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsuxpremn002-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_brsuxpremn003-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn002-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-rsa-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-rsa-svrs"
  description  = "role: CHG0114581"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gibappresc20-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1appresc20-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_brsapdresc20-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-non-cde-jump" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-non-cde-jump"
  description  = "role: CHG0120024"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_prdxjmp28jmp001-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_group-shop-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_group-shop-network"
  description  = "role: CHG0120024"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-93-0-0_16.path, nsxt_policy_group.pr-n-mgt_10-94-0-0_16.path, nsxt_policy_group.pr-n-mgt_10-96-0-0_16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_47"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_47"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-44-25.path, nsxt_policy_group.pr-n-mgt_ip_10-120-44-26.path, nsxt_policy_group.pr-n-mgt_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-ldap" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-ldap"
  description  = "role: CHG0017824, CHG0024307"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-1-28-4.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-20s32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_122"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1apprnwb91.path, nsxt_policy_group.pr-n-mgt_grp_push-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_93"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_93"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-proofpoint.path, nsxt_policy_group.pr-n-mgt_stj-proofpoint.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_hp-irs-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_hp-irs-server"
  description  = "role: pr-n-mgt_grp_hp-irs-server"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpremn01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-ad-dc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-ad-dc"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpresc03.path, nsxt_policy_group.pr-n-mgt_sc1wnpresc04.path, nsxt_policy_group.pr-n-mgt_grp_grp-pr-c-ad-child.path, nsxt_policy_group.pr-n-mgt_grp_grp-pr-c-ad-parent.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_oracle-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_oracle-db-servers"
  description  = "role: CHG0075769"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb01.path, nsxt_policy_group.pr-n-mgt_sc1uxprgdb05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-redhat-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-redhat-servers"
  description  = "role: CHG0051845"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap43.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trs_db_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trs_db_servers"
  description  = "role: pr-n-mgt_grp_trs_db_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprrdb04.path, nsxt_policy_group.pr-n-mgt_sc1uxprrdb05.path, nsxt_policy_group.pr-n-mgt_trs_vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_185"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_185"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-200-4-246.path, nsxt_policy_group.pr-n-mgt_ip_10-201-9-247.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_qlickview_app_mgt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_qlickview_app_mgt"
  description  = "role: pr-n-mgt_grp_qlickview_app_mgt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-53.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-54.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_spin2win-sql-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_spin2win-sql-svrs"
  description  = "role: pr-n-mgt_grp_spin2win-sql-svrs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb037.path, nsxt_policy_group.pr-n-mgt_sc1wnprgap02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sc1uxprndb037-38_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sc1uxprndb037-38_ilo"
  description  = "role: pr-n-mgt_grp_sc1uxprndb037-38_ilo"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb037_ilo.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb038_ilo.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_commvault-backup-networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_commvault-backup-networks"
  description  = "role: pr-n-mgt_grp_commvault-backup-networks"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gib-corp-tier.path, nsxt_policy_group.pr-n-mgt_gib-ncde-db-tier.path, nsxt_policy_group.pr-n-mgt_gib-ncde-mgmt-tier.path, nsxt_policy_group.pr-n-mgt_sc1-cde-frontend-hdr-tier.path, nsxt_policy_group.pr-n-mgt_sc1-ncde-app-tier.path, nsxt_policy_group.pr-n-mgt_sc1-ncde-frontend-ods-tier.path, nsxt_policy_group.pr-n-mgt_sc1-ncde-mgmt-tier.path, nsxt_policy_group.pr-n-mgt_sc1-retail-mgmt-tier.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-trading-oracle-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-trading-oracle-cluster"
  description  = "role: CHG0112168"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprodb001.path, nsxt_policy_group.pr-n-mgt_sc1uxprodb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-enc-ilo-nodes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-enc-ilo-nodes"
  description  = "role: CHG0112168"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprodb001_ilo.path, nsxt_policy_group.pr-n-mgt_sc1uxprodb002_ilo.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_124"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_124"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprrdb04.path, nsxt_policy_group.pr-n-mgt_sc1uxprrdb05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_126" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_126"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_126"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsm7001.path, nsxt_policy_group.pr-n-mgt_sccm7001.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_147"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_147"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb05.path, nsxt_policy_group.pr-n-mgt_grp_oracle-db-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_154"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_154"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb05.path, nsxt_policy_group.pr-n-mgt_sc1uxprodb001.path, nsxt_policy_group.pr-n-mgt_sc1uxprodb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_117" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_117"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_117"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-148-36.path, nsxt_policy_group.pr-n-mgt_ip_10-120-148-37.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_118"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_118"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ad-dc.path, nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-dns.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_171"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_171"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gsh-cheque-troy-printer.path, nsxt_policy_group.pr-n-mgt_stj-cheque-troy-printer.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc_mrr_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc_mrr_db"
  description  = "role: pr-n-mgt_grp_scc_mrr_db"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprndb51.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb52.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_voip-infrastructure" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_voip-infrastructure"
  description  = "role: CHG0146120"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1acprgcp01.path, nsxt_policy_group.pr-n-mgt_sc1acprgcp01-vmc.path, nsxt_policy_group.pr-n-mgt_sc1acprgcp01-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprcucm01.path, nsxt_policy_group.pr-n-mgt_sc1uxprcucm01-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo03.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo03-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo04.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo04-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnvgprgin06.path, nsxt_policy_group.pr-n-mgt_sc1wnvgprgin06-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprgcj01.path, nsxt_policy_group.pr-n-mgt_sc1uxprgcj01-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo01.path, nsxt_policy_group.pr-n-mgt_sc1apprevo01-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo02.path, nsxt_policy_group.pr-n-mgt_sc1apprevo02-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo03.path, nsxt_policy_group.pr-n-mgt_sc1apprevo03-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo04.path, nsxt_policy_group.pr-n-mgt_sc1apprevo04-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo05.path, nsxt_policy_group.pr-n-mgt_sc1apprevo05-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo07.path, nsxt_policy_group.pr-n-mgt_sc1apprevo07-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo08.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo08-aci.path, nsxt_policy_group.pr-n-mgt_ireuxprevo01.path, nsxt_policy_group.pr-n-mgt_ireuxprevo01-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip-vmc.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06-vmc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_116"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_116"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-149-36.path, nsxt_policy_group.pr-n-mgt_ip_10-120-149-37.path, nsxt_policy_group.pr-n-mgt_ip_10-120-149-60.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_92"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_92"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_w7d-dbjump.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb81.path, nsxt_policy_group.pr-n-mgt_grp_mrr-servers-db.path, nsxt_policy_group.pr-n-mgt_grp_tableau-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_82"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_82"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_ad-controllers.path, nsxt_policy_group.pr-n-mgt_grp_scc-ad-controllers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ods-ad-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ods-ad-servers"
  description  = "role: pr-n-mgt_grp_ods-ad-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb004.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb005_ip_10-120-149-27.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb006_ip_10-120-149-28.path, nsxt_policy_group.pr-n-mgt_sc1wnprnap003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ad-controllers-brs-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ad-controllers-brs-scc"
  description  = "role: pr-n-mgt_grp_ad-controllers-brs-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-n-mgt_brswnpredc03_ip_10-210-194-13.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc08_ip_10-120-194-18.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-dpe-prod-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-dpe-prod-servers"
  description  = "role: pr-n-mgt_grp_data-mgt-dpe-prod-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb004.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb005_ip_10-120-149-27.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb006_ip_10-120-149-28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-dpe-dr-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-dpe-dr-servers"
  description  = "role: pr-n-mgt_grp_data-mgt-dpe-dr-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brswndrndb003.path, nsxt_policy_group.pr-n-mgt_brswndrndb004.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_78"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_78"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_new-sc1wnprefs03-group-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1wnprefs03-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_172"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_172"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_cf_api_app_server.path, nsxt_policy_group.pr-n-mgt_grp_riak_app_servers.path, nsxt_policy_group.pr-n-mgt_grp_rabbit_mq_server.path, nsxt_policy_group.pr-n-mgt_grp_tennis_creation_service.path, nsxt_policy_group.pr-n-mgt_grp_tennis_pricing_app_servers.path, nsxt_policy_group.pr-n-mgt_grp_nevadaadapter-servers.path, nsxt_policy_group.pr-n-mgt_grp_grp-gtp-fred-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-nap-wily" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-nap-wily"
  description  = "role: pr-n-mgt_grp_grp-pr-nap-wily"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-120-163-36.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-31.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-32.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-33.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-34.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-scc-spin-mgt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-scc-spin-mgt"
  description  = "role: pr-n-mgt_grp_grp-scc-spin-mgt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-153-79.path, nsxt_policy_group.pr-n-mgt_ip_10-120-153-80.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_market-services-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_market-services-server"
  description  = "role: pr-n-mgt_grp_market-services-server"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprntc57-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1uxprntc58-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_220"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_220"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_market-services-server.path, nsxt_policy_group.pr-n-mgt_grp_nevadaadapter-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_231" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_231"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnmq35.path, nsxt_policy_group.pr-n-mgt_sc1uxprnmq36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-wily" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-wily"
  description  = "role: pr-n-mgt_grp_grp-wily"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn10.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn11.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn12.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn13.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-idam-sftp-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-idam-sftp-access"
  description  = "role: CHG0142650"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_adp-host-170-146-243-252.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net10.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net7.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net8.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net9.path, nsxt_policy_group.pr-n-mgt_ext-adp_sftp_access_host1.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_host1.path, nsxt_policy_group.pr-n-mgt_ext-clearmile_sftp_access_host1.path, nsxt_policy_group.pr-n-mgt_ext-evolution_sftp_access_host1.path, nsxt_policy_group.pr-n-mgt_ext-successfactors_sftp_access_host1.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net1.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net2.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net3.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net4.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net5.path, nsxt_policy_group.pr-n-mgt_ext-avature_sftp_access_net6.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_54"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_54"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb05.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb05_06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_168" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_168"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_168"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_dba-team.path, nsxt_policy_group.pr-n-mgt_grp_dba_group.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_169" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_169"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_169"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb12.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb13.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb14.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb15.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb16.path, nsxt_policy_group.pr-n-mgt_sc1uxprgdb01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sailpoint-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sailpoint-group"
  description  = "role: CHG0140307"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_va-1183.path, nsxt_policy_group.pr-n-mgt_va-2930.path, nsxt_policy_group.pr-n-mgt_va-2931.path, nsxt_policy_group.pr-n-mgt_va-2947.path, nsxt_policy_group.pr-n-mgt_va-2949.path, nsxt_policy_group.pr-n-mgt_va-3615.path, nsxt_policy_group.pr-n-mgt_va-986.path, nsxt_policy_group.pr-n-mgt_va-987.path, nsxt_policy_group.pr-n-mgt_va-990.path, nsxt_policy_group.pr-n-mgt_va-991.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_9"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_9"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap71.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap73.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb12.path, nsxt_policy_group.pr-n-mgt_ip_10-120-148-11.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_177" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_177"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_177"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_ob-internal-backoffice-web.path, nsxt_policy_group.pr-n-mgt_grp_ob-appservers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_201"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_201"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_who-monika-newbound.path, nsxt_policy_group.pr-n-mgt_who-neilwright.path, nsxt_policy_group.pr-n-mgt_who-rocio-jimenez.path, nsxt_policy_group.pr-n-mgt_who-karol-szeplewicz.path, nsxt_policy_group.pr-n-mgt_who-jamessturdy_ip_10-17-100-164.path, nsxt_policy_group.pr-n-mgt_gib-sergeymangov.path, nsxt_policy_group.pr-n-mgt_wh5002470.path, nsxt_policy_group.pr-n-mgt_whtemp003.path, nsxt_policy_group.pr-n-mgt_whtemp027.path, nsxt_policy_group.pr-n-mgt_whtemp037.path, nsxt_policy_group.pr-n-mgt_whtemp055.path, nsxt_policy_group.pr-n-mgt_whtemp058.path, nsxt_policy_group.pr-n-mgt_whtemp059.path, nsxt_policy_group.pr-n-mgt_whtemp060.path, nsxt_policy_group.pr-n-mgt_whtemp062.path, nsxt_policy_group.pr-n-mgt_whtemp080.path, nsxt_policy_group.pr-n-mgt_whtemp086.path, nsxt_policy_group.pr-n-mgt_whtemp089.path, nsxt_policy_group.pr-n-mgt_stj-samcarrera.path, nsxt_policy_group.pr-n-mgt_who-aliebrahim.path, nsxt_policy_group.pr-n-mgt_who-dionbonner.path, nsxt_policy_group.pr-n-mgt_who-samcarrara.path, nsxt_policy_group.pr-n-mgt_who-merrynhelleur.path, nsxt_policy_group.pr-n-mgt_gib-monikanewbound.path, nsxt_policy_group.pr-n-mgt_who-hazeldincer.path, nsxt_policy_group.pr-n-mgt_who-mariagrigorova.path, nsxt_policy_group.pr-n-mgt_who-slawomirniemiec.path, nsxt_policy_group.pr-n-mgt_who-ellaking2.path, nsxt_policy_group.pr-n-mgt_who-joshroberts2.path, nsxt_policy_group.pr-n-mgt_who-jamessturdy1.path, nsxt_policy_group.pr-n-mgt_who-martonscocs.path, nsxt_policy_group.pr-n-mgt_who_andylidbetter.path, nsxt_policy_group.pr-n-mgt_who-grahamrobertson.path, nsxt_policy_group.pr-n-mgt_bfa-vip_users.path, nsxt_policy_group.pr-n-mgt_bfa-vip_users_2.path, nsxt_policy_group.pr-n-mgt_do_test.path, nsxt_policy_group.pr-n-mgt_nippun_chopra_test_bfa.path, nsxt_policy_group.pr-n-mgt_host-10-180-19-172.path, nsxt_policy_group.pr-n-mgt_gib-nerysthomas.path, nsxt_policy_group.pr-n-mgt_gib-kathrynkiggins.path, nsxt_policy_group.pr-n-mgt_gib-kirstymoffat.path, nsxt_policy_group.pr-n-mgt_bfa-sagilaniado.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-180.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-47.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-66.path, nsxt_policy_group.pr-n-mgt_ip_10-53-33-219.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-201.path, nsxt_policy_group.pr-n-mgt_grp_all-data-mgt-users.path, nsxt_policy_group.pr-n-mgt_grp_who-lev-ankudinov.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sdp-intergation-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sdp-intergation-access"
  description  = "role: pr-n-mgt_grp_sdp-intergation-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-waclawbargiel.path, nsxt_policy_group.pr-n-mgt_who-leszekgornik.path, nsxt_policy_group.pr-n-mgt_host-10-55-15-154.path, nsxt_policy_group.pr-n-mgt_host-10-1-87-45.path, nsxt_policy_group.pr-n-mgt_10-55-12-93.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_193" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_193"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_193"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dba.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dev.path, nsxt_policy_group.pr-n-mgt_grp_systemengineers.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-steward-arch.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-testers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_uk-dr-in-an" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_uk-dr-in-an"
  description  = "role: pr-n-mgt_grp_uk-dr-in-an"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprnap51.path, nsxt_policy_group.pr-n-mgt_sc1wnprnap52.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb51.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb52.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb53.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_197" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_197"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_197"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sas-consultant-temp.path, nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dba.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dev.path, nsxt_policy_group.pr-n-mgt_grp_systemengineers.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-steward-arch.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sas-prod-crm-analytics" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sas-prod-crm-analytics"
  description  = "role: pr-n-mgt_grp_sas-prod-crm-analytics"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap001.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap002.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_206"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_206"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_host-10-180-19-172.path, nsxt_policy_group.pr-n-mgt_who-victoriagould.path, nsxt_policy_group.pr-n-mgt_host-jomitrou.path, nsxt_policy_group.pr-n-mgt_who-apapoulias.path, nsxt_policy_group.pr-n-mgt_stj-lewisballantine.path, nsxt_policy_group.pr-n-mgt_who-davidhotson.path, nsxt_policy_group.pr-n-mgt_gib-garethnetto.path, nsxt_policy_group.pr-n-mgt_gib-garethnetto-desktop.path, nsxt_policy_group.pr-n-mgt_krk-damiandamianov.path, nsxt_policy_group.pr-n-mgt_who-danielstringer.path, nsxt_policy_group.pr-n-mgt_stj-alanhunter.path, nsxt_policy_group.pr-n-mgt_10-1-74-159.path, nsxt_policy_group.pr-n-mgt_who-pedronucci.path, nsxt_policy_group.pr-n-mgt_gib-thomasgrabarczyk.path, nsxt_policy_group.pr-n-mgt_stj-laurablancarte.path, nsxt_policy_group.pr-n-mgt_10-56-12-50.path, nsxt_policy_group.pr-n-mgt_whg-kamiltumiewicz.path, nsxt_policy_group.pr-n-mgt_who-simonfirth.path, nsxt_policy_group.pr-n-mgt_whg-gosiaraus.path, nsxt_policy_group.pr-n-mgt_who-boglarkabihari.path, nsxt_policy_group.pr-n-mgt_who-ionutmanea.path, nsxt_policy_group.pr-n-mgt_who-panagiotistsiolis.path, nsxt_policy_group.pr-n-mgt_who-robertwhitehead.path, nsxt_policy_group.pr-n-mgt_gib-paula-jedrzejczyk.path, nsxt_policy_group.pr-n-mgt_anthony-kowaliw-pc1.path, nsxt_policy_group.pr-n-mgt_theodoros-petanidis-pc1.path, nsxt_policy_group.pr-n-mgt_simon-firth-pc1_ip_10-56-10-191.path, nsxt_policy_group.pr-n-mgt_simon-firth-pc2_ip_192-168-2-46.path, nsxt_policy_group.pr-n-mgt_vasileia-kouti-pc1.path, nsxt_policy_group.pr-n-mgt_simon-firth-pc2_ip_192-168-2-14.path, nsxt_policy_group.pr-n-mgt_piotr-snarski-pc1.path, nsxt_policy_group.pr-n-mgt_pawel-opozda-pc1.path, nsxt_policy_group.pr-n-mgt_javier-luna-labrador-pc1.path, nsxt_policy_group.pr-n-mgt_magdalena-sikotowska-pc1.path, nsxt_policy_group.pr-n-mgt_john-edward-lope-pc1.path, nsxt_policy_group.pr-n-mgt_elzbieta-plesnar-pc1.path, nsxt_policy_group.pr-n-mgt_bfa-sagilaniado.path, nsxt_policy_group.pr-n-mgt_david-oxley-pc1.path, nsxt_policy_group.pr-n-mgt_kseniia-koltsova-pc1.path, nsxt_policy_group.pr-n-mgt_iryna-marchenko-pc1.path, nsxt_policy_group.pr-n-mgt_erik-wallen-pc1.path, nsxt_policy_group.pr-n-mgt_fabien-efaty-pc1.path, nsxt_policy_group.pr-n-mgt_andres-gomez-pc1.path, nsxt_policy_group.pr-n-mgt_chris-purnell-pc1.path, nsxt_policy_group.pr-n-mgt_monika-piatek-pc1.path, nsxt_policy_group.pr-n-mgt_nataliia-romanchuk-pc1.path, nsxt_policy_group.pr-n-mgt_mariel-alcoriza-pc1.path, nsxt_policy_group.pr-n-mgt_richard-fletcher-pc1.path, nsxt_policy_group.pr-n-mgt_marek-grzymala-pc1.path, nsxt_policy_group.pr-n-mgt_piotr-migdal-pc1.path, nsxt_policy_group.pr-n-mgt_pawel-kicek-pc1.path, nsxt_policy_group.pr-n-mgt_kundan-yadav-pc1.path, nsxt_policy_group.pr-n-mgt_kenneth-farrugia-pc1.path, nsxt_policy_group.pr-n-mgt_thu-van-lee-pc1.path, nsxt_policy_group.pr-n-mgt_constancia-sanchez-pc1.path, nsxt_policy_group.pr-n-mgt_who-fernandolago.path, nsxt_policy_group.pr-n-mgt_ip_192-168-2-232.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dba.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dev.path, nsxt_policy_group.pr-n-mgt_grp_systemengineers.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-steward-arch.path, nsxt_policy_group.pr-n-mgt_grp_crm-analytics-db-users.path, nsxt_policy_group.pr-n-mgt_grp_who-lev-ankudinov.path, nsxt_policy_group.pr-n-mgt_grp_who-piotr-nurkowski.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_235"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_235"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-carmitkleinboxer.path, nsxt_policy_group.pr-n-mgt_who-zachcohen.path, nsxt_policy_group.pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83.path, nsxt_policy_group.pr-n-mgt_who-alexandrospapoulias.path, nsxt_policy_group.pr-n-mgt_bfd-simonfirth.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-bi-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-trading-r-and-d" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-trading-r-and-d"
  description  = "role: pr-n-mgt_grp_grp-trading-r-and-d"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_stj-andystogdale.path, nsxt_policy_group.pr-n-mgt_stj-antonioostios.path, nsxt_policy_group.pr-n-mgt_stj-dancockerill.path, nsxt_policy_group.pr-n-mgt_stj-gustavljundqvist.path, nsxt_policy_group.pr-n-mgt_stj-jamessmith.path, nsxt_policy_group.pr-n-mgt_stj-liammosley.path, nsxt_policy_group.pr-n-mgt_stj-poppywaterhouse.path, nsxt_policy_group.pr-n-mgt_stj-tradingr_and_d.path, nsxt_policy_group.pr-n-mgt_stj-new-trading_r_d_svr.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_malta-bi-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_malta-bi-users"
  description  = "role: CHG0134318"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-40-10-134.path, nsxt_policy_group.pr-n-mgt_10-40-10-236.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-143.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-144.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-145.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-146.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-147.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-148.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-149.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-150.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-151.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-152.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-153.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-154.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-155.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-156.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-157.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-158.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-199.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-102.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-124.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-132.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-159.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-112.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-113.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-116.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-123.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-142.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-171.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-172.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-173.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-174.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-175.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-176.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-177.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-178.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-179.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-180.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-181.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-182.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-183.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-184.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-185.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-186.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-187.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-188.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-189.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-190.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-191.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-192.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-193.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-194.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-195.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-196.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-197.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-198.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-200.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-201.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-202.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-203.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-204.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-205.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-206.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-207.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-208.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-209.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-210.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-211.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-212.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-213.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-214.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-215.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-130.path, nsxt_policy_group.pr-n-mgt_ip_10-40-11-100.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-231.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-232.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-216.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-217.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-218.path, nsxt_policy_group.pr-n-mgt_ip_10-53-32-168.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-220.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-221.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-222.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-223.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-224.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-225.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-226.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-227.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-228.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-229.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-230.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-233.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-241.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-234.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_orbis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_orbis"
  description  = "role: pr-n-mgt_grp_orbis"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_orbis-dr-nat.path, nsxt_policy_group.pr-n-mgt_ip_10-194-140-0s24.path, nsxt_policy_group.pr-n-mgt_grp_orbis-live.path, nsxt_policy_group.pr-n-mgt_grp_orbis-dr.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_37"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_37"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path, nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path, nsxt_policy_group.pr-n-mgt_ods-mgmt-network-24.path, nsxt_policy_group.pr-n-mgt_web-tier-network-24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-ta-gsh-testers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-ta-gsh-testers"
  description  = "role: pr-n-mgt_grp_grp-ta-gsh-testers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gsh-mathewbarrett.path, nsxt_policy_group.pr-n-mgt_gsh-matthew-barrett-2.path, nsxt_policy_group.pr-n-mgt_gsh-vasanti-tailor-2.path, nsxt_policy_group.pr-n-mgt_gsh-vasantitaylor.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-scc-ta-db-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-scc-ta-db-2"
  description  = "role: pr-n-mgt_grp_grp-scc-ta-db-2"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-115.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-116.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-c-nms-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-c-nms-mgmt"
  description  = "role: pr-n-mgt_grp_grp-pr-c-nms-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-cacti01.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-131.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_rfc-1918" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_rfc-1918"
  description  = "role: CHG0015230"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_172-16-0-0s12.path, nsxt_policy_group.pr-n-mgt_ip_192-168-0-0s16.path, nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sc1-networkmonitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sc1-networkmonitoring"
  description  = "role: pr-n-mgt_grp_sc1-networkmonitoring"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-cacti01.path, nsxt_policy_group.pr-n-mgt_uk-sc1-solarwinds.path, nsxt_policy_group.pr-n-mgt_uk-sc1-netbrain01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_2"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_2"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-wn-pre-in03.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-128.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-mgmt-vlans" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-mgmt-vlans"
  description  = "role: pr-n-mgt_grp_grp-pr-n-mgmt-vlans"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-144-0s20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-moni-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-moni-servers"
  description  = "role: pr-n-mgt_grp_scc-moni-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn10.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn11.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn12.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn13.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn15.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn14.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_119" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_119"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_119"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_ob-web-app-hosts.path, nsxt_policy_group.pr-n-mgt_grp_push-mgmt.path, nsxt_policy_group.pr-n-mgt_grp_marketinginternalproxies.path, nsxt_policy_group.pr-n-mgt_grp_google-proxy-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_107"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_107"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_stj-ncs.path, nsxt_policy_group.pr-n-mgt_ip_10-120-136-140.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_7"
  description  = "role: CHG0031140, CHG0036892, CHG0064457"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dba-28.path, nsxt_policy_group.pr-n-mgt_infosec-28.path, nsxt_policy_group.pr-n-mgt_netsec-27.path, nsxt_policy_group.pr-n-mgt_serveroperations-27.path, nsxt_policy_group.pr-n-mgt_environments-26.path, nsxt_policy_group.pr-n-mgt_incident-analyst-27.path, nsxt_policy_group.pr-n-mgt_incident-analyst2-27.path, nsxt_policy_group.pr-n-mgt_stj-grahameades.path, nsxt_policy_group.pr-n-mgt_lcw-byrongalietta.path, nsxt_policy_group.pr-n-mgt_usr-billpalfreman.path, nsxt_policy_group.pr-n-mgt_scr-kamentarlov.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson3.path, nsxt_policy_group.pr-n-mgt_who-oliverallan2.path, nsxt_policy_group.pr-n-mgt_dba-jamesfryer.path, nsxt_policy_group.pr-n-mgt_lcw-stevemoyes.path, nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_stj-wh5002126.path, nsxt_policy_group.pr-n-mgt_lcw-andylunn.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-n-mgt_grp_systemengineers.path, nsxt_policy_group.pr-n-mgt_grp_stj-ops.path, nsxt_policy_group.pr-n-mgt_grp_grp-trading-ias.path, nsxt_policy_group.pr-n-mgt_grp_dba-team.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_6"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path, nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path, nsxt_policy_group.pr-n-mgt_ods-mgmt-network-24.path, nsxt_policy_group.pr-n-mgt_web-tier-network-24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_1"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_1"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_infosec-28.path, nsxt_policy_group.pr-n-mgt_netsec-27.path, nsxt_policy_group.pr-n-mgt_netsec-oncall-28.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-n-mgt_grp_netsec-stj.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-orion-app-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-orion-app-srvs"
  description  = "role: pr-n-mgt_grp_grp-orion-app-srvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6wnpremn79-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_net-obj-g-solarwinds-destinations" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_net-obj-g-solarwinds-destinations"
  description  = "role: CHG0138643"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-159-0s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-96s27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_81"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_81"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_jabber-uc-vcsc-mgmt.path, nsxt_policy_group.pr-n-mgt_sc1acprgcp01.path, nsxt_policy_group.pr-n-mgt_sc1acprgcp01-vmc.path, nsxt_policy_group.pr-n-mgt_sc1acprgcp01-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprcucm01.path, nsxt_policy_group.pr-n-mgt_sc1uxprcucm01-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo03.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo03-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo04.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo04-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnvgprgin06.path, nsxt_policy_group.pr-n-mgt_sc1wnvgprgin06-aci.path, nsxt_policy_group.pr-n-mgt_sc1uxprgcj01.path, nsxt_policy_group.pr-n-mgt_sc1uxprgcj01-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo01.path, nsxt_policy_group.pr-n-mgt_sc1apprevo01-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo02.path, nsxt_policy_group.pr-n-mgt_sc1apprevo02-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo03.path, nsxt_policy_group.pr-n-mgt_sc1apprevo03-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo04.path, nsxt_policy_group.pr-n-mgt_sc1apprevo04-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo05.path, nsxt_policy_group.pr-n-mgt_sc1apprevo05-aci.path, nsxt_policy_group.pr-n-mgt_sc1apprevo07.path, nsxt_policy_group.pr-n-mgt_sc1apprevo07-aci.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo08.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo08-aci.path, nsxt_policy_group.pr-n-mgt_ireuxprevo01.path, nsxt_policy_group.pr-n-mgt_ireuxprevo01-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo10-vip-vmc.path, nsxt_policy_group.pr-n-mgt_sc1uxprevo11-vip-vmc.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo06-vmc.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-77.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_80"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_80"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_jabber-uc-vcse-mgmt.path, nsxt_policy_group.pr-n-mgt_vc-vcs-express-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_3"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_3"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_infosec-28.path, nsxt_policy_group.pr-n-mgt_netsec-27.path, nsxt_policy_group.pr-n-mgt_netsec-oncall-28.path, nsxt_policy_group.pr-n-mgt_jkirkwood.path, nsxt_policy_group.pr-n-mgt_aitor_ayape.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-n-mgt_10-19-2-128s25.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-64s26.path, nsxt_policy_group.pr-n-mgt_ip_192-168-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_84"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_84"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_jabber-uc-vcse-mgmt.path, nsxt_policy_group.pr-n-mgt_vc-vcs-express-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_29"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_29"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-180-18-44.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-95.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_121"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_121"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_net_10-120-180-0_25.path, nsxt_policy_group.pr-n-mgt_ip_10-120-131-191.path, nsxt_policy_group.pr-n-mgt_ip_10-120-136-181.path, nsxt_policy_group.pr-n-mgt_ip_10-53-0-0s24.path, nsxt_policy_group.pr-n-mgt_grp_grp-pr-c-layer7-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_noncde-mgmt-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_noncde-mgmt-nets"
  description  = "role: pr-n-mgt_grp_noncde-mgmt-nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-144-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-148-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-149-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-0s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-192s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-96s27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_143"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_143"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_lsj-leesheard.path, nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path, nsxt_policy_group.pr-n-mgt_gib-monikanewbound.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-0s24.path, nsxt_policy_group.pr-n-mgt_grp_dba-team.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_125" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_125"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_125"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap32.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap45.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap46.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb12.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb13.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb41.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb42.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap41.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap42.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb47.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb48.path, nsxt_policy_group.pr-n-mgt_who-katherinehawes.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-97.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-219.path, nsxt_policy_group.pr-n-mgt_grp_vcenter50-access-https.path, nsxt_policy_group.pr-n-mgt_grp_crm-calendar-cluster.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_130" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_130"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_130"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path, nsxt_policy_group.pr-n-mgt_ods-mgmt-network-24.path, nsxt_policy_group.pr-n-mgt_web-tier-network-24.path, nsxt_policy_group.pr-n-mgt_app2-tier-network-24.path, nsxt_policy_group.pr-n-mgt_app-tier-network-24.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-168.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-17.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-181.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-185.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_83"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_83"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gsh-jamiebladd.path, nsxt_policy_group.pr-n-mgt_ip_10-1-82-92.path, nsxt_policy_group.pr-n-mgt_ip_10-3-60-206.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_infrastructure_architects" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_infrastructure_architects"
  description  = "role: pr-n-mgt_grp_infrastructure_architects"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-craigjohnson.path, nsxt_policy_group.pr-n-mgt_who-georgepetrouis.path, nsxt_policy_group.pr-n-mgt_who-ianrichards.path, nsxt_policy_group.pr-n-mgt_who-jamesgirvan.path, nsxt_policy_group.pr-n-mgt_who-jarrodsmithers.path, nsxt_policy_group.pr-n-mgt_who-neilwilson.path, nsxt_policy_group.pr-n-mgt_who-patmills.path, nsxt_policy_group.pr-n-mgt_who-richardsanderson.path, nsxt_policy_group.pr-n-mgt_lcw-johnnoel.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_20"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_20"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path, nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path, nsxt_policy_group.pr-n-mgt_edge-mgmt-network-27.path, nsxt_policy_group.pr-n-mgt_email-mgmt-network-27.path, nsxt_policy_group.pr-n-mgt_ods-mgmt-network-24.path, nsxt_policy_group.pr-n-mgt_server-ilo-network-24.path, nsxt_policy_group.pr-n-mgt_vc-mgmt-network-27.path, nsxt_policy_group.pr-n-mgt_web-tier-network-24.path, nsxt_policy_group.pr-n-mgt_webscreen-mgmt-network-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_21"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_21"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap71.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap73.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap74.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_symantec-workflow-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_symantec-workflow-servers"
  description  = "role: pr-n-mgt_grp_symantec-workflow-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprein30.path, nsxt_policy_group.pr-n-mgt_sc1wnprein31.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trafalgar_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trafalgar_servers"
  description  = "role: pr-n-mgt_grp_trafalgar_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-120-145-71-78.path, nsxt_policy_group.pr-n-mgt_10-120-147-71.path, nsxt_policy_group.pr-n-mgt_10-120-147-72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap65.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap66.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap017.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap018.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap047.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap048.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap079.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap080.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap081.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap082.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap083.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-121.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-122.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-123.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-124.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-61.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-62.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-63.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-64.path, nsxt_policy_group.pr-n-mgt_grp_trafalga_pds_servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_214"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_214"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_whtemp033.path, nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path, nsxt_policy_group.pr-n-mgt_stj-chriswade.path, nsxt_policy_group.pr-n-mgt_stj-traders.path, nsxt_policy_group.pr-n-mgt_stj-chriswade2.path, nsxt_policy_group.pr-n-mgt_grp_trading_report_svr_users.path, nsxt_policy_group.pr-n-mgt_grp_client-mgmt-grp.path, nsxt_policy_group.pr-n-mgt_grp_italianpublishingtrading.path, nsxt_policy_group.pr-n-mgt_grp_japan-spanish-online-team.path, nsxt_policy_group.pr-n-mgt_grp_grp-pr-manila-users.path, nsxt_policy_group.pr-n-mgt_grp_trs-access-users.path, nsxt_policy_group.pr-n-mgt_grp_mnl-trs-users.path, nsxt_policy_group.pr-n-mgt_grp_manila-client-mgmt.path, nsxt_policy_group.pr-n-mgt_grp_stj-broadcastpcs.path, nsxt_policy_group.pr-n-mgt_grp_mnl-tonykennerly-team.path, nsxt_policy_group.pr-n-mgt_grp_makati-trading-bcp.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_liability-viewer-pds-apps" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_liability-viewer-pds-apps"
  description  = "role: pr-n-mgt_grp_liability-viewer-pds-apps"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprrap01-mg.path, nsxt_policy_group.pr-n-mgt_sc1uxprrap02-mg.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_liability-viewer-euthenia-apps" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_liability-viewer-euthenia-apps"
  description  = "role: pr-n-mgt_grp_liability-viewer-euthenia-apps"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprrap03-mg.path, nsxt_policy_group.pr-n-mgt_sc1uxprrap04-mg.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_239"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_239"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_gib_corp_users.path, nsxt_policy_group.pr-n-mgt_grp_grp-gtp-outbound-adapters.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-noncde-cf-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-noncde-cf-mgmt"
  description  = "role: pr-n-mgt_grp_grp-noncde-cf-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-152-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-153-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_234"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_234"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_lcw-jw.path, nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path, nsxt_policy_group.pr-n-mgt_netsec-27.path, nsxt_policy_group.pr-n-mgt_serveroperations-27.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_166"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_166"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-120-152-21.path, nsxt_policy_group.pr-n-mgt_10-120-152-22.path, nsxt_policy_group.pr-n-mgt_net-10-120-153-0_24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_165" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_165"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_165"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gsh-jamiebladd.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_cf_proxy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_cf_proxy"
  description  = "role: pr-n-mgt_grp_cf_proxy"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb21.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_212"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_212"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dba-paulmartin.path, nsxt_policy_group.pr-n-mgt_dba-timwilkinson.path, nsxt_policy_group.pr-n-mgt_who-farukhshah.path, nsxt_policy_group.pr-n-mgt_brswnstrdb001.path, nsxt_policy_group.pr-n-mgt_10-3-20-112.path, nsxt_policy_group.pr-n-mgt_10-3-20-113.path, nsxt_policy_group.pr-n-mgt_stj-maggierolls.path, nsxt_policy_group.pr-n-mgt_lcw-kejautouray.path, nsxt_policy_group.pr-n-mgt_wh5001700.path, nsxt_policy_group.pr-n-mgt_stj-kundanyadav.path, nsxt_policy_group.pr-n-mgt_ip_10-1-71-2.path, nsxt_policy_group.pr-n-mgt_grp_dba_workstations.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_182"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_182"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_usr-richardniland.path, nsxt_policy_group.pr-n-mgt_usr-richardniland2.path, nsxt_policy_group.pr-n-mgt_lcw-kejautouray.path, nsxt_policy_group.pr-n-mgt_alb-kejautouray.path, nsxt_policy_group.pr-n-mgt_ip_192-168-2-0s23.path, nsxt_policy_group.pr-n-mgt_ip_192-168-48-0s20.path, nsxt_policy_group.pr-n-mgt_grp_dba-team.path, nsxt_policy_group.pr-n-mgt_grp_ras-vpn-pool.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_184" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_184"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_184"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_riak_app_servers.path, nsxt_policy_group.pr-n-mgt_grp_trs_db_servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trs-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trs-users"
  description  = "role: CHG0064276"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_davidemagni_sslvpn.path, nsxt_policy_group.pr-n-mgt_lorenarodriguez_sslvpn.path, nsxt_policy_group.pr-n-mgt_mattiascagliola_sslvpn.path, nsxt_policy_group.pr-n-mgt_who-marktrotter.path, nsxt_policy_group.pr-n-mgt_who-andrewtibet.path, nsxt_policy_group.pr-n-mgt_10-1-30-151.path, nsxt_policy_group.pr-n-mgt_10-1-62-30.path, nsxt_policy_group.pr-n-mgt_stj-alanhunter2.path, nsxt_policy_group.pr-n-mgt_wh5004012.path, nsxt_policy_group.pr-n-mgt_wh5004034.path, nsxt_policy_group.pr-n-mgt_wh5004076.path, nsxt_policy_group.pr-n-mgt_10-1-18-155.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-224.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-141.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-222.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-221.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-143.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-226.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-139.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-166.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-204.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-180.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-160.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-161.path, nsxt_policy_group.pr-n-mgt_ip_10-17-100-168.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-142.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-140.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-135.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-133.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-165.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-144.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-134.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-137.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-228.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-136.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-229.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-201.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-98.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-73.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-69.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-46.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-39.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-45.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-181.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-182.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-70.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-67.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-9.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-21.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-124.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-159.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-19.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-226.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-228.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-28.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-69.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-45.path, nsxt_policy_group.pr-n-mgt_ip_10-1-112-237.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-75.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-77.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-78.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-79.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-82.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-87.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-150.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-177.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-211.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-216.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-30.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-54.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-84.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-98.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-100.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-107.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-113.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-114.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-122.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-137.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-139.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-147.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-148.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-156.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-15.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-161.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-162.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-164.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-166.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-167.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-17.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-190.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-193.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-198.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-203.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-208.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-215.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-219.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-223.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-242.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-24.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-25.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-29.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-31.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-48.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-50.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-51.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-53.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-54.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-66.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-74.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-76.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-82.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-154.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-179.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-194.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-196.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-246.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-39.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-77.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-80.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-88.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-94.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-95.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-33.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-34.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-58.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-60.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-63.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-138.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-140.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-75.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-37.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-38.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-39.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-41.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-47.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-48.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-49.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-51.path, nsxt_policy_group.pr-n-mgt_ip_10-1-66-53.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-38.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-150.path, nsxt_policy_group.pr-n-mgt_ip_192-168-2-40.path, nsxt_policy_group.pr-n-mgt_ip_192-168-2-37.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-93.path, nsxt_policy_group.pr-n-mgt_ip_192-168-201-84.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-176.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-62.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-14.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-82.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-201.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-24.path, nsxt_policy_group.pr-n-mgt_ip_10-1-67-171.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-239.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-130.path, nsxt_policy_group.pr-n-mgt_grp_trs-users-uk.path, nsxt_policy_group.pr-n-mgt_grp_mnl-trs-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_cxb41-0-corp-lans" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_cxb41-0-corp-lans"
  description  = "role: pr-n-mgt_grp_cxb41-0-corp-lans"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_cxb41-0-shoreditch01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-citywalk01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-citywalk02.path, nsxt_policy_group.pr-n-mgt_cxb41-0-citywalk03.path, nsxt_policy_group.pr-n-mgt_cxb41-0-stjohns01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-stjohns02.path, nsxt_policy_group.pr-n-mgt_cxb41-0-stjohns03.path, nsxt_policy_group.pr-n-mgt_cxb41-0-greenside01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-gibraltar01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-gibraltar02.path, nsxt_policy_group.pr-n-mgt_cxb41-0-gibraltar03.path, nsxt_policy_group.pr-n-mgt_cxb41-0-ra01.path, nsxt_policy_group.pr-n-mgt_cxb41-0-ra02.path, nsxt_policy_group.pr-n-mgt_cxb41-0-ra03.path, nsxt_policy_group.pr-n-mgt_cxb41-0-tel-aviv-lan-nat.path, nsxt_policy_group.pr-n-mgt_shoreditch03.path, nsxt_policy_group.pr-n-mgt_cxb41-0-stjohns04.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-n-mgt_grp_net-10-1-78-0-23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wh-user-networks-01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wh-user-networks-01"
  description  = "role: pr-n-mgt_grp_wh-user-networks-01"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_shoreditch01.path, nsxt_policy_group.pr-n-mgt_citywalk01.path, nsxt_policy_group.pr-n-mgt_citywalk02.path, nsxt_policy_group.pr-n-mgt_citywalk03.path, nsxt_policy_group.pr-n-mgt_stjohns01.path, nsxt_policy_group.pr-n-mgt_stjohns02.path, nsxt_policy_group.pr-n-mgt_stjohns03.path, nsxt_policy_group.pr-n-mgt_greenside01.path, nsxt_policy_group.pr-n-mgt_gibraltar01.path, nsxt_policy_group.pr-n-mgt_gibraltar02.path, nsxt_policy_group.pr-n-mgt_gibraltar03.path, nsxt_policy_group.pr-n-mgt_gib-vpn.path, nsxt_policy_group.pr-n-mgt_tel-aviv-lan-nat.path, nsxt_policy_group.pr-n-mgt_brs-vpn.path, nsxt_policy_group.pr-n-mgt_citywalk78.path, nsxt_policy_group.pr-n-mgt_stjohns79.path, nsxt_policy_group.pr-n-mgt_shoreditch03.path, nsxt_policy_group.pr-n-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-n-mgt_grp_net-10-1-78-0-23.path, nsxt_policy_group.pr-n-mgt_grp_kotlarska_cloudteam-nets.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_76"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_76"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_do_test.path, nsxt_policy_group.pr-n-mgt_ip_10-1-83-128.path, nsxt_policy_group.pr-n-mgt_grp_bi-ssrs-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_213"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_213"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path, nsxt_policy_group.pr-n-mgt_stj-traders.path, nsxt_policy_group.pr-n-mgt_net-10-1-30-0_24.path, nsxt_policy_group.pr-n-mgt_ip_10-1-82-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_gtp-stream-servers-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_gtp-stream-servers-mgmt"
  description  = "role: pr-n-mgt_grp_gtp-stream-servers-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb26.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb27.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb26mgmt.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb27mgmt.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_229"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_229"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_scc-cx-network.path, nsxt_policy_group.pr-n-mgt_scc-cx-inv-network.path, nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_101"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_101"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_krakow_user_lan_tempoffice.path, nsxt_policy_group.pr-n-mgt_krk-wifi-core.path, nsxt_policy_group.pr-n-mgt_alb-jiridokoupil.path, nsxt_policy_group.pr-n-mgt_alb-nickabbott.path, nsxt_policy_group.pr-n-mgt_alb-danferry.path, nsxt_policy_group.pr-n-mgt_krk-maciejpiekos.path, nsxt_policy_group.pr-n-mgt_krk_wifi.path, nsxt_policy_group.pr-n-mgt_grp_bg-sophia-devs.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-non-cde-jump-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-non-cde-jump-hosts"
  description  = "role: pr-n-mgt_grp_grp-non-cde-jump-hosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_prdxjmp23hst001-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_prdxjmp28jmp001-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_hp-oneview-backups" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_hp-oneview-backups"
  description  = "role: pr-n-mgt_grp_hp-oneview-backups"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremg26-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_brsuxpremg25-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1uxpremg27-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_ld6uxpremg01-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_labuxpremg01-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-apm-enterprise-manager" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-apm-enterprise-manager"
  description  = "role: pr-n-mgt_grp_grp-apm-enterprise-manager"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn10.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn11.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn12.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn13.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sql-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sql-servers"
  description  = "role: pr-n-mgt_grp_sql-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprgdb03.path, nsxt_policy_group.pr-n-mgt_sc1-wn-prg-db01.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb02.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb004.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb005_ip_10-120-149-27.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb006_ip_10-120-149-28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_corp_sql_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_corp_sql_servers"
  description  = "role: pr-n-mgt_grp_corp_sql_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprgdb01a.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb02.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb03.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb004.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb006_ip_10-120-149-28.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb003_ip_10-120-149-25.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb005_ip_10-120-149-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_8"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_8"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_w7d-dbjump.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb019.path, nsxt_policy_group.pr-n-mgt_10-120-146-51.path, nsxt_policy_group.pr-n-mgt_10-120-146-52.path, nsxt_policy_group.pr-n-mgt_10-120-180-142.path, nsxt_policy_group.pr-n-mgt_cessql.path, nsxt_policy_group.pr-n-mgt_sc1wnpredb01.path, nsxt_policy_group.pr-n-mgt_sc1wnprevo01.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb06.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb81.path, nsxt_policy_group.pr-n-mgt_sc1wnprrto01.path, nsxt_policy_group.pr-n-mgt_sc1wnprrto02.path, nsxt_policy_group.pr-n-mgt_sc1wnprndb53.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb05.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb05-vmc.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb06-vmc.path, nsxt_policy_group.pr-n-mgt_corpservicessql-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_corpservicessql-prod-williamhill-plc-vmc.path, nsxt_policy_group.pr-n-mgt_corpservices-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_corpservices-prod-williamhill-plc-vmc.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-115.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-116.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_86" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_86"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_86"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-alexandrospapoulias.path, nsxt_policy_group.pr-n-mgt_who-garethnetto.path, nsxt_policy_group.pr-n-mgt_host-10-180-19-172.path, nsxt_policy_group.pr-n-mgt_who-apapoulias.path, nsxt_policy_group.pr-n-mgt_who-nerysthomas.path, nsxt_policy_group.pr-n-mgt_stj-alanhunter.path, nsxt_policy_group.pr-n-mgt_who-robertwhitehead.path, nsxt_policy_group.pr-n-mgt_who-ionutmanea.path, nsxt_policy_group.pr-n-mgt_lsj-anthonykowaliw.path, nsxt_policy_group.pr-n-mgt_raphael-sammut-pc1.path, nsxt_policy_group.pr-n-mgt_jan-paroan-pc1.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-bi-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_db-sql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_db-sql"
  description  = "role: pr-n-mgt_grp_db-sql"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpremn20a.path, nsxt_policy_group.pr-n-mgt_sc1uxpromn001.path, nsxt_policy_group.pr-n-mgt_sc1wnpremn15.path, nsxt_policy_group.pr-n-mgt_sc1wnpremn21a.path, nsxt_policy_group.pr-n-mgt_uk-sc1-solarwinds-netflow.path, nsxt_policy_group.pr-n-mgt_uk-sc1-solarwinds.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-62.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_35"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_35"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-120-146-51.path, nsxt_policy_group.pr-n-mgt_10-120-146-52.path, nsxt_policy_group.pr-n-mgt_sc1wnprgdb05_06.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-54.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-55.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_113"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_113"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_krakow-subnets.path, nsxt_policy_group.pr-n-mgt_grp_krakow_user_ranges.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_75"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_75"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprbkms01.path, nsxt_policy_group.pr-n-mgt_sc1uxprbkms02.path, nsxt_policy_group.pr-n-mgt_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_77"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_77"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprndb81.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_87"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_87"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-55-12-93.path, nsxt_policy_group.pr-n-mgt_10-55-224-93.path, nsxt_policy_group.pr-n-mgt_ip_10-55-0-55.path, nsxt_policy_group.pr-n-mgt_ip_10-55-1-221.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_94" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_94"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_94"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-133.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-134.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-151.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-152.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-60.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-62.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-97.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-98.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_97"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_97"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ardenta-dr.path, nsxt_policy_group.pr-n-mgt_ardenta-net.path, nsxt_policy_group.pr-n-mgt_orbis-live-dr.path, nsxt_policy_group.pr-n-mgt_orbis-live-net.path, nsxt_policy_group.pr-n-mgt_grp_grp-ardenta-vpn-nat.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_98"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_98"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1apprcsc50-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1jump-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-po-kr-mars-db-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-po-kr-mars-db-users"
  description  = "role: pr-n-mgt_grp_grp-po-kr-mars-db-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-55-12-42.path, nsxt_policy_group.pr-n-mgt_10-55-12-43.path, nsxt_policy_group.pr-n-mgt_10-55-12-46.path, nsxt_policy_group.pr-n-mgt_10-55-12-47.path, nsxt_policy_group.pr-n-mgt_10-55-12-50.path, nsxt_policy_group.pr-n-mgt_10-55-12-93.path, nsxt_policy_group.pr-n-mgt_10-55-224-42.path, nsxt_policy_group.pr-n-mgt_10-55-224-43.path, nsxt_policy_group.pr-n-mgt_10-55-224-46.path, nsxt_policy_group.pr-n-mgt_10-55-224-47.path, nsxt_policy_group.pr-n-mgt_10-55-224-50.path, nsxt_policy_group.pr-n-mgt_10-55-224-93.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_114" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_114"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_114"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_alb-danferry.path, nsxt_policy_group.pr-n-mgt_stj_danferry_ip_10-1-74-181.path, nsxt_policy_group.pr-n-mgt_stj-samsonkarnikoti.path, nsxt_policy_group.pr-n-mgt_retail-main-sonar-runner-1.path, nsxt_policy_group.pr-n-mgt_lsj-emmafletcher.path, nsxt_policy_group.pr-n-mgt_lsj-hannahslinger.path, nsxt_policy_group.pr-n-mgt_grp_sftp-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_eoc-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_eoc-devices"
  description  = "role: CHG0119660"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-55-14-0.path, nsxt_policy_group.pr-n-mgt_10-55-14-1.path, nsxt_policy_group.pr-n-mgt_10-55-14-10.path, nsxt_policy_group.pr-n-mgt_10-55-14-11.path, nsxt_policy_group.pr-n-mgt_10-55-14-12.path, nsxt_policy_group.pr-n-mgt_10-55-14-13.path, nsxt_policy_group.pr-n-mgt_10-55-14-14.path, nsxt_policy_group.pr-n-mgt_10-55-14-15.path, nsxt_policy_group.pr-n-mgt_10-55-14-16.path, nsxt_policy_group.pr-n-mgt_10-55-14-17.path, nsxt_policy_group.pr-n-mgt_10-55-14-2.path, nsxt_policy_group.pr-n-mgt_10-55-14-3.path, nsxt_policy_group.pr-n-mgt_10-55-14-4.path, nsxt_policy_group.pr-n-mgt_10-55-14-5.path, nsxt_policy_group.pr-n-mgt_10-55-14-6.path, nsxt_policy_group.pr-n-mgt_10-55-14-7.path, nsxt_policy_group.pr-n-mgt_10-55-14-8.path, nsxt_policy_group.pr-n-mgt_10-55-14-9.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-po-kra-mars-master-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-po-kra-mars-master-users"
  description  = "role: CHG0119649"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-55-12-42.path, nsxt_policy_group.pr-n-mgt_10-55-12-43.path, nsxt_policy_group.pr-n-mgt_10-55-12-44.path, nsxt_policy_group.pr-n-mgt_10-55-12-99.path, nsxt_policy_group.pr-n-mgt_10-55-224-42.path, nsxt_policy_group.pr-n-mgt_10-55-224-43.path, nsxt_policy_group.pr-n-mgt_10-55-224-44.path, nsxt_policy_group.pr-n-mgt_10-55-224-99.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_129" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_129"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_129"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap43.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_148"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_148"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb05.path, nsxt_policy_group.pr-n-mgt_grp_oracle-db-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_149" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_149"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_149"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-pr-citrix-vlan.path, nsxt_policy_group.pr-n-mgt_scc-pr-citrix-vlan.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_163" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_163"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_163"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_krk-wifi-inc-prb-rls.path, nsxt_policy_group.pr-n-mgt_grp_lan-krakow-inc-prb-rls.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_malta-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_malta-users"
  description  = "role: pr-n-mgt_grp_malta-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-180-27-59.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-60.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-105.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-107.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-199.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-100.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-101.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-102.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-103.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-104.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-106.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-108.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-109.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-110.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-111.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-112.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-113.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-114.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-115.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-116.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-117.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-118.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-119.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-120.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-121.path, nsxt_policy_group.pr-n-mgt_ip_10-40-10-122.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_25"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_25"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb12.path, nsxt_policy_group.pr-n-mgt_sc1wxprnwb31.path, nsxt_policy_group.pr-n-mgt_10-120-145-32slash29.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap71.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap73.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_49"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_49"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpredc15.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc17.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc15-fe.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_aws-tss-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_aws-tss-subnets"
  description  = "role: pr-n-mgt_grp_aws-tss-subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_aws-100-79-0-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-2-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-4-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-6-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-8-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-10-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-12-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-14-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-16-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-18-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-20-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-22-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-24-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-26-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-28-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-30-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-32-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-34-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-36-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-38-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-40-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-42-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-44-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-46-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-48-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-50-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-52-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-54-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-56-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-58-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-60-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-62-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-64-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-66-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-68-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-70-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-72-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-74-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-76-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-78-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-80-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-82-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-84-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-86-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-88-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-90-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-92-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-94-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-96-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-98-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-100-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-102-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-104-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-106-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-108-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-110-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-112-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-114-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-116-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-118-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-120-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-122-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-124-0s23.path, nsxt_policy_group.pr-n-mgt_aws-100-79-126-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_uk-sc1-edgeswitches" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_uk-sc1-edgeswitches"
  description  = "role: pr-n-mgt_grp_uk-sc1-edgeswitches"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-er01.path, nsxt_policy_group.pr-n-mgt_uk-sc1-er02.path, nsxt_policy_group.pr-n-mgt_uk-sc1-es01.path, nsxt_policy_group.pr-n-mgt_uk-sc1-es02.path, nsxt_policy_group.pr-n-mgt_uk-sc1-er-01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_pr_n_mgt_local_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_pr_n_mgt_local_subnets"
  description  = "role: pr-n-mgt_grp_pr_n_mgt_local_subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-144-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-145-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-146-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-148-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-149-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-151-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-152-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-153-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-0s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-192s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-159-96s27.path, nsxt_policy_group.pr-n-mgt_ip_10-120-160-192s27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_73"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_73"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_aws-techservices-nonprod-vpc.path, nsxt_policy_group.pr-n-mgt_aws-techservices-prod-vpc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_5"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_5"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_usr-richardniland2.path, nsxt_policy_group.pr-n-mgt_10-1-18-226.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_manila-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_manila-subnets"
  description  = "role: pr-n-mgt_grp_manila-subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_manila-subnet-1.path, nsxt_policy_group.pr-n-mgt_manila-subnet-2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_dm-aws-prod-vpc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_dm-aws-prod-vpc"
  description  = "role: pr-n-mgt_grp_dm-aws-prod-vpc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dm-aws-prod-vpc-1.path, nsxt_policy_group.pr-n-mgt_dm-aws-prod-vpc-2.path, nsxt_policy_group.pr-n-mgt_dm-aws-prod-vpc-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_10"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_10"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ld6wnppeiam01.path, nsxt_policy_group.pr-n-mgt_ld6wnpreiam01.path, nsxt_policy_group.pr-n-mgt_sc1wnppeiam01.path, nsxt_policy_group.pr-n-mgt_sc1wnpreiam01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_vmc-sddcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_vmc-sddcs"
  description  = "role: pr-n-mgt_grp_vmc-sddcs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-156-5-0s24.path, nsxt_policy_group.pr-n-mgt_grp_vmc-sddc-retail-production.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_whgroup_ad_servers-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_whgroup_ad_servers-chg0144834"
  description  = "role: pr-n-mgt_grp_whgroup_ad_servers-chg0144834"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_bfawnpredc01.path, nsxt_policy_group.pr-n-mgt_brswnpredc01.path, nsxt_policy_group.pr-n-mgt_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-n-mgt_brswnpredc03_ip_10-210-194-13.path, nsxt_policy_group.pr-n-mgt_gibwnpredc02.path, nsxt_policy_group.pr-n-mgt_gibwnpredc03.path, nsxt_policy_group.pr-n-mgt_irewnprdc01.path, nsxt_policy_group.pr-n-mgt_irewnprdc02.path, nsxt_policy_group.pr-n-mgt_nvawnprdc01.path, nsxt_policy_group.pr-n-mgt_nvawnprdc02.path, nsxt_policy_group.pr-n-mgt_krawnpredc01.path, nsxt_policy_group.pr-n-mgt_krawnpredc02.path, nsxt_policy_group.pr-n-mgt_ld6wnpredc01-new.path, nsxt_policy_group.pr-n-mgt_ld6wnpredc02-new.path, nsxt_policy_group.pr-n-mgt_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-n-mgt_mnlwnpredc03.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc01.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc02.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-n-mgt_sofwnpredc01.path, nsxt_policy_group.pr-n-mgt_sofwnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_euc_mgmt_server-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_euc_mgmt_server-group-chg0142765"
  description  = "role: pr-n-mgt_grp_euc_mgmt_server-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsapprcmg002-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_on_premise_datacentre_vlans-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_on_premise_datacentre_vlans-group-chg0142765"
  description  = "role: pr-n-mgt_grp_on_premise_datacentre_vlans-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-0-0s16.path, nsxt_policy_group.pr-n-mgt_ip_10-210-0-0s16.path, nsxt_policy_group.pr-n-mgt_ip_10-180-0-0s16.path, nsxt_policy_group.pr-n-mgt_ip_10-112-0-0s16.path, nsxt_policy_group.pr-n-mgt_ip_10-19-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wh_nets-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wh_nets-chg0143200"
  description  = "role: pr-n-mgt_grp_wh_nets-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_splunk_deployment_server-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_splunk_deployment_server-chg0143200"
  description  = "role: pr-n-mgt_grp_splunk_deployment_server-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wh_nets-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wh_nets-chg0142763"
  description  = "role: pr-n-mgt_grp_wh_nets-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_splunk_deployment_server-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_splunk_deployment_server-chg0142763"
  description  = "role: pr-n-mgt_grp_splunk_deployment_server-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ras-vpn-pool"
  description  = "role: pr-n-mgt_grp_ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_ld6-ras-vpn-pool.path, nsxt_policy_group.pr-n-mgt_grp_sc1-ras-vpn-pool.path, nsxt_policy_group.pr-n-mgt_grp_mrg-ras-vpn-pool.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ise-psn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ise-psn"
  description  = "role: CHG0137261,CHG0145266"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-ise02-pre-vmc.path, nsxt_policy_group.pr-n-mgt_uk-brs-ise02.path, nsxt_policy_group.pr-n-mgt_gi-mpl-ise01.path, nsxt_policy_group.pr-n-mgt_uk-sc1-ise02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-scc-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-scc-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprbkms01.path, nsxt_policy_group.pr-n-mgt_sc1uxprbkms02.path, nsxt_policy_group.pr-n-mgt_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-ld6-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-ld6-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ld6wnprbkcs01.path, nsxt_policy_group.pr-n-mgt_ld6uxprbkms03.path, nsxt_policy_group.pr-n-mgt_ld6uxprbkms04.path, nsxt_policy_group.pr-n-mgt_ld6uxprbkms01.path, nsxt_policy_group.pr-n-mgt_ld6uxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-gib-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-gib-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_gibuxprbkms01.path, nsxt_policy_group.pr-n-mgt_gibuxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_splunkhfcluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_splunkhfcluster"
  description  = "role: pr-n-mgt_grp_splunkhfcluster"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn002-prod-williamhill-plc.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn003-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_rundeck-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_rundeck-servers"
  description  = "role: pr-n-mgt_grp_rundeck-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpreap237.path, nsxt_policy_group.pr-n-mgt_sc1uxpreap238.path, nsxt_policy_group.pr-n-mgt_sc1uxpreap239.path, nsxt_policy_group.pr-n-mgt_sc1uxpreap242.path, nsxt_policy_group.pr-n-mgt_sc1uxrdk.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wily-svrs_all" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wily-svrs_all"
  description  = "role: pr-n-mgt_grp_wily-svrs_all"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_wily_svrs_brs.path, nsxt_policy_group.pr-n-mgt_grp_wily_svrs_scc.path, nsxt_policy_group.pr-n-mgt_grp_wily_svrs_gib.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wily-access-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wily-access-group"
  description  = "role: pr-n-mgt_grp_wily-access-group"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_webproxies-cx-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_webproxies-cx-scc"
  description  = "role: pr-n-mgt_grp_webproxies-cx-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-121-5-0slash24.path, nsxt_policy_group.pr-n-mgt_10-121-7-0slash24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_48"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_48"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-44-25.path, nsxt_policy_group.pr-n-mgt_ip_10-120-44-26.path, nsxt_policy_group.pr-n-mgt_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_100"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_100"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsux910.path, nsxt_policy_group.pr-n-mgt_gibux910.path, nsxt_policy_group.pr-n-mgt_ld6uxpreds01.path, nsxt_policy_group.pr-n-mgt_sc1uxpreds01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mailhosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mailhosts"
  description  = "role: pr-n-mgt_grp_mailhosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_emailhost01.path, nsxt_policy_group.pr-n-mgt_emailhost02.path, nsxt_policy_group.pr-n-mgt_emailhost03.path, nsxt_policy_group.pr-n-mgt_emailhost04.path, nsxt_policy_group.pr-n-mgt_emailhost05.path, nsxt_policy_group.pr-n-mgt_emailhost06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ossec-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ossec-servers"
  description  = "role: pr-n-mgt_grp_ossec-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprcmn001.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_whgroup-ad-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_whgroup-ad-servers"
  description  = "role: pr-n-mgt_grp_whgroup-ad-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-n-mgt_brswnpredc03_ip_10-210-194-13.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-n-mgt_gibwnpredc02.path, nsxt_policy_group.pr-n-mgt_gibwnpredc03.path, nsxt_policy_group.pr-n-mgt_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-n-mgt_ld6predc01-new.path, nsxt_policy_group.pr-n-mgt_ld6predc02-new.path, nsxt_policy_group.pr-n-mgt_bfawnpredc01.path, nsxt_policy_group.pr-n-mgt_krawnpredc01.path, nsxt_policy_group.pr-n-mgt_krawnpredc02.path, nsxt_policy_group.pr-n-mgt_mnlwnpredc03.path, nsxt_policy_group.pr-n-mgt_sofwnpredc01.path, nsxt_policy_group.pr-n-mgt_sofwnpredc02.path, nsxt_policy_group.pr-n-mgt_brswnpredc01.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc01.path, nsxt_policy_group.pr-n-mgt_sc1wnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_infoblox-all-dns-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_infoblox-all-dns-servers"
  description  = "role: pr-n-mgt_grp_infoblox-all-dns-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsns01.path, nsxt_policy_group.pr-n-mgt_brsns02.path, nsxt_policy_group.pr-n-mgt_gibns01.path, nsxt_policy_group.pr-n-mgt_gibns02.path, nsxt_policy_group.pr-n-mgt_sccns01.path, nsxt_policy_group.pr-n-mgt_sccns02.path, nsxt_policy_group.pr-n-mgt_ld6ns01.path, nsxt_policy_group.pr-n-mgt_ld6ns02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-wsus-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-wsus-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-scc-wsus.path, nsxt_policy_group.pr-n-mgt_stj-wsus.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-syslog-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-syslog-servers"
  description  = "role: pr-n-mgt_grp_grp-pr-n-syslog-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-sm02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-nms-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-nms-mgmt"
  description  = "role: pr-n-mgt_grp_grp-pr-n-nms-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-sc1-wn-pre-mn15.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-131.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-59.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-openview" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-openview"
  description  = "role: CHG0017824"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnpremn21.path, nsxt_policy_group.pr-n-mgt_ip_10-1-14-120s32.path, nsxt_policy_group.pr-n-mgt_grp_grp-orion-app-srvs.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-ntp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-ntp"
  description  = "role: CHG0017824"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-163-19s32.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-20s32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-status-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-status-servers"
  description  = "role: pr-n-mgt_grp_grp-pr-n-status-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremg30.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-kms-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-kms-servers"
  description  = "role: pr-n-mgt_grp_grp-pr-n-kms-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprein12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-katello-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-katello-servers"
  description  = "role: pr-n-mgt_grp_grp-pr-n-katello-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sccuxstnmg01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mail-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mail-servers"
  description  = "role: pr-n-mgt_grp_mail-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brs-proofpoint.path, nsxt_policy_group.pr-n-mgt_scc-mail.path, nsxt_policy_group.pr-n-mgt_stj-proofpoint.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_uim-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_uim-servers"
  description  = "role: CHG0079749,CHG0119559"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brsuxpremn65.path, nsxt_policy_group.pr-n-mgt_brsuxpremn66.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn65.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn66.path, nsxt_policy_group.pr-n-mgt_ld6uxpremn13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_nexus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_nexus"
  description  = "role: pr-n-mgt_grp_nexus"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-210-163-21.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_18"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_18"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn74.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-73.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-migrated_network_59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-migrated_network_59"
  description  = "role: pr-n-mgt_grp_scc-migrated_network_59"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-65-68.path, nsxt_policy_group.pr-n-mgt_ip_10-210-65-68.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_rds-kms-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_rds-kms-server"
  description  = "role: KMS/RDS license servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_brswndremg002.path, nsxt_policy_group.pr-n-mgt_sc1wnpremg002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_skybox-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_skybox-appliances"
  description  = "role: CHG0122435"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1appresc02-data.path, nsxt_policy_group.pr-n-mgt_sc1appresc03-data.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_push-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_push-mgmt"
  description  = "role: pr-n-mgt_grp_push-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wxprnwb31.path, nsxt_policy_group.pr-n-mgt_sc1wxprnwb32.path, nsxt_policy_group.pr-n-mgt_sc1wxprnwb33.path, nsxt_policy_group.pr-n-mgt_sc1wxprnwb34.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb35.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-c-ad-child" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-c-ad-child"
  description  = "role: CHG0014122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-194-13.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-14.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-15.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-18.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-16.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-17.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-c-ad-parent" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-c-ad-parent"
  description  = "role: CHG0014122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-194-11.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-n-dns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-n-dns"
  description  = "role: CHG0017824"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_uk-brs-dns.path, nsxt_policy_group.pr-n-mgt_uk-sc1-dns.path, nsxt_policy_group.pr-n-mgt_ip_10-1-34-10s32.path, nsxt_policy_group.pr-n-mgt_ip_10-64-72-10s32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mrr-servers-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mrr-servers-db"
  description  = "role: pr-n-mgt_grp_mrr-servers-db"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-120-149-52.path, nsxt_policy_group.pr-n-mgt_ip_10-120-149-51.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_tableau-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_tableau-servers"
  description  = "role: pr-n-mgt_grp_tableau-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprnap87.path, nsxt_policy_group.pr-n-mgt_sc1wnprnap88.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ad-controllers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ad-controllers"
  description  = "role: pr-n-mgt_grp_ad-controllers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ld6predc01-new.path, nsxt_policy_group.pr-n-mgt_ld6predc02-new.path, nsxt_policy_group.pr-n-mgt_ip_10-210-194-12.path, nsxt_policy_group.pr-n-mgt_ip_10-210-194-13.path, nsxt_policy_group.pr-n-mgt_ip_10-210-194-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_scc-ad-controllers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_scc-ad-controllers"
  description  = "role: pr-n-mgt_grp_scc-ad-controllers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-194-12.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-13.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-14.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-15.path, nsxt_policy_group.pr-n-mgt_ip_10-120-194-18.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_cf_api_app_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_cf_api_app_server"
  description  = "role: pr-n-mgt_grp_cf_api_app_server"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprntc49.path, nsxt_policy_group.pr-n-mgt_sc1uxprntc50.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_riak_app_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_riak_app_servers"
  description  = "role: pr-n-mgt_grp_riak_app_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnrk21.path, nsxt_policy_group.pr-n-mgt_sc1uxprnrk22.path, nsxt_policy_group.pr-n-mgt_sc1uxprnrk23.path, nsxt_policy_group.pr-n-mgt_sc1uxprnrk24.path, nsxt_policy_group.pr-n-mgt_sc1uxprnrk25.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_rabbit_mq_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_rabbit_mq_server"
  description  = "role: pr-n-mgt_grp_rabbit_mq_server"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnmq31.path, nsxt_policy_group.pr-n-mgt_sc1uxprnmq32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_tennis_creation_service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_tennis_creation_service"
  description  = "role: pr-n-mgt_grp_tennis_creation_service"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprntc41.path, nsxt_policy_group.pr-n-mgt_sc1uxprntc42.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_tennis_pricing_app_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_tennis_pricing_app_servers"
  description  = "role: pr-n-mgt_grp_tennis_pricing_app_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1wnprnap53.path, nsxt_policy_group.pr-n-mgt_sc1wnprnap54.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_nevadaadapter-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_nevadaadapter-servers"
  description  = "role: pr-n-mgt_grp_nevadaadapter-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprntc55.path, nsxt_policy_group.pr-n-mgt_sc1uxprntc56.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-gtp-fred-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-gtp-fred-mgmt"
  description  = "role: pr-n-mgt_grp_grp-gtp-fred-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap100.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap101.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_dba-team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_dba-team"
  description  = "role: pr-n-mgt_grp_dba-team"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dba-jayakumarperrikrishnaiah.path, nsxt_policy_group.pr-n-mgt_dba-keithbrailey.path, nsxt_policy_group.pr-n-mgt_dba-mattprice.path, nsxt_policy_group.pr-n-mgt_dba-nickhowe.path, nsxt_policy_group.pr-n-mgt_dba-oliverallan.path, nsxt_policy_group.pr-n-mgt_dba-oliverallan2.path, nsxt_policy_group.pr-n-mgt_dba-philhinchcliffe.path, nsxt_policy_group.pr-n-mgt_dba-piotradamiak.path, nsxt_policy_group.pr-n-mgt_dba-richardanthony.path, nsxt_policy_group.pr-n-mgt_dba-richardanthony2.path, nsxt_policy_group.pr-n-mgt_dba-simoneaster.path, nsxt_policy_group.pr-n-mgt_dba-simoneaster2.path, nsxt_policy_group.pr-n-mgt_dba-simoneaster3.path, nsxt_policy_group.pr-n-mgt_dba-simoneaster4.path, nsxt_policy_group.pr-n-mgt_dba-stephenwood.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson3.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson4.path, nsxt_policy_group.pr-n-mgt_dba-amarbarot.path, nsxt_policy_group.pr-n-mgt_dba-jamesfryer.path, nsxt_policy_group.pr-n-mgt_dba-jamesgibson.path, nsxt_policy_group.pr-n-mgt_dba-paulmartin.path, nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_who-adriansugden.path, nsxt_policy_group.pr-n-mgt_dba-gary-dennis-ip1.path, nsxt_policy_group.pr-n-mgt_dba-gary-dennis-ip2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_dba_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_dba_group"
  description  = "role: pr-n-mgt_grp_dba_group"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dba-nickhowe.path, nsxt_policy_group.pr-n-mgt_dba-philhinchcliffe.path, nsxt_policy_group.pr-n-mgt_dba-richardanthony.path, nsxt_policy_group.pr-n-mgt_dba-richardanthony2.path, nsxt_policy_group.pr-n-mgt_who-keithbrailey.path, nsxt_policy_group.pr-n-mgt_who-mattprice.path, nsxt_policy_group.pr-n-mgt_who-oliverallan.path, nsxt_policy_group.pr-n-mgt_who-oliverallan2.path, nsxt_policy_group.pr-n-mgt_who-piotradamiak.path, nsxt_policy_group.pr-n-mgt_who-simoneaster.path, nsxt_policy_group.pr-n-mgt_who-simoneaster2.path, nsxt_policy_group.pr-n-mgt_who-simoneaster3.path, nsxt_policy_group.pr-n-mgt_who-stephenwood.path, nsxt_policy_group.pr-n-mgt_who-tobyhenderson.path, nsxt_policy_group.pr-n-mgt_who-tobyhenderson2.path, nsxt_policy_group.pr-n-mgt_who-tobyhenderson3.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson.path, nsxt_policy_group.pr-n-mgt_dba-amarbarot.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ob-internal-backoffice-web" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ob-internal-backoffice-web"
  description  = "role: pr-n-mgt_grp_ob-internal-backoffice-web"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ob-appservers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ob-appservers"
  description  = "role: pr-n-mgt_grp_ob-appservers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap71.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap73.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_all-data-mgt-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_all-data-mgt-users"
  description  = "role: pr-n-mgt_grp_all-data-mgt-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-annaventuras.path, nsxt_policy_group.pr-n-mgt_lcw-fabrizioorsini.path, nsxt_policy_group.pr-n-mgt_who-nickyjones.path, nsxt_policy_group.pr-n-mgt_ip_10-53-33-219.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-106.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-137.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-157.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-246.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-66.path, nsxt_policy_group.pr-n-mgt_ip_10-1-148-85.path, nsxt_policy_group.pr-n-mgt_grp_systemengineers.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-bi-users.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dba.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-dev.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-steward-arch.path, nsxt_policy_group.pr-n-mgt_grp_data-mgt-testers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_who-lev-ankudinov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_who-lev-ankudinov"
  description  = "role: TASK0221382"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-lev-ankudinov-pc1.path, nsxt_policy_group.pr-n-mgt_who-lev-ankudinov-pc2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-dba" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-dba"
  description  = "role: # For Data Mgt Channel staff only - others will be removed"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dba-keithbrailey.path, nsxt_policy_group.pr-n-mgt_dba-jayakumarperrikrishnaiah.path, nsxt_policy_group.pr-n-mgt_dba-nickhowe.path, nsxt_policy_group.pr-n-mgt_dba-stephenwood.path, nsxt_policy_group.pr-n-mgt_dba-oliverallan.path, nsxt_policy_group.pr-n-mgt_dba-oliverallan2.path, nsxt_policy_group.pr-n-mgt_dba-amarbarot.path, nsxt_policy_group.pr-n-mgt_dba-jamesfryer.path, nsxt_policy_group.pr-n-mgt_dba-dimitrikosoy.path, nsxt_policy_group.pr-n-mgt_dba-dimitrikosoy2.path, nsxt_policy_group.pr-n-mgt_dba-ofiritzhaki.path, nsxt_policy_group.pr-n-mgt_who-adriansugden.path, nsxt_policy_group.pr-n-mgt_dba-tobyhenderson.path, nsxt_policy_group.pr-n-mgt_dba-markpugh.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-dev" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-dev"
  description  = "role: # For Data Mgt Channel staff only - others will be removed"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_vijaytumati.path, nsxt_policy_group.pr-n-mgt_vijaytumati2.path, nsxt_policy_group.pr-n-mgt_vincenzodeconcilo.path, nsxt_policy_group.pr-n-mgt_mariaroytshenker.path, nsxt_policy_group.pr-n-mgt_who-mansingh.path, nsxt_policy_group.pr-n-mgt_who-richardnoland.path, nsxt_policy_group.pr-n-mgt_who-markalderson.path, nsxt_policy_group.pr-n-mgt_who-roberttokarski.path, nsxt_policy_group.pr-n-mgt_who-marcfitzgerald.path, nsxt_policy_group.pr-n-mgt_who-davidday.path, nsxt_policy_group.pr-n-mgt_who-jamesgornell.path, nsxt_policy_group.pr-n-mgt_who-talvindersahota.path, nsxt_policy_group.pr-n-mgt_who-simonthompson.path, nsxt_policy_group.pr-n-mgt_who-neilunderwood.path, nsxt_policy_group.pr-n-mgt_who-kevinbrownhill.path, nsxt_policy_group.pr-n-mgt_who-shahzadrehman.path, nsxt_policy_group.pr-n-mgt_whoalexandraasulin.path, nsxt_policy_group.pr-n-mgt_who-rossfleming.path, nsxt_policy_group.pr-n-mgt_who-jordanbrear.path, nsxt_policy_group.pr-n-mgt_who-mansingh2.path, nsxt_policy_group.pr-n-mgt_who-andrewknight.path, nsxt_policy_group.pr-n-mgt_who-simonthompson2.path, nsxt_policy_group.pr-n-mgt_who-neilunderwood2.path, nsxt_policy_group.pr-n-mgt_who-kevinbrownhill2.path, nsxt_policy_group.pr-n-mgt_who-talvindersahota2.path, nsxt_policy_group.pr-n-mgt_who-vicenzodeconcilo2.path, nsxt_policy_group.pr-n-mgt_who-roberttokarski2.path, nsxt_policy_group.pr-n-mgt_who-davidday2.path, nsxt_policy_group.pr-n-mgt_who-jamesgornall2.path, nsxt_policy_group.pr-n-mgt_who-marcfitz.path, nsxt_policy_group.pr-n-mgt_who-vijaytumati2.path, nsxt_policy_group.pr-n-mgt_who-andydavis.path, nsxt_policy_group.pr-n-mgt_who-mattlister.path, nsxt_policy_group.pr-n-mgt_who-stuartconnor.path, nsxt_policy_group.pr-n-mgt_who-mattspencernoble.path, nsxt_policy_group.pr-n-mgt_usr-cwk-markchrystyn.path, nsxt_policy_group.pr-n-mgt_who-colinpearson.path, nsxt_policy_group.pr-n-mgt_who-briankitchen.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_systemengineers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_systemengineers"
  description  = "role: Gareth Sephton owned"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-llandosnunez.path, nsxt_policy_group.pr-n-mgt_who-llanosnunez.path, nsxt_policy_group.pr-n-mgt_lcw-andrewdonachie.path, nsxt_policy_group.pr-n-mgt_lcw-chriswren.path, nsxt_policy_group.pr-n-mgt_lcw-chriswren2.path, nsxt_policy_group.pr-n-mgt_lcw-danferry.path, nsxt_policy_group.pr-n-mgt_lcw-garethsephton.path, nsxt_policy_group.pr-n-mgt_lcw-markpetrie.path, nsxt_policy_group.pr-n-mgt_lcw-ravisingh.path, nsxt_policy_group.pr-n-mgt_lcw-richardhampshire.path, nsxt_policy_group.pr-n-mgt_lcw-richardscott.path, nsxt_policy_group.pr-n-mgt_lcw-roblewis.path, nsxt_policy_group.pr-n-mgt_lcw-stevewilson.path, nsxt_policy_group.pr-n-mgt_lcw-tomfield.path, nsxt_policy_group.pr-n-mgt_who-joncandlin.path, nsxt_policy_group.pr-n-mgt_who-marcuscampbell.path, nsxt_policy_group.pr-n-mgt_who-neilbellamy.path, nsxt_policy_group.pr-n-mgt_who-neilbellamy2.path, nsxt_policy_group.pr-n-mgt_who-vpn-llanosnunez.path, nsxt_policy_group.pr-n-mgt_who-vpn-neilbellamy.path, nsxt_policy_group.pr-n-mgt_who-alastairmontgomery.path, nsxt_policy_group.pr-n-mgt_lcw-davidbarszczak.path, nsxt_policy_group.pr-n-mgt_usr-wpp-agalindo2.path, nsxt_policy_group.pr-n-mgt_usr-wpp-agalindo.path, nsxt_policy_group.pr-n-mgt_who-joseescanciano.path, nsxt_policy_group.pr-n-mgt_who-patrickdiloreto.path, nsxt_policy_group.pr-n-mgt_who-jamesmoody.path, nsxt_policy_group.pr-n-mgt_who-pedrogutirrez.path, nsxt_policy_group.pr-n-mgt_who-miguelpoyatos.path, nsxt_policy_group.pr-n-mgt_who-petrutodoran.path, nsxt_policy_group.pr-n-mgt_who-istvanpapp.path, nsxt_policy_group.pr-n-mgt_lcw-billpalfreman.path, nsxt_policy_group.pr-n-mgt_stj_danferry_ip_10-1-74-25.path, nsxt_policy_group.pr-n-mgt_nickchrzanowski.path, nsxt_policy_group.pr-n-mgt_niklambev.path, nsxt_policy_group.pr-n-mgt_peterwaithe.path, nsxt_policy_group.pr-n-mgt_piotrmozdzynski.path, nsxt_policy_group.pr-n-mgt_who-mauroarnoldi.path, nsxt_policy_group.pr-n-mgt_se_nathanflynn.path, nsxt_policy_group.pr-n-mgt_lcw-alancatto.path, nsxt_policy_group.pr-n-mgt_who-mauroarnoldi2.path, nsxt_policy_group.pr-n-mgt_stj-andrewglass.path, nsxt_policy_group.pr-n-mgt_stj-amarbarot.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-78.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-79.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-87.path, nsxt_policy_group.pr-n-mgt_ip_10-1-74-144.path, nsxt_policy_group.pr-n-mgt_ip_10-1-74-166.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-steward-arch" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-steward-arch"
  description  = "role: # For Data Mgt Channel staff only - others will be removed"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_alanchristie-sslvpn.path, nsxt_policy_group.pr-n-mgt_jarrodsmithers.path, nsxt_policy_group.pr-n-mgt_doriangordon.path, nsxt_policy_group.pr-n-mgt_andrewthompson-sslvpn.path, nsxt_policy_group.pr-n-mgt_tlv-giladlandau.path, nsxt_policy_group.pr-n-mgt_who-gavinmarshall.path, nsxt_policy_group.pr-n-mgt_who-alanchristie-desktop.path, nsxt_policy_group.pr-n-mgt_who-alanchristie-laptop.path, nsxt_policy_group.pr-n-mgt_andrewthompson.path, nsxt_policy_group.pr-n-mgt_who-glyniswalsh.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-testers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-testers"
  description  = "role: # For Data Mgt Channel staff only - others will be removed"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_dm-tester-rahulsogani.path, nsxt_policy_group.pr-n-mgt_dm-tester-grahamhoyle.path, nsxt_policy_group.pr-n-mgt_dm-tester-adeellis.path, nsxt_policy_group.pr-n-mgt_dm-tester-grahamhoyle-sslvpn.path, nsxt_policy_group.pr-n-mgt_who-trimsejdiu.path, nsxt_policy_group.pr-n-mgt_who-adeellisdesktop.path, nsxt_policy_group.pr-n-mgt_who-grahamhoyle2.path, nsxt_policy_group.pr-n-mgt_who-trimsejdiu2.path, nsxt_policy_group.pr-n-mgt_who-adeellis2.path, nsxt_policy_group.pr-n-mgt_who-philellis.path, nsxt_policy_group.pr-n-mgt_who-rahulsogani2.path, nsxt_policy_group.pr-n-mgt_who-aellis.path, nsxt_policy_group.pr-n-mgt_who-rameshkrishna.path, nsxt_policy_group.pr-n-mgt_who-deborahmoore.path, nsxt_policy_group.pr-n-mgt_who-soumyasamal.path, nsxt_policy_group.pr-n-mgt_who-satyabhat.path, nsxt_policy_group.pr-n-mgt_who-richardshields.path, nsxt_policy_group.pr-n-mgt_lcw_dorothy_hawley.path, nsxt_policy_group.pr-n-mgt_host-10-1-86-56.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_crm-analytics-db-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_crm-analytics-db-users"
  description  = "role: pr-n-mgt_grp_crm-analytics-db-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_bi-sarahhadley-pc.path, nsxt_policy_group.pr-n-mgt_bi-woutervanzutphen-pc.path, nsxt_policy_group.pr-n-mgt_gib-waynefield.path, nsxt_policy_group.pr-n-mgt_who-carmitkleinboxer.path, nsxt_policy_group.pr-n-mgt_who-oamrbahaya.path, nsxt_policy_group.pr-n-mgt_who-waynefield.path, nsxt_policy_group.pr-n-mgt_who-zachcohen.path, nsxt_policy_group.pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83.path, nsxt_policy_group.pr-n-mgt_tlv-ayalawaiechman.path, nsxt_policy_group.pr-n-mgt_10-1-78-155.path, nsxt_policy_group.pr-n-mgt_gib-piotrsmolinski.path, nsxt_policy_group.pr-n-mgt_laurablancarte.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_who-piotr-nurkowski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_who-piotr-nurkowski"
  description  = "role: TASK0221378"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-piotr-nurkowski-pc1.path, nsxt_policy_group.pr-n-mgt_who-piotr-nurkowski-pc2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_data-mgt-bi-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_data-mgt-bi-users"
  description  = "role: # For Data Mgt Channel staff only - others will be removed"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_bi-woutervanzutphen-pc.path, nsxt_policy_group.pr-n-mgt_woutervanzutphen-sslvpn.path, nsxt_policy_group.pr-n-mgt_sarahhadley-sslvpn.path, nsxt_policy_group.pr-n-mgt_tobiemuir.path, nsxt_policy_group.pr-n-mgt_bi-skyemartin.path, nsxt_policy_group.pr-n-mgt_waynefield.path, nsxt_policy_group.pr-n-mgt_waynefield-sslvpn.path, nsxt_policy_group.pr-n-mgt_robertsadler.path, nsxt_policy_group.pr-n-mgt_bi-sarahhadley-pc.path, nsxt_policy_group.pr-n-mgt_who-carmitkleinboxer.path, nsxt_policy_group.pr-n-mgt_who-natalijazvokelj.path, nsxt_policy_group.pr-n-mgt_who-waynefield.path, nsxt_policy_group.pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83.path, nsxt_policy_group.pr-n-mgt_tlv-ayalawaiechman.path, nsxt_policy_group.pr-n-mgt_who-omarbahaya.path, nsxt_policy_group.pr-n-mgt_who-zachcohen.path, nsxt_policy_group.pr-n-mgt_who-jamesmakepeace.path, nsxt_policy_group.pr-n-mgt_who-danieldodita.path, nsxt_policy_group.pr-n-mgt_gib-simongatenby.path, nsxt_policy_group.pr-n-mgt_gib-adamfrench.path, nsxt_policy_group.pr-n-mgt_gib-laurenwood.path, nsxt_policy_group.pr-n-mgt_who-rayforrester.path, nsxt_policy_group.pr-n-mgt_gib-adamkynastonsmith.path, nsxt_policy_group.pr-n-mgt_bg-wh5000589.path, nsxt_policy_group.pr-n-mgt_bg-wh5001302.path, nsxt_policy_group.pr-n-mgt_bg-wh5001303.path, nsxt_policy_group.pr-n-mgt_tlv-idanbril.path, nsxt_policy_group.pr-n-mgt_tlv-marinashoyhedbrod.path, nsxt_policy_group.pr-n-mgt_tlv-nat-mariaroytshenker.path, nsxt_policy_group.pr-n-mgt_tlv-nat-rongrossman.path, nsxt_policy_group.pr-n-mgt_tlv-revitalalon.path, nsxt_policy_group.pr-n-mgt_who-omridahan.path, nsxt_policy_group.pr-n-mgt_who-oshratashkenazi.path, nsxt_policy_group.pr-n-mgt_lcw-danieldodita.path, nsxt_policy_group.pr-n-mgt_who-martonscocs.path, nsxt_policy_group.pr-n-mgt_tlv-oshratashkenazi.path, nsxt_policy_group.pr-n-mgt_tlv-reutrefaeli.path, nsxt_policy_group.pr-n-mgt_tlv-yairelitzur.path, nsxt_policy_group.pr-n-mgt_who-laurablancarte.path, nsxt_policy_group.pr-n-mgt_who-martinwray.path, nsxt_policy_group.pr-n-mgt_who-martinwraysslvpn.path, nsxt_policy_group.pr-n-mgt_10-1-78-155.path, nsxt_policy_group.pr-n-mgt_stj-waynefield.path, nsxt_policy_group.pr-n-mgt_who-karol-szeplewicz.path, nsxt_policy_group.pr-n-mgt_who-fernandolago.path, nsxt_policy_group.pr-n-mgt_who-laurablancarte2.path, nsxt_policy_group.pr-n-mgt_gib-piotrsmolinski.path, nsxt_policy_group.pr-n-mgt_danieldodita-sslvpn.path, nsxt_policy_group.pr-n-mgt_fernandolago-sslvpn.path, nsxt_policy_group.pr-n-mgt_rayforrester-sslvpn.path, nsxt_policy_group.pr-n-mgt_ssl-samfurby.path, nsxt_policy_group.pr-n-mgt_lsj-laurablancarte.path, nsxt_policy_group.pr-n-mgt_bfa-marco-purgatori-pc.path, nsxt_policy_group.pr-n-mgt_who-angelosxypolias.path, nsxt_policy_group.pr-n-mgt_bfa-kasrarostamkhany.path, nsxt_policy_group.pr-n-mgt_host-10-55-15-152.path, nsxt_policy_group.pr-n-mgt_gib-boglarkabihari.path, nsxt_policy_group.pr-n-mgt_gib-joaofardilha.path, nsxt_policy_group.pr-n-mgt_slm-robertcamilleri.path, nsxt_policy_group.pr-n-mgt_gib-vasileiakouti.path, nsxt_policy_group.pr-n-mgt_gib-theodorospetanidis.path, nsxt_policy_group.pr-n-mgt_lsj-anthonykowaliw.path, nsxt_policy_group.pr-n-mgt_bfa-sagilaniado.path, nsxt_policy_group.pr-n-mgt_who-panagiotistsiolis.path, nsxt_policy_group.pr-n-mgt_mal-fabienefaty.path, nsxt_policy_group.pr-n-mgt_man-marielalcoriza.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_orbis-live" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_orbis-live"
  description  = "role: pr-n-mgt_grp_orbis-live"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-194-20-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_orbis-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_orbis-dr"
  description  = "role: pr-n-mgt_grp_orbis-dr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-193-30-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ob-web-app-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ob-web-app-hosts"
  description  = "role: pr-n-mgt_grp_ob-web-app-hosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap61.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap62.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap71.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap72.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb12.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb41.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb42.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_marketinginternalproxies" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_marketinginternalproxies"
  description  = "role: pr-n-mgt_grp_marketinginternalproxies"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ssc1uxprnwb05.path, nsxt_policy_group.pr-n-mgt_ssc1uxprnwb06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_google-proxy-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_google-proxy-servers"
  description  = "role: pr-n-mgt_grp_google-proxy-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb001.path, nsxt_policy_group.pr-n-mgt_sc1uxprnwb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_stj-ops" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_stj-ops"
  description  = "role: pr-n-mgt_grp_stj-ops"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-1-112-230.path, nsxt_policy_group.pr-n-mgt_ip_10-1-21-118.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-17.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-181.path, nsxt_policy_group.pr-n-mgt_ip_10-1-22-185.path, nsxt_policy_group.pr-n-mgt_ip_10-1-83-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-trading-ias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-trading-ias"
  description  = "role: pr-n-mgt_grp_grp-trading-ias"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ia_andygallagher.path, nsxt_policy_group.pr-n-mgt_ia_inplaymonitoringpc1.path, nsxt_policy_group.pr-n-mgt_ia_inplaymonitoringpc2.path, nsxt_policy_group.pr-n-mgt_ia_matthayman.path, nsxt_policy_group.pr-n-mgt_ia_vivekvattigunta.path, nsxt_policy_group.pr-n-mgt_stj-byrongalietta.path, nsxt_policy_group.pr-n-mgt_stj-varungundlapalli.path, nsxt_policy_group.pr-n-mgt_stj-wh5002126.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_netsec-stj" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_netsec-stj"
  description  = "role: pr-n-mgt_grp_netsec-stj"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_stj-asimibrahim.path, nsxt_policy_group.pr-n-mgt_stj-nicksimpson.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-c-layer7-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-c-layer7-servers"
  description  = "role: pr-n-mgt_grp_grp-pr-c-layer7-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1apprcwb01.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb02.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb03.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb04.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb005.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb006.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb007.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb008.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb009.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb010.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb011.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb012.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb013.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb014.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb016.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-n-mgt_sc1apprcwb024.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_vcenter50-access-https" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_vcenter50-access-https"
  description  = "role: pr-n-mgt_grp_vcenter50-access-https"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-katherinehawes.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap32.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap45.path, nsxt_policy_group.pr-n-mgt_sc1uxprcap46.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb12.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb13.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb41.path, nsxt_policy_group.pr-n-mgt_sc1uxprcwb42.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap41.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap42.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb47.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb48.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-97.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-219.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_crm-calendar-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_crm-calendar-cluster"
  description  = "role: pr-n-mgt_grp_crm-calendar-cluster"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprndb95.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb96.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trafalga_pds_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trafalga_pds_servers"
  description  = "role: CHG0035851"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxprnap65.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap66.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap51.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap52.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap53.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap54.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap63.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap64.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap67.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap68.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb11.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb12.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb13.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb14.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb15.path, nsxt_policy_group.pr-n-mgt_sc1uxprndb16.path, nsxt_policy_group.pr-n-mgt_sc1uxprnap55.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-61.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-62.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-25.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-26.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-69.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-70.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-241.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-242.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-243.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-244.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-245.path, nsxt_policy_group.pr-n-mgt_ip_10-120-147-246.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trading_report_svr_users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trading_report_svr_users"
  description  = "role: pr-n-mgt_grp_trading_report_svr_users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_birstall_bcp_dr_hosts.path, nsxt_policy_group.pr-n-mgt_who-daniellomax.path, nsxt_policy_group.pr-n-mgt_who-jameskennedy.path, nsxt_policy_group.pr-n-mgt_who-kennicol.path, nsxt_policy_group.pr-n-mgt_who-martinlayfield.path, nsxt_policy_group.pr-n-mgt_who-paulharrington.path, nsxt_policy_group.pr-n-mgt_who-richardfieldsend.path, nsxt_policy_group.pr-n-mgt_who-marktrotter.path, nsxt_policy_group.pr-n-mgt_mnl-bryandianon.path, nsxt_policy_group.pr-n-mgt_who-iantalbot.path, nsxt_policy_group.pr-n-mgt_who-luciaramos.path, nsxt_policy_group.pr-n-mgt_who-adrianalonso.path, nsxt_policy_group.pr-n-mgt_who-markhowarth.path, nsxt_policy_group.pr-n-mgt_lsj-terrypattinson.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-14.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_client-mgmt-grp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_client-mgmt-grp"
  description  = "role: CHG0083007"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_client-mgmt-1.path, nsxt_policy_group.pr-n-mgt_client-mgmt-2.path, nsxt_policy_group.pr-n-mgt_client-mgmt-3.path, nsxt_policy_group.pr-n-mgt_client-mgmt-4.path, nsxt_policy_group.pr-n-mgt_lsj-markswarbrick.path, nsxt_policy_group.pr-n-mgt_who-iangoodin.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_italianpublishingtrading" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_italianpublishingtrading"
  description  = "role: pr-n-mgt_grp_italianpublishingtrading"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_mariagrigorova.path, nsxt_policy_group.pr-n-mgt_silviacecchia.path, nsxt_policy_group.pr-n-mgt_stefanodelbeato.path, nsxt_policy_group.pr-n-mgt_who-massimilianoprimatesta.path, nsxt_policy_group.pr-n-mgt_who-massimoscimmi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_japan-spanish-online-team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_japan-spanish-online-team"
  description  = "role: RITM0097790"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_bfd-shinnosukekoda.path, nsxt_policy_group.pr-n-mgt_bfd-yukiweston.path, nsxt_policy_group.pr-n-mgt_gib-ivanvera.path, nsxt_policy_group.pr-n-mgt_gib-lourdeslopez.path, nsxt_policy_group.pr-n-mgt_gib-raquelperez.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-pr-manila-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-pr-manila-users"
  description  = "role: CHG0126190"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_mnl-user1.path, nsxt_policy_group.pr-n-mgt_mnl-user10.path, nsxt_policy_group.pr-n-mgt_mnl-user11.path, nsxt_policy_group.pr-n-mgt_mnl-user12.path, nsxt_policy_group.pr-n-mgt_mnl-user13.path, nsxt_policy_group.pr-n-mgt_mnl-user14.path, nsxt_policy_group.pr-n-mgt_mnl-user2.path, nsxt_policy_group.pr-n-mgt_mnl-user3.path, nsxt_policy_group.pr-n-mgt_mnl-user4.path, nsxt_policy_group.pr-n-mgt_mnl-user5.path, nsxt_policy_group.pr-n-mgt_mnl-user6.path, nsxt_policy_group.pr-n-mgt_mnl-user7.path, nsxt_policy_group.pr-n-mgt_mnl-user8.path, nsxt_policy_group.pr-n-mgt_mnl-user9.path, nsxt_policy_group.pr-n-mgt_mnl-user15.path, nsxt_policy_group.pr-n-mgt_mnl-user16.path, nsxt_policy_group.pr-n-mgt_mnl-user17.path, nsxt_policy_group.pr-n-mgt_mnl-user18.path, nsxt_policy_group.pr-n-mgt_mnl-user19.path, nsxt_policy_group.pr-n-mgt_mnl-user20.path, nsxt_policy_group.pr-n-mgt_mnl-user21.path, nsxt_policy_group.pr-n-mgt_mnl-user22.path, nsxt_policy_group.pr-n-mgt_mnl-user23.path, nsxt_policy_group.pr-n-mgt_mnl-user24.path, nsxt_policy_group.pr-n-mgt_mnl-user25.path, nsxt_policy_group.pr-n-mgt_mnl-user26.path, nsxt_policy_group.pr-n-mgt_mnl-user27.path, nsxt_policy_group.pr-n-mgt_mnl-user28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trs-access-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trs-access-users"
  description  = "role: pr-n-mgt_grp_trs-access-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_who-adamwalker.path, nsxt_policy_group.pr-n-mgt_who-adamwalker1.path, nsxt_policy_group.pr-n-mgt_who-alanchristie-desktop.path, nsxt_policy_group.pr-n-mgt_who-alanchristie-laptop.path, nsxt_policy_group.pr-n-mgt_who-alanhunter.path, nsxt_policy_group.pr-n-mgt_who-alanhunter1.path, nsxt_policy_group.pr-n-mgt_who-andrewtibet.path, nsxt_policy_group.pr-n-mgt_who-andylidbetter.path, nsxt_policy_group.pr-n-mgt_who-antonioostios.path, nsxt_policy_group.pr-n-mgt_who-danhall.path, nsxt_policy_group.pr-n-mgt_who-davidjones.path, nsxt_policy_group.pr-n-mgt_who-domhall.path, nsxt_policy_group.pr-n-mgt_who-elviratrikova.path, nsxt_policy_group.pr-n-mgt_who-hazeldincer.path, nsxt_policy_group.pr-n-mgt_who-iangoodin.path, nsxt_policy_group.pr-n-mgt_who-ivayloivanov.path, nsxt_policy_group.pr-n-mgt_who-jamesbromwell.path, nsxt_policy_group.pr-n-mgt_who-jameskennedy1.path, nsxt_policy_group.pr-n-mgt_who-manusbonner.path, nsxt_policy_group.pr-n-mgt_who-marcopinnisi.path, nsxt_policy_group.pr-n-mgt_who-mariagrigorova.path, nsxt_policy_group.pr-n-mgt_who-martonscocs.path, nsxt_policy_group.pr-n-mgt_who-massimoscimmi.path, nsxt_policy_group.pr-n-mgt_who-michaelrichardson.path, nsxt_policy_group.pr-n-mgt_who-monika.path, nsxt_policy_group.pr-n-mgt_who-omarbahaya.path, nsxt_policy_group.pr-n-mgt_who-slawomirniemiec.path, nsxt_policy_group.pr-n-mgt_who-stefanoscialanca.path, nsxt_policy_group.pr-n-mgt_who-stephenbrooker.path, nsxt_policy_group.pr-n-mgt_stj-adamchance.path, nsxt_policy_group.pr-n-mgt_stj-alanhunter.path, nsxt_policy_group.pr-n-mgt_stj-chrisjohnson.path, nsxt_policy_group.pr-n-mgt_stj-chrisohara.path, nsxt_policy_group.pr-n-mgt_stj-johnkaye.path, nsxt_policy_group.pr-n-mgt_stj-leesheard.path, nsxt_policy_group.pr-n-mgt_stj-lewisballantine.path, nsxt_policy_group.pr-n-mgt_stj-olivervickers.path, nsxt_policy_group.pr-n-mgt_stj-richardniland.path, nsxt_policy_group.pr-n-mgt_stjmichaelnaughton.path, nsxt_policy_group.pr-n-mgt_stj_nicholasshaw.path, nsxt_policy_group.pr-n-mgt_10-1-113-80.path, nsxt_policy_group.pr-n-mgt_10-1-113-82.path, nsxt_policy_group.pr-n-mgt_10-1-113-87.path, nsxt_policy_group.pr-n-mgt_10-1-18-54.path, nsxt_policy_group.pr-n-mgt_10-1-30-151.path, nsxt_policy_group.pr-n-mgt_10-1-66-59.path, nsxt_policy_group.pr-n-mgt_10-1-67-213.path, nsxt_policy_group.pr-n-mgt_10-1-74-144.path, nsxt_policy_group.pr-n-mgt_10-1-74-159.path, nsxt_policy_group.pr-n-mgt_10-1-74-75.path, nsxt_policy_group.pr-n-mgt_10-53-227-243.path, nsxt_policy_group.pr-n-mgt_10-53-32-217.path, nsxt_policy_group.pr-n-mgt_10-53-32-219.path, nsxt_policy_group.pr-n-mgt_10-53-32-220.path, nsxt_policy_group.pr-n-mgt_10-53-32-47.path, nsxt_policy_group.pr-n-mgt_10-53-32-57.path, nsxt_policy_group.pr-n-mgt_alanhunter.path, nsxt_policy_group.pr-n-mgt_gib-alanhunter.path, nsxt_policy_group.pr-n-mgt_gib-monikanewbound.path, nsxt_policy_group.pr-n-mgt_gib-nicktrevett.path, nsxt_policy_group.pr-n-mgt_gib-robcoleman.path, nsxt_policy_group.pr-n-mgt_gib-sherwinjarvand.path, nsxt_policy_group.pr-n-mgt_gib-tombedson.path, nsxt_policy_group.pr-n-mgt_man-tonykennerly.path, nsxt_policy_group.pr-n-mgt_mnl-kringmoran.path, nsxt_policy_group.pr-n-mgt_host-10-1-113-45.path, nsxt_policy_group.pr-n-mgt_host-10-1-113-55.path, nsxt_policy_group.pr-n-mgt_host-10-1-18-83.path, nsxt_policy_group.pr-n-mgt_10-180-119-138.path, nsxt_policy_group.pr-n-mgt_10-180-19-234.path, nsxt_policy_group.pr-n-mgt_stjchristopherdack.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-236.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-46.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-51.path, nsxt_policy_group.pr-n-mgt_ip_10-1-113-62.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-145.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-166.path, nsxt_policy_group.pr-n-mgt_ip_10-1-13-212.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-175.path, nsxt_policy_group.pr-n-mgt_ip_10-1-18-42.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-21.path, nsxt_policy_group.pr-n-mgt_ip_10-1-30-56.path, nsxt_policy_group.pr-n-mgt_ip_10-1-52-162.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-211.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-23.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-95.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mnl-trs-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mnl-trs-users"
  description  = "role: pr-n-mgt_grp_mnl-trs-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_mnl-aldenaquino.path, nsxt_policy_group.pr-n-mgt_mnl-desireesunga.path, nsxt_policy_group.pr-n-mgt_mnl-joanamarielerum.path, nsxt_policy_group.pr-n-mgt_mnl-maryanndeleon.path, nsxt_policy_group.pr-n-mgt_mnl-marygracedionisio.path, nsxt_policy_group.pr-n-mgt_mnl-myrielvaldivia.path, nsxt_policy_group.pr-n-mgt_mnl-pearlyjao.path, nsxt_policy_group.pr-n-mgt_10-123-12-20.path, nsxt_policy_group.pr-n-mgt_wh5004012.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-149.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-171.path, nsxt_policy_group.pr-n-mgt_ip_10-123-13-24.path, nsxt_policy_group.pr-n-mgt_ip_10-123-22-211.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-211.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_manila-client-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_manila-client-mgmt"
  description  = "role: CHG0082152"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_whtemp019.path, nsxt_policy_group.pr-n-mgt_whtemp025.path, nsxt_policy_group.pr-n-mgt_whtemp045.path, nsxt_policy_group.pr-n-mgt_whtemp092.path, nsxt_policy_group.pr-n-mgt_wh5001137.path, nsxt_policy_group.pr-n-mgt_wh5002720.path, nsxt_policy_group.pr-n-mgt_whtemp076.path, nsxt_policy_group.pr-n-mgt_wh5004012.path, nsxt_policy_group.pr-n-mgt_wh5004034.path, nsxt_policy_group.pr-n-mgt_wh5004076.path, nsxt_policy_group.pr-n-mgt_10-123-13-172.path, nsxt_policy_group.pr-n-mgt_10-123-13-204.path, nsxt_policy_group.pr-n-mgt_10-123-13-224.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-132.path, nsxt_policy_group.pr-n-mgt_ip_10-123-12-211.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_stj-broadcastpcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_stj-broadcastpcs"
  description  = "role: CHG0116429"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-30-66.path, nsxt_policy_group.pr-n-mgt_10-1-30-67.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mnl-tonykennerly-team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mnl-tonykennerly-team"
  description  = "role: CHG0129506"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-123-12-101.path, nsxt_policy_group.pr-n-mgt_10-123-12-106.path, nsxt_policy_group.pr-n-mgt_10-123-12-133.path, nsxt_policy_group.pr-n-mgt_10-123-12-5.path, nsxt_policy_group.pr-n-mgt_10-123-12-50.path, nsxt_policy_group.pr-n-mgt_10-123-12-93.path, nsxt_policy_group.pr-n-mgt_10-123-13-116.path, nsxt_policy_group.pr-n-mgt_10-123-13-142.path, nsxt_policy_group.pr-n-mgt_10-123-13-153.path, nsxt_policy_group.pr-n-mgt_10-123-13-26.path, nsxt_policy_group.pr-n-mgt_10-123-13-36.path, nsxt_policy_group.pr-n-mgt_10-123-140-59.path, nsxt_policy_group.pr-n-mgt_10-123-140-81.path, nsxt_policy_group.pr-n-mgt_10-123-140-86.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_makati-trading-bcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_makati-trading-bcp"
  description  = "role: pr-n-mgt_grp_makati-trading-bcp"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_makati-trading-1.path, nsxt_policy_group.pr-n-mgt_makati-trading-2.path, nsxt_policy_group.pr-n-mgt_makati-trading-3.path, nsxt_policy_group.pr-n-mgt_makati-trading-4.path, nsxt_policy_group.pr-n-mgt_makati-trading-5.path, nsxt_policy_group.pr-n-mgt_makati-trading-6.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_gib_corp_users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_gib_corp_users"
  description  = "role: pr-n-mgt_grp_gib_corp_users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-180-18-169.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-148.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-202.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-152.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-157.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-189.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-89.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-80.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-122.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-26.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-110.path, nsxt_policy_group.pr-n-mgt_ip_10-180-18-113.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-217.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-179.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-141.path, nsxt_policy_group.pr-n-mgt_ip_10-180-19-224.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-gtp-outbound-adapters" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-gtp-outbound-adapters"
  description  = "role: pr-n-mgt_grp_grp-gtp-outbound-adapters"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-120-102-55.path, nsxt_policy_group.pr-n-mgt_ip_10-120-102-56.path, nsxt_policy_group.pr-n-mgt_ip_10-120-102-61.path, nsxt_policy_group.pr-n-mgt_ip_10-120-102-62.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_dba_workstations" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_dba_workstations"
  description  = "role: pr-n-mgt_grp_dba_workstations"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_usr-cwk-piotradamiak.path, nsxt_policy_group.pr-n-mgt_usr-cwk-keithbrailey.path, nsxt_policy_group.pr-n-mgt_usr-cwk-keithbrailey_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-mattprice.path, nsxt_policy_group.pr-n-mgt_usr-cwk-mattprice_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-nickhowe.path, nsxt_policy_group.pr-n-mgt_usr-cwk-nickhowe_vpn.path, nsxt_policy_group.pr-n-mgt_on_call_laptop_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-jamesgibson.path, nsxt_policy_group.pr-n-mgt_usr-cwk-jamesgibson_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-stephenwood.path, nsxt_policy_group.pr-n-mgt_usr-cwk-stephenwood_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-tobyhenderson_2.path, nsxt_policy_group.pr-n-mgt_usr-cwk-tobyhenderson_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-tobyhenderson_vpn_2.path, nsxt_policy_group.pr-n-mgt_usr-cwk-oliverallan.path, nsxt_policy_group.pr-n-mgt_usr-cwk-oliverallan_2.path, nsxt_policy_group.pr-n-mgt_usr-cwk-oliverallan_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-jayakumarperrikrishnaiah.path, nsxt_policy_group.pr-n-mgt_usr-cwk-amarbarot.path, nsxt_policy_group.pr-n-mgt_usr-cwk-piotradamiak_vpn.path, nsxt_policy_group.pr-n-mgt_usr-cwk-amarbarot2.path, nsxt_policy_group.pr-n-mgt_who-jamesgornall2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trs-users-uk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trs-users-uk"
  description  = "role: pr-n-mgt_grp_trs-users-uk"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp_trading_analysts.path, nsxt_policy_group.pr-n-mgt_grp_trading_management.path, nsxt_policy_group.pr-n-mgt_grp_trading_services.path, nsxt_policy_group.pr-n-mgt_grp_client_management.path, nsxt_policy_group.pr-n-mgt_grp_uk_pre_match.path, nsxt_policy_group.pr-n-mgt_grp_rd.path, nsxt_policy_group.pr-n-mgt_grp_uk-racing.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_net-10-1-78-0-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_net-10-1-78-0-23"
  description  = "role: pr-n-mgt_grp_net-10-1-78-0-23"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_citywalk78.path, nsxt_policy_group.pr-n-mgt_stjohns79.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_kotlarska_cloudteam-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_kotlarska_cloudteam-nets"
  description  = "role: pr-n-mgt_grp_kotlarska_cloudteam-nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_kotlarska_cloudteam.path, nsxt_policy_group.pr-n-mgt_kotlarska_cloudteam-wireless.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_bi-ssrs-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_bi-ssrs-users"
  description  = "role: who-Lev-Ankudinov"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_lcw-stefangarczynski.path, nsxt_policy_group.pr-n-mgt_who-danmarsden.path, nsxt_policy_group.pr-n-mgt_who-jamesbarr.path, nsxt_policy_group.pr-n-mgt_who-neilbancroft-sslvpn.path, nsxt_policy_group.pr-n-mgt_who-neilmcdonald.path, nsxt_policy_group.pr-n-mgt_who-neilmcdonald-sslvpn.path, nsxt_policy_group.pr-n-mgt_who-robwalton.path, nsxt_policy_group.pr-n-mgt_who-simongatenby.path, nsxt_policy_group.pr-n-mgt_who-omridahan.path, nsxt_policy_group.pr-n-mgt_who-oshratashkenazi.path, nsxt_policy_group.pr-n-mgt_tlv-nat-rongrossman.path, nsxt_policy_group.pr-n-mgt_il-webapptool.path, nsxt_policy_group.pr-n-mgt_who-natalijazvokelj.path, nsxt_policy_group.pr-n-mgt_tlv-ishaigalon_ip_10-51-51-83.path, nsxt_policy_group.pr-n-mgt_who-carmitkleinboxer.path, nsxt_policy_group.pr-n-mgt_who-sarithammer.path, nsxt_policy_group.pr-n-mgt_who-zachcohen.path, nsxt_policy_group.pr-n-mgt_who-adeellisdesktop.path, nsxt_policy_group.pr-n-mgt_bi-cristinapostolache-pc.path, nsxt_policy_group.pr-n-mgt_bi-cristinapostolache-sslvpn.path, nsxt_policy_group.pr-n-mgt_simoneaster.path, nsxt_policy_group.pr-n-mgt_gib-waynefield.path, nsxt_policy_group.pr-n-mgt_waynefield-sslvpn.path, nsxt_policy_group.pr-n-mgt_who-oamrbahaya.path, nsxt_policy_group.pr-n-mgt_who-daniellomax.path, nsxt_policy_group.pr-n-mgt_who-kennicol.path, nsxt_policy_group.pr-n-mgt_who-martinlayfield.path, nsxt_policy_group.pr-n-mgt_who-antoniomunoz.path, nsxt_policy_group.pr-n-mgt_who-guisepperoma.path, nsxt_policy_group.pr-n-mgt_who-caroleherbert.path, nsxt_policy_group.pr-n-mgt_who-helenhanley.path, nsxt_policy_group.pr-n-mgt_who-veronicalopezmonroy.path, nsxt_policy_group.pr-n-mgt_who-jameskelly.path, nsxt_policy_group.pr-n-mgt_who-ashleyheaton.path, nsxt_policy_group.pr-n-mgt_who-timlawrenson.path, nsxt_policy_group.pr-n-mgt_who-simonesswood.path, nsxt_policy_group.pr-n-mgt_who-janeslowey.path, nsxt_policy_group.pr-n-mgt_who-melanieenrile.path, nsxt_policy_group.pr-n-mgt_who-rhiannongoodall.path, nsxt_policy_group.pr-n-mgt_who-jamessturdy_ip_10-17-100-69.path, nsxt_policy_group.pr-n-mgt_who-tanyafrancis.path, nsxt_policy_group.pr-n-mgt_who-richardatkinson_ip_10-17-100-162.path, nsxt_policy_group.pr-n-mgt_who-jamesstephenson.path, nsxt_policy_group.pr-n-mgt_who-danieldavis.path, nsxt_policy_group.pr-n-mgt_who-omarbahayavpn.path, nsxt_policy_group.pr-n-mgt_who-andylidbetter.path, nsxt_policy_group.pr-n-mgt_who-stefanodelbeato.path, nsxt_policy_group.pr-n-mgt_remybarthomeuf.path, nsxt_policy_group.pr-n-mgt_silviacecchia.path, nsxt_policy_group.pr-n-mgt_alexrutherford.path, nsxt_policy_group.pr-n-mgt_chrispaye.path, nsxt_policy_group.pr-n-mgt_jonathanhoward.path, nsxt_policy_group.pr-n-mgt_mariagrigorova.path, nsxt_policy_group.pr-n-mgt_who-neilbancroft_ip_192-168-10-24.path, nsxt_policy_group.pr-n-mgt_who-woutervanzutphenssl.path, nsxt_policy_group.pr-n-mgt_who-jennabrown_ip_192-168-9-97.path, nsxt_policy_group.pr-n-mgt_who-craigconnelly.path, nsxt_policy_group.pr-n-mgt_who-richardatkinson_ip_10-180-21-39.path, nsxt_policy_group.pr-n-mgt_who-slawekmackowiak.path, nsxt_policy_group.pr-n-mgt_bi-skyemartin.path, nsxt_policy_group.pr-n-mgt_who-dominichammond.path, nsxt_policy_group.pr-n-mgt_who-paulkozlowski.path, nsxt_policy_group.pr-n-mgt_who-russellmottram.path, nsxt_policy_group.pr-n-mgt_who-valeriomiccio.path, nsxt_policy_group.pr-n-mgt_who-valeriomicciovpn.path, nsxt_policy_group.pr-n-mgt_who-ellaking.path, nsxt_policy_group.pr-n-mgt_who-benjones.path, nsxt_policy_group.pr-n-mgt_who-leostewart.path, nsxt_policy_group.pr-n-mgt_who-davidhill.path, nsxt_policy_group.pr-n-mgt_mattiascagliola_sslvpn.path, nsxt_policy_group.pr-n-mgt_who-simonkew.path, nsxt_policy_group.pr-n-mgt_who-michaeltaylor.path, nsxt_policy_group.pr-n-mgt_who-michailpalagkas.path, nsxt_policy_group.pr-n-mgt_who-przemekkawa.path, nsxt_policy_group.pr-n-mgt_who-terryzhang.path, nsxt_policy_group.pr-n-mgt_who-vladimirslegkovskis.path, nsxt_policy_group.pr-n-mgt_davidemagni_sslvpn.path, nsxt_policy_group.pr-n-mgt_lcw-mohammedahmed.path, nsxt_policy_group.pr-n-mgt_lcw-simonpierce.path, nsxt_policy_group.pr-n-mgt_who-bernhardstorhas.path, nsxt_policy_group.pr-n-mgt_who-jennabrown1.path, nsxt_policy_group.pr-n-mgt_who-jennabrown_ip_10-150-19-176.path, nsxt_policy_group.pr-n-mgt_who-heatherfaulkner.path, nsxt_policy_group.pr-n-mgt_who-alvarogonzalez.path, nsxt_policy_group.pr-n-mgt_who-marcosanta.path, nsxt_policy_group.pr-n-mgt_who-fabiomarchi.path, nsxt_policy_group.pr-n-mgt_who-rosefinan.path, nsxt_policy_group.pr-n-mgt_who-adamwalker.path, nsxt_policy_group.pr-n-mgt_who-danieldavies.path, nsxt_policy_group.pr-n-mgt_who-neilbancroft_ip_192-168-9-143.path, nsxt_policy_group.pr-n-mgt_who-allyflynn.path, nsxt_policy_group.pr-n-mgt_who-daleoldham.path, nsxt_policy_group.pr-n-mgt_who-sarahmcglue.path, nsxt_policy_group.pr-n-mgt_who-nicktrevett.path, nsxt_policy_group.pr-n-mgt_who-jameskennedy.path, nsxt_policy_group.pr-n-mgt_who-joshuawalker.path, nsxt_policy_group.pr-n-mgt_who-jamiecollings.path, nsxt_policy_group.pr-n-mgt_who-joshroberts.path, nsxt_policy_group.pr-n-mgt_who-philmanwaring.path, nsxt_policy_group.pr-n-mgt_who-christinabacani.path, nsxt_policy_group.pr-n-mgt_who-danmarsden2.path, nsxt_policy_group.pr-n-mgt_who-ellaking2.path, nsxt_policy_group.pr-n-mgt_who-jamesbarr2.path, nsxt_policy_group.pr-n-mgt_who-jamiecollings2.path, nsxt_policy_group.pr-n-mgt_who-jekynvilenna.path, nsxt_policy_group.pr-n-mgt_who-joshroberts2.path, nsxt_policy_group.pr-n-mgt_who-joshuawalker2.path, nsxt_policy_group.pr-n-mgt_who-philmanwaring2.path, nsxt_policy_group.pr-n-mgt_gib-andrewtowills.path, nsxt_policy_group.pr-n-mgt_who-callumjones.path, nsxt_policy_group.pr-n-mgt_who-davidjones.path, nsxt_policy_group.pr-n-mgt_who-markcheeswright.path, nsxt_policy_group.pr-n-mgt_who-monika.path, nsxt_policy_group.pr-n-mgt_who-neilwright.path, nsxt_policy_group.pr-n-mgt_who-susanasanchez.path, nsxt_policy_group.pr-n-mgt_stj-richardnolan.path, nsxt_policy_group.pr-n-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-n-mgt_10-1-78-147.path, nsxt_policy_group.pr-n-mgt_who-adeellis2.path, nsxt_policy_group.pr-n-mgt_who-paultait.path, nsxt_policy_group.pr-n-mgt_gib-piotrsmolinski.path, nsxt_policy_group.pr-n-mgt_who-rachelpalmer.path, nsxt_policy_group.pr-n-mgt_bfa-vip_users.path, nsxt_policy_group.pr-n-mgt_do_test.path, nsxt_policy_group.pr-n-mgt_lcw-peteredwards.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-18.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-22.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-66.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-81.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-82.path, nsxt_policy_group.pr-n-mgt_ip_10-180-27-93.path, nsxt_policy_group.pr-n-mgt_grp_all-data-mgt-users.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_bg-sophia-devs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_bg-sophia-devs"
  description  = "role: pr-n-mgt_grp_bg-sophia-devs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-53-0-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_krakow-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_krakow-subnets"
  description  = "role: pr-n-mgt_grp_krakow-subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_krakow-gaming-wifi.path, nsxt_policy_group.pr-n-mgt_krakow-gaming-lan.path, nsxt_policy_group.pr-n-mgt_krakow-sports-lan.path, nsxt_policy_group.pr-n-mgt_krakow-sports-wifi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_krakow_user_ranges" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_krakow_user_ranges"
  description  = "role: pr-n-mgt_grp_krakow_user_ranges"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_krakow_user_lan.path, nsxt_policy_group.pr-n-mgt_krakow_user_lan_tempoffice.path, nsxt_policy_group.pr-n-mgt_krk-wifi.path, nsxt_policy_group.pr-n-mgt_krk-core.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_grp-ardenta-vpn-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_grp-ardenta-vpn-nat"
  description  = "role: pr-n-mgt_grp_grp-ardenta-vpn-nat"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_grp-net-ardenta-vpn.path, nsxt_policy_group.pr-n-mgt_grp-net-ardenta-vpn-dr.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sftp-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sftp-users"
  description  = "role: pr-n-mgt_grp_sftp-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-56-134.path, nsxt_policy_group.pr-n-mgt_10-1-56-160.path, nsxt_policy_group.pr-n-mgt_10-1-56-179.path, nsxt_policy_group.pr-n-mgt_10-1-56-226.path, nsxt_policy_group.pr-n-mgt_10-1-56-248.path, nsxt_policy_group.pr-n-mgt_10-1-56-8.path, nsxt_policy_group.pr-n-mgt_grp_gsh-ias.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_krk-wifi-inc-prb-rls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_krk-wifi-inc-prb-rls"
  description  = "role: CHG0127893"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-55-226-21.path, nsxt_policy_group.pr-n-mgt_10-55-226-22.path, nsxt_policy_group.pr-n-mgt_10-55-226-23.path, nsxt_policy_group.pr-n-mgt_10-55-226-24.path, nsxt_policy_group.pr-n-mgt_10-55-226-25.path, nsxt_policy_group.pr-n-mgt_10-55-226-26.path, nsxt_policy_group.pr-n-mgt_10-55-226-27.path, nsxt_policy_group.pr-n-mgt_10-55-226-28.path, nsxt_policy_group.pr-n-mgt_10-55-226-29.path, nsxt_policy_group.pr-n-mgt_10-55-226-30.path, nsxt_policy_group.pr-n-mgt_10-55-226-31.path, nsxt_policy_group.pr-n-mgt_10-55-226-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_lan-krakow-inc-prb-rls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_lan-krakow-inc-prb-rls"
  description  = "role: CHG0127851"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_lan-krakow-inc-prb-rls-subnet.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_vmc-sddc-retail-production" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_vmc-sddc-retail-production"
  description  = "role: pr-n-mgt_grp_vmc-sddc-retail-production"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_vmc-retail-production-vsphere-mgmt.path, nsxt_policy_group.pr-n-mgt_vmc-retail-production-10-233-0-0s24.path, nsxt_policy_group.pr-n-mgt_vmc-retail-production-services-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_ld6-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_ld6-ras-vpn-pool"
  description  = "role: pr-n-mgt_grp_ld6-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_192-168-48-0s20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_sc1-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_sc1-ras-vpn-pool"
  description  = "role: pr-n-mgt_grp_sc1-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_192-168-12-0s22.path, nsxt_policy_group.pr-n-mgt_ip_192-168-16-0s22.path, nsxt_policy_group.pr-n-mgt_ip_192-168-0-0s21.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_mrg-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_mrg-ras-vpn-pool"
  description  = "role: pr-n-mgt_grp_mrg-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-30-200-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-30-202-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-40-200-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-40-202-0s24.path, nsxt_policy_group.pr-n-mgt_ip_10-130-200-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wily_svrs_brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wily_svrs_brs"
  description  = "role: pr-n-mgt_grp_wily_svrs_brs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-210-163-95.path, nsxt_policy_group.pr-n-mgt_ip_10-210-163-96.path, nsxt_policy_group.pr-n-mgt_ip_10-210-163-97.path, nsxt_policy_group.pr-n-mgt_ip_10-210-163-98.path, nsxt_policy_group.pr-n-mgt_ip_10-210-163-99.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wily_svrs_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wily_svrs_scc"
  description  = "role: pr-n-mgt_grp_wily_svrs_scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_sc1uxpremn105.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn106.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn107.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn108.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn120.path, nsxt_policy_group.pr-n-mgt_sc1uxpremn121.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-31.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-32.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-33.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-34.path, nsxt_policy_group.pr-n-mgt_ip_10-120-163-36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_wily_svrs_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_wily_svrs_gib"
  description  = "role: pr-n-mgt_grp_wily_svrs_gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_ip_10-180-163-211.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-212.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-213.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-214.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-218.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-102.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-220.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-221.path, nsxt_policy_group.pr-n-mgt_ip_10-180-163-40.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trading_analysts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trading_analysts"
  description  = "role: pr-n-mgt_grp_trading_analysts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-18-124.path, nsxt_policy_group.pr-n-mgt_10-1-18-226.path, nsxt_policy_group.pr-n-mgt_10-1-18-228.path, nsxt_policy_group.pr-n-mgt_10-1-18-28.path, nsxt_policy_group.pr-n-mgt_10-1-66-45.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trading_management" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trading_management"
  description  = "role: pr-n-mgt_grp_trading_management"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-18-159.path, nsxt_policy_group.pr-n-mgt_10-1-18-19.path, nsxt_policy_group.pr-n-mgt_10-1-18-69.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_trading_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_trading_services"
  description  = "role: pr-n-mgt_grp_trading_services"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-13-122.path, nsxt_policy_group.pr-n-mgt_10-1-13-150.path, nsxt_policy_group.pr-n-mgt_10-1-13-211.path, nsxt_policy_group.pr-n-mgt_10-1-13-216.path, nsxt_policy_group.pr-n-mgt_10-1-13-30.path, nsxt_policy_group.pr-n-mgt_10-1-13-54.path, nsxt_policy_group.pr-n-mgt_10-1-13-84.path, nsxt_policy_group.pr-n-mgt_10-1-13-98.path, nsxt_policy_group.pr-n-mgt_10-1-18-156.path, nsxt_policy_group.pr-n-mgt_10-1-18-203.path, nsxt_policy_group.pr-n-mgt_10-1-18-75.path, nsxt_policy_group.pr-n-mgt_10-1-30-154.path, nsxt_policy_group.pr-n-mgt_10-1-30-179.path, nsxt_policy_group.pr-n-mgt_10-1-30-194.path, nsxt_policy_group.pr-n-mgt_10-1-30-196.path, nsxt_policy_group.pr-n-mgt_10-1-30-246.path, nsxt_policy_group.pr-n-mgt_10-1-30-77.path, nsxt_policy_group.pr-n-mgt_10-1-30-80.path, nsxt_policy_group.pr-n-mgt_10-1-30-88.path, nsxt_policy_group.pr-n-mgt_10-1-30-94.path, nsxt_policy_group.pr-n-mgt_10-1-30-95.path, nsxt_policy_group.pr-n-mgt_10-1-66-33.path, nsxt_policy_group.pr-n-mgt_10-1-66-34.path, nsxt_policy_group.pr-n-mgt_10-1-66-58.path, nsxt_policy_group.pr-n-mgt_10-1-66-60.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_client_management" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_client_management"
  description  = "role: pr-n-mgt_grp_client_management"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-18-137.path, nsxt_policy_group.pr-n-mgt_10-1-18-162.path, nsxt_policy_group.pr-n-mgt_10-1-18-17.path, nsxt_policy_group.pr-n-mgt_10-1-18-31.path, nsxt_policy_group.pr-n-mgt_10-1-66-63.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_uk_pre_match" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_uk_pre_match"
  description  = "role: pr-n-mgt_grp_uk_pre_match"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-18-107.path, nsxt_policy_group.pr-n-mgt_10-1-18-113.path, nsxt_policy_group.pr-n-mgt_10-1-18-114.path, nsxt_policy_group.pr-n-mgt_10-1-18-148.path, nsxt_policy_group.pr-n-mgt_10-1-18-15.path, nsxt_policy_group.pr-n-mgt_10-1-18-161.path, nsxt_policy_group.pr-n-mgt_10-1-18-164.path, nsxt_policy_group.pr-n-mgt_10-1-18-167.path, nsxt_policy_group.pr-n-mgt_10-1-18-219.path, nsxt_policy_group.pr-n-mgt_10-1-18-24.path, nsxt_policy_group.pr-n-mgt_10-1-18-25.path, nsxt_policy_group.pr-n-mgt_10-1-18-29.path, nsxt_policy_group.pr-n-mgt_10-1-18-51.path, nsxt_policy_group.pr-n-mgt_10-1-18-53.path, nsxt_policy_group.pr-n-mgt_10-1-18-54.path, nsxt_policy_group.pr-n-mgt_10-1-18-76.path, nsxt_policy_group.pr-n-mgt_10-1-18-82.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_rd" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_rd"
  description  = "role: pr-n-mgt_grp_rd"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-112-237.path, nsxt_policy_group.pr-n-mgt_10-1-113-75.path, nsxt_policy_group.pr-n-mgt_10-1-113-77.path, nsxt_policy_group.pr-n-mgt_10-1-113-78.path, nsxt_policy_group.pr-n-mgt_10-1-113-79.path, nsxt_policy_group.pr-n-mgt_10-1-113-81.path, nsxt_policy_group.pr-n-mgt_10-1-113-82.path, nsxt_policy_group.pr-n-mgt_10-1-113-87.path, nsxt_policy_group.pr-n-mgt_stj-trading-randd-svr.path, nsxt_policy_group.pr-n-mgt_stjdancockerill.path, nsxt_policy_group.pr-n-mgt_stjgustavljundqvist.path, nsxt_policy_group.pr-n-mgt_stjjamessmith.path, nsxt_policy_group.pr-n-mgt_stjliammosley.path, nsxt_policy_group.pr-n-mgt_stjpoppywaterhouse.path, nsxt_policy_group.pr-n-mgt_stjantonioostios.path, nsxt_policy_group.pr-n-mgt_stjandystogdale.path, nsxt_policy_group.pr-n-mgt_stj-new-trading_r_d_svr.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_uk-racing" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_uk-racing"
  description  = "role: pr-n-mgt_grp_uk-racing"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-1-18-100.path, nsxt_policy_group.pr-n-mgt_10-1-18-139.path, nsxt_policy_group.pr-n-mgt_10-1-18-147.path, nsxt_policy_group.pr-n-mgt_10-1-18-166.path, nsxt_policy_group.pr-n-mgt_10-1-18-190.path, nsxt_policy_group.pr-n-mgt_10-1-18-193.path, nsxt_policy_group.pr-n-mgt_10-1-18-198.path, nsxt_policy_group.pr-n-mgt_10-1-18-208.path, nsxt_policy_group.pr-n-mgt_10-1-18-215.path, nsxt_policy_group.pr-n-mgt_10-1-18-223.path, nsxt_policy_group.pr-n-mgt_10-1-18-242.path, nsxt_policy_group.pr-n-mgt_10-1-18-48.path, nsxt_policy_group.pr-n-mgt_10-1-18-50.path, nsxt_policy_group.pr-n-mgt_10-1-18-66.path, nsxt_policy_group.pr-n-mgt_10-1-18-74.path]
    }
  }
}
resource "nsxt_policy_group" "pr-n-mgt_grp_gsh-ias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp_gsh-ias"
  description  = "role: pr-n-mgt_grp_gsh-ias"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-n-mgt_10-3-1-81.path, nsxt_policy_group.pr-n-mgt_10-3-1-83.path]
    }
  }
}
